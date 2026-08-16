#!/usr/bin/env python3
"""Trinity Panel setup wizard — the recommended way to install.

Serves the wizard on your own machine and performs the installation you ask it
for: it builds the Worker, creates the KV namespace, uploads the script with
its Durable Object migration, enables the workers.dev subdomain, and hands back
a private link to your panel.

    python scripts/install.py

Then follow the four steps in the browser tab that opens.

Nothing is written to disk except the build output under `build/`. Your
Cloudflare API token is held in memory for the duration of one install, is
never logged, and is never persisted.

The server binds to 127.0.0.1 only. It is a local tool, not a service: it
accepts requests from this machine and refuses cross-origin ones.
"""

from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
import secrets
import subprocess
import sys
import threading
import urllib.parse
import uuid
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import deploy  # noqa: E402  (same directory; the API layer is shared)

WIZARD = os.path.join(ROOT, "wizard", "index.html")

# Kept in step with the wizard's dropdown.
METHODS = {"workers", "workers-custom-domain", "manual"}


def random_name() -> str:
    """An unremarkable default Worker name.

    Deliberately not proxy-shaped: the hostname is public, and a name that
    announces what the deployment is invites attention it does not need.
    """
    words = ("edge", "cache", "assets", "static", "relay", "gateway", "origin", "media")
    return f"{secrets.choice(words)}-{secrets.token_hex(2)}"


def generate_credentials(method: str = "2022-blake3-aes-256-gcm") -> dict:
    """Every secret and path a fresh install needs, generated locally.

    Mirrors `deploy.py`'s generation rules exactly, including the Shadowsocks
    key length being fixed by the method — the wrong length is the most common
    Shadowsocks-2022 misconfiguration, so it is derived rather than chosen.
    """
    user_uuid = str(uuid.uuid4())
    key_len = 16 if method == "2022-blake3-aes-128-gcm" else 32
    ss_key = base64.b64encode(secrets.token_bytes(key_len)).decode()
    return {
        "vless_users": user_uuid,
        # One UUID serves VLESS and VMess: they are the same secret to the
        # operator, and two of them buys no security.
        "vmess_users": user_uuid,
        "trojan_users": secrets.token_urlsafe(18),
        "ss_users": f"{method}:{ss_key}",
        "panel_password": secrets.token_urlsafe(18),
        "xhttp_path": "/" + secrets.token_hex(8),
        "panel_path": "/" + secrets.token_hex(8),
        "sub_path": "/" + secrets.token_hex(8),
    }


def bindings_for(kv_id: str, creds: dict) -> list:
    """The binding set uploaded with the script.

    Paths are plain text because they are not secrets in the cryptographic
    sense; everything that authenticates a client is a secret binding, which is
    write-only once set.
    """
    return [
        {"type": "kv_namespace", "name": "SETTINGS", "namespace_id": kv_id},
        {
            "type": "durable_object_namespace",
            "name": "XHTTP_SESSION",
            "class_name": deploy.DO_CLASS,
        },
        {"type": "plain_text", "name": "XHTTP_PATH", "text": creds["xhttp_path"]},
        {"type": "plain_text", "name": "PANEL_PATH", "text": creds["panel_path"]},
        {"type": "plain_text", "name": "SUB_PATH", "text": creds["sub_path"]},
        # WebSocket stays off. It is the most heavily classified transport in
        # this space, and enabling it on the same hostname as XHTTP couples
        # their survival.
        {"type": "plain_text", "name": "WS_ENABLED", "text": "false"},
        {"type": "plain_text", "name": "WS_PATH", "text": "/ws"},
        {"type": "secret_text", "name": "VLESS_USERS", "text": creds["vless_users"]},
        {"type": "secret_text", "name": "TROJAN_USERS", "text": creds["trojan_users"]},
        {"type": "secret_text", "name": "VMESS_USERS", "text": creds["vmess_users"]},
        {"type": "secret_text", "name": "SS_USERS", "text": creds["ss_users"]},
        {"type": "secret_text", "name": "PANEL_PASSWORD", "text": creds["panel_password"]},
    ]


def discover_account(token: str) -> str:
    """The single account this token can act on.

    The wizard asks for a token and nothing else, so the account ID has to come
    from the token itself. A token scoped to several accounts is ambiguous and
    is reported as such rather than guessed at.
    """
    accounts = deploy._request("GET", "/accounts", token) or []

    if not accounts:
        raise deploy.DeployError(
            "This token cannot see any account. Check that 'Account Resources' "
            "was set on the token page and that 'Account Settings: Read' is "
            "included."
        )
    if len(accounts) > 1:
        names = ", ".join(f"{a.get('name')} ({a.get('id')})" for a in accounts)
        raise deploy.DeployError(
            "This token can see more than one account, so the wizard cannot "
            f"choose for you: {names}. Create a token scoped to one account."
        )
    return accounts[0]["id"]


def zone_for_hostname(token: str, hostname: str) -> tuple[str, str]:
    """Find the zone a hostname belongs to, longest suffix first.

    `panel.example.com` may sit under `example.com` or under a
    `panel.example.com` zone of its own; the more specific zone wins.
    """
    zones = deploy._request("GET", "/zones?per_page=200", token) or []
    matches = [
        z
        for z in zones
        if hostname == z.get("name") or hostname.endswith("." + str(z.get("name")))
    ]
    if not matches:
        raise deploy.DeployError(
            f"No zone on this account covers {hostname}. Add the domain to "
            "Cloudflare first, or install on a workers.dev hostname instead."
        )
    best = max(matches, key=lambda z: len(str(z.get("name"))))
    return best["id"], best["name"]


def attach_domain(token: str, account: str, script: str, hostname: str) -> None:
    """Bind a custom hostname to the Worker."""
    zone_id, zone_name = zone_for_hostname(token, hostname)
    deploy._request(
        "PUT",
        f"/accounts/{account}/workers/domains",
        token,
        body=json.dumps(
            {
                "environment": "production",
                "hostname": hostname,
                "service": script,
                "zone_id": zone_id,
                "zone_name": zone_name,
            }
        ).encode(),
        content_type="application/json",
    )


def build(emit) -> str:
    """Compile the Worker, reporting progress as it goes.

    Returns the build directory. Delegates to `scripts/build.py` so the wizard
    and the command-line path cannot drift apart.
    """
    out = os.path.join(ROOT, "build", "worker")
    emit("step", "Compiling the Worker (this takes a few minutes the first time)...")
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "build.py"), "--out", out],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            emit("note", line.rstrip())
    if proc.returncode != 0:
        tail = "\n".join((proc.stderr or "").strip().splitlines()[-12:])
        raise deploy.DeployError(f"the build failed:\n{tail}")
    return out


def script_exists(token: str, account: str, name: str) -> bool:
    """Whether a Worker of this name is already on the account."""
    scripts = deploy._request("GET", f"/accounts/{account}/workers/scripts", token) or []
    return any(s.get("id") == name for s in scripts)


def run_install(payload: dict, emit) -> None:
    """Perform one installation, emitting progress events as it goes.

    `emit(event, message, **extra)` is the only channel back to the wizard.
    Nothing here prints, because stdout belongs to the HTTP server.
    """
    token = str(payload.get("token", "")).strip()
    method = str(payload.get("method", "workers"))
    name = str(payload.get("name", "")).strip() or random_name()
    hostname = str(payload.get("domain", "")).strip()

    if not token:
        raise deploy.DeployError("no API token was supplied")
    if method not in METHODS:
        raise deploy.DeployError(f"unknown installation method {method!r}")

    creds = generate_credentials()

    if method == "manual":
        # Nothing is created. The values are still generated so the printed
        # commands are the ones that would have run.
        emit(
            "commands",
            "Run these two commands from the repository root:",
            commands=[
                "python scripts/build.py",
                f"python scripts/deploy.py --name {name}",
            ],
        )
        emit(
            "note",
            "deploy.py generates its own credentials and prints them once. "
            "Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID first.",
        )
        return

    emit("step", "Checking the token...")
    account = discover_account(token)
    subdomain = deploy.preflight(token, account)
    emit("note", f"account {account[:8]}... · subdomain {subdomain}.workers.dev")

    build_dir = build(emit)

    emit("step", "Creating the settings namespace...")
    kv_id = deploy.ensure_kv(token, account, f"{name}-settings")

    emit("step", f"Uploading the Worker as {name}...")
    entry, modules = deploy.collect_modules(build_dir)
    total = sum(len(m[2]) for m in modules) // 1024
    emit("note", f"{len(modules)} module(s), {total} KiB, entry {entry}")
    # The Durable Object migration may only be applied once per script. Running
    # it against a script that already has the class is rejected outright, so an
    # install over an existing name has to skip it.
    fresh = not script_exists(token, account, name)
    if not fresh:
        emit("note", f"{name} already exists; replacing it and keeping its session class")
    deploy.upload(token, account, name, entry, modules, bindings_for(kv_id, creds), fresh)

    emit("step", "Enabling the workers.dev hostname...")
    deploy.enable_subdomain(token, account, name)
    host = f"{name}.{subdomain}.workers.dev"

    if method == "workers-custom-domain":
        emit("step", f"Attaching {hostname}...")
        attach_domain(token, account, name, hostname)
        host = hostname

    emit(
        "done",
        "Deployed.",
        result={
            "host": host,
            "panelUrl": f"https://{host}{creds['panel_path']}",
            "panelPassword": creds["panel_password"],
            "subscriptionUrl": f"https://{host}{creds['sub_path']}",
            "xhttpPath": creds["xhttp_path"],
            "vlessUuid": creds["vless_users"],
            "vmessUuid": creds["vmess_users"],
            "trojanPassword": creds["trojan_users"],
            "shadowsocksUsers": creds["ss_users"],
        },
    )


class Handler(http.server.BaseHTTPRequestHandler):
    """Serves the wizard and one endpoint. Local only, single install at a time."""

    server_version = "TrinityPanelSetup"
    sys_version = ""

    # Set by main(); a caller with the wrong value is not from our own page.
    origin_token = ""

    def log_message(self, fmt, *args):
        # The default logs the full request line. Nothing sensitive travels in a
        # URL here, but quiet output keeps the terminal readable, and a wizard
        # that echoes requests invites pasting them somewhere.
        if self.path.startswith("/api/"):
            sys.stderr.write(f"  {self.command} {self.path}\n")

    def _guard(self) -> bool:
        """Refuse anything that did not come from the page we served.

        A browser will happily let any website POST to 127.0.0.1. Requiring a
        secret the page was rendered with means only this wizard tab can drive
        an install.
        """
        if self.headers.get("X-Setup-Token", "") == self.origin_token:
            return True
        self._json(403, {"event": "error", "message": "This request did not come from the wizard."})
        return False

    def _json(self, code: int, payload: dict) -> None:
        body = (json.dumps(payload) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802  (stdlib naming)
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._page()
        else:
            self.send_error(404, "Not here")

    def _page(self) -> None:
        with open(WIZARD, "rb") as handle:
            html = handle.read()
        # The page is told the per-run token so its fetches can prove they came
        # from here. Injected rather than embedded so the file on disk carries no
        # secret and can be opened directly while working on the styling.
        marker = b'"use strict";'
        token = json.dumps(Handler.origin_token).encode()
        if marker not in html:
            raise deploy.DeployError("wizard/index.html is missing its script marker")
        html = html.replace(marker, marker + b"\nwindow.__SETUP_TOKEN__ = " + token + b";", 1)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path != "/api/install":
            self.send_error(404, "Not here")
            return
        if not self._guard():
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"event": "error", "message": "That request could not be read."})
            return

        # Newline-delimited JSON, flushed per event: a build takes minutes, and a
        # progressless wait is indistinguishable from a hang.
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        def emit(event: str, message: str = "", **extra) -> None:
            line = json.dumps({"event": event, "message": message, **extra}) + "\n"
            try:
                self.wfile.write(line.encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                # The tab was closed. Nothing to report to.
                pass

        try:
            run_install(payload, emit)
        except deploy.DeployError as exc:
            emit("error", str(exc))
        except Exception as exc:  # noqa: BLE001  (last resort; the tab must hear about it)
            emit("error", f"unexpected failure: {type(exc).__name__}: {exc}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Trinity Panel setup wizard.")
    ap.add_argument("--port", type=int, default=8787, help="local port (default 8787)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    args = ap.parse_args()

    if not os.path.isfile(WIZARD):
        print(f"cannot find {WIZARD}. Run this from a checkout of the repository.", file=sys.stderr)
        return 2

    Handler.origin_token = secrets.token_urlsafe(24)

    # Bound to loopback deliberately. This process can create Workers on your
    # account; it must not be reachable from the network.
    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        print(f"cannot listen on 127.0.0.1:{args.port} ({exc}). Try --port.", file=sys.stderr)
        return 1

    url = f"http://127.0.0.1:{args.port}/"
    print("Trinity Panel setup")
    print(f"  Open {url}")
    print("  Press Ctrl+C when you are finished.\n")
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
