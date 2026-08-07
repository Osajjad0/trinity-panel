#!/usr/bin/env python3
"""Deploy the Worker through the Cloudflare REST API.

No wrangler, no Node, no CLI toolchain beyond Python 3.8+ and the standard
library. This is the same sequence the setup wizard performs, kept as a
readable script so the wizard is not the only way to understand what happens
to your account.

Reads credentials from the environment, never from a file in this repository:

    CLOUDFLARE_API_TOKEN     required
    CLOUDFLARE_ACCOUNT_ID    required

Required token permissions:

    Account -> Workers Scripts     -> Edit
    Account -> Workers KV Storage  -> Edit
    Account -> Account Settings    -> Read

Note that ``GET /user/tokens/verify`` will report a correctly-scoped token as
invalid, because that endpoint is user-scoped and an account-scoped token
cannot call it. This script probes the endpoints it actually needs instead.

Usage:

    python scripts/deploy.py --name my-worker --build-dir build/worker \\
        --kv-id <namespace id>

Anything not supplied is generated and printed once. Nothing is written to
disk by this script.
"""

from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import secrets
import sys
import urllib.error
import urllib.request
import uuid

API = "https://api.cloudflare.com/client/v4"

# Pins runtime behaviour. Changing this can change semantics, so it moves only
# deliberately and in step with the Rust build.
COMPATIBILITY_DATE = "2026-07-01"

# The Durable Object class exported by the Worker. Must match the Rust type
# name annotated with #[durable_object].
DO_CLASS = "XhttpSession"


class DeployError(RuntimeError):
    """Anything that should stop the deployment with a readable message."""


def _request(method: str, path: str, token: str, *, body=None, content_type=None):
    """Call the Cloudflare API, retrying on transient network resets.

    This host's path to the Cloudflare API intermittently drops the TCP
    connection mid-request (WinError 10054). A single lost request used to
    abort a whole deploy that had already passed its preflight; retrying a
    few times with backoff lets the deploy ride out the flaky window instead
    of failing on the first reset. Failed responses (HTTP 4xx/5xx) are not
    retried; only requests that never got an answer at all.
    """
    import time as _time
    url = f"{API}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    last = None
    payload = None
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                raise DeployError(f"{method} {path} failed: HTTP {exc.code}: {raw[:400]}") from exc
            last = None
            break
        except urllib.error.URLError as exc:
            last = exc
            _time.sleep(2 * (attempt + 1))
            continue
    if last is not None or payload is None:
        reason = last.reason if last else "unknown error"
        raise DeployError(
            f"could not reach the Cloudflare API after retries ({reason}). "
            "Check your network, and if you are behind a proxy set HTTPS_PROXY."
        ) from last

    if not payload.get("success"):
        messages = "; ".join(e.get("message", "?") for e in payload.get("errors", []))
        raise DeployError(f"{method} {path} was rejected by Cloudflare: {messages}")
    return payload.get("result")


def preflight(token: str, account: str) -> str:
    """Verify the token really has the three permissions, by using them.

    Returns the account's workers.dev subdomain.
    """
    try:
        _request("GET", f"/accounts/{account}", token)
    except DeployError as exc:
        raise DeployError(
            "Cannot read the account. Either the account ID is wrong, or the "
            "token is missing 'Account Settings: Read'.\n  " + str(exc)
        ) from exc

    try:
        _request("GET", f"/accounts/{account}/workers/scripts", token)
    except DeployError as exc:
        raise DeployError(
            "Cannot list Workers. The token is probably missing "
            "'Workers Scripts: Edit'.\n  " + str(exc)
        ) from exc

    try:
        _request("GET", f"/accounts/{account}/storage/kv/namespaces", token)
    except DeployError as exc:
        raise DeployError(
            "Cannot list KV namespaces. The token is probably missing "
            "'Workers KV Storage: Edit'.\n  " + str(exc)
        ) from exc

    result = _request("GET", f"/accounts/{account}/workers/subdomain", token)
    subdomain = (result or {}).get("subdomain")
    if not subdomain:
        raise DeployError(
            "This account has no workers.dev subdomain yet. Register one in the "
            "Cloudflare dashboard under Workers & Pages, then re-run."
        )
    return subdomain


def ensure_kv(token: str, account: str, title: str) -> str:
    """Return the id of a KV namespace with this title, creating it if absent."""
    existing = _request("GET", f"/accounts/{account}/storage/kv/namespaces", token) or []
    for ns in existing:
        if ns.get("title") == title:
            return ns["id"]
    created = _request(
        "POST",
        f"/accounts/{account}/storage/kv/namespaces",
        token,
        body=json.dumps({"title": title}).encode(),
        content_type="application/json",
    )
    return created["id"]


def _multipart(parts):
    """Build a multipart/form-data body.

    `parts` is a list of (name, filename, content_type, bytes). Written by hand
    because the standard library has no multipart encoder and this needs no
    third-party dependency.
    """
    boundary = "----tricore" + secrets.token_hex(16)
    out = bytearray()
    for name, filename, ctype, data in parts:
        out += f"--{boundary}\r\n".encode()
        disp = f'form-data; name="{name}"'
        if filename:
            disp += f'; filename="{filename}"'
        out += f"Content-Disposition: {disp}\r\n".encode()
        out += f"Content-Type: {ctype}\r\n\r\n".encode()
        out += data
        out += b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def collect_modules(build_dir: str):
    """Find the entry module and every sibling module it needs."""
    if not os.path.isdir(build_dir):
        raise DeployError(
            f"Build output not found at {build_dir}. Run the build first "
            "(see docs), or pass --build-dir."
        )

    entry = None
    modules = []
    # Walk, do not just list. wasm-bindgen emits inline JS snippets into
    # `snippets/<hash>/inline0.js`, and index.js imports them by that exact
    # relative path. A module uploaded under any other name, or omitted, fails
    # at startup with "No such module" — after a successful upload, so the
    # error surfaces on the first request rather than here.
    for root, _dirs, files in os.walk(build_dir):
        for fname in sorted(files):
            full = os.path.join(root, fname)
            if fname.endswith(".wasm"):
                ctype = "application/wasm"
            elif fname.endswith((".mjs", ".js")):
                ctype = "application/javascript+module"
            else:
                continue
            # Module names are the path relative to the build directory, with
            # forward slashes on every platform.
            rel = os.path.relpath(full, build_dir).replace(os.sep, "/")
            with open(full, "rb") as handle:
                modules.append((rel, ctype, handle.read()))

    # Order matters: shim.mjs imports index.js, so the shim is the entry point
    # and index.js is a dependency. Picking by directory order would choose
    # index.js, which exports the raw bindings and no Worker handler, and the
    # deployment would fail at runtime rather than at upload.
    for preferred in ("shim.mjs", "worker.mjs", "index.mjs"):
        if any(m[0] == preferred for m in modules):
            entry = preferred
            break

    if not modules:
        raise DeployError(f"No .mjs/.js/.wasm modules found in {build_dir}.")
    if entry is None:
        # Fall back to the single JS module if there is exactly one.
        js = [m[0] for m in modules if not m[0].endswith(".wasm")]
        if len(js) != 1:
            raise DeployError(
                "Could not determine the entry module. Expected shim.mjs; "
                f"found {js}."
            )
        entry = js[0]
    return entry, modules


def upload(token, account, name, entry, modules, bindings, migrate_do):
    metadata = {
        "main_module": entry,
        "compatibility_date": COMPATIBILITY_DATE,
        "bindings": bindings,
    }
    if migrate_do:
        # Must be new_sqlite_classes. The KV-backed `new_classes` form fails on
        # accounts without a pre-existing KV-backed namespace, and SQLite is the
        # only backend available on the free plan.
        metadata["migrations"] = {"new_tag": "v1", "new_sqlite_classes": [DO_CLASS]}

    parts = [("metadata", None, "application/json", json.dumps(metadata).encode())]
    for fname, ctype, data in modules:
        parts.append((fname, fname, ctype, data))

    body, ctype = _multipart(parts)
    return _request(
        "PUT",
        f"/accounts/{account}/workers/scripts/{name}",
        token,
        body=body,
        content_type=ctype,
    )


def enable_subdomain(token, account, name):
    _request(
        "POST",
        f"/accounts/{account}/workers/scripts/{name}/subdomain",
        token,
        body=json.dumps({"enabled": True}).encode(),
        content_type="application/json",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Deploy the Worker via the Cloudflare API.")
    ap.add_argument("--name", required=True, help="Worker script name")
    ap.add_argument("--build-dir", default="build/worker", help="Directory holding shim.mjs and the .wasm")
    ap.add_argument("--kv-title", default=None, help="KV namespace title (default: <name>-settings)")
    ap.add_argument("--kv-id", default=None, help="Use an existing KV namespace id")
    ap.add_argument("--uuid", default=None, help="VLESS user UUID (generated if omitted)")
    ap.add_argument(
        "--trojan-password",
        default=None,
        help="Trojan password (generated if omitted; pass an empty string to disable Trojan)",
    )
    ap.add_argument(
        "--vmess-uuid",
        default=None,
        help="VMess user UUID (defaults to the VLESS UUID; pass an empty string to disable VMess)",
    )
    ap.add_argument(
        "--ss-method",
        default="2022-blake3-aes-256-gcm",
        help="Shadowsocks-2022 method (default: 2022-blake3-aes-256-gcm)",
    )
    ap.add_argument(
        "--ss-password",
        default=None,
        help="Shadowsocks base64 key (generated to match the method if omitted; "
        "pass an empty string to disable Shadowsocks)",
    )
    ap.add_argument(
        "--ss-users",
        default=None,
        help="Full Shadowsocks user list as comma-separated 'method:base64key' "
        "entries. Overrides --ss-method/--ss-password; use for several users or "
        "several methods on one deployment.",
    )
    ap.add_argument(
        "--panel-password",
        default=None,
        help="Admin panel password (generated if omitted; pass an empty string to "
        "disable the panel entirely)",
    )
    ap.add_argument("--xhttp-path", default=None, help="XHTTP base path (generated if omitted)")
    ap.add_argument("--panel-path", default=None, help="Admin panel base path (generated if omitted)")
    ap.add_argument("--sub-path", default=None, help="Subscription base path (generated if omitted)")
    ap.add_argument("--no-do", action="store_true", help="Skip the Durable Object migration (redeploys)")
    args = ap.parse_args()

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    if not token or not account:
        print(
            "CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID must be set in the "
            "environment.\nSee .env.example for how to obtain them.",
            file=sys.stderr,
        )
        return 2

    try:
        print("Checking the token can do what it needs...")
        subdomain = preflight(token, account)

        kv_id = args.kv_id or ensure_kv(token, account, args.kv_title or f"{args.name}-settings")

        # Generated once, printed once, never written to disk. A guessable path
        # is the cheapest thing for a scanner to find.
        user_uuid = args.uuid or str(uuid.uuid4())
        # `is None` rather than falsy: an explicitly empty string is how an
        # operator turns Trojan off, and must not be replaced by a fresh one.
        trojan_pw = args.trojan_password if args.trojan_password is not None else secrets.token_urlsafe(18)
        # One UUID serves both VLESS and VMess by default: they are the same
        # secret to the operator, and asking someone to keep two straight buys
        # no security. Same `is None` rule so an empty string disables VMess.
        vmess_uuid = args.vmess_uuid if args.vmess_uuid is not None else user_uuid
        # The key length is fixed by the method: 16 bytes for the 128-bit
        # method, 32 for the others. Generating the wrong length is the most
        # common Shadowsocks-2022 misconfiguration, so it is derived here
        # rather than left to the operator.
        ss_key_len = 16 if args.ss_method == "2022-blake3-aes-128-gcm" else 32
        if args.ss_password is not None:
            ss_password = args.ss_password
        else:
            ss_password = base64.b64encode(secrets.token_bytes(ss_key_len)).decode()
        if args.ss_users is not None:
            ss_users = args.ss_users
        else:
            ss_users = f"{args.ss_method}:{ss_password}" if ss_password else ""
        # An empty string disables the panel outright rather than leaving it
        # open: the panel can read every credential the deployment serves, so
        # "no password configured" must mean "no panel", never "no check".
        panel_password = (
            args.panel_password
            if args.panel_password is not None
            else secrets.token_urlsafe(18)
        )
        xhttp_path = args.xhttp_path or "/" + secrets.token_hex(8)
        panel_path = args.panel_path or "/" + secrets.token_hex(8)
        sub_path = args.sub_path or "/" + secrets.token_hex(8)

        entry, modules = collect_modules(args.build_dir)
        total = sum(len(m[2]) for m in modules)
        print(f"Uploading {len(modules)} module(s), {total // 1024} KiB, entry {entry}...")

        bindings = [
            {"type": "kv_namespace", "name": "SETTINGS", "namespace_id": kv_id},
            {"type": "durable_object_namespace", "name": "XHTTP_SESSION", "class_name": DO_CLASS},
            {"type": "plain_text", "name": "XHTTP_PATH", "text": xhttp_path},
            {"type": "plain_text", "name": "PANEL_PATH", "text": panel_path},
            {"type": "plain_text", "name": "SUB_PATH", "text": sub_path},
            {"type": "plain_text", "name": "WS_ENABLED", "text": "true"},
            {"type": "plain_text", "name": "WS_PATH", "text": "/ws"},
            {"type": "secret_text", "name": "VLESS_USERS", "text": user_uuid},
            {"type": "secret_text", "name": "TROJAN_USERS", "text": trojan_pw},
            {"type": "secret_text", "name": "VMESS_USERS", "text": vmess_uuid},
            {"type": "secret_text", "name": "SS_USERS", "text": ss_users},
            {"type": "secret_text", "name": "PANEL_PASSWORD", "text": panel_password},
        ]

        upload(token, account, args.name, entry, modules, bindings, not args.no_do)
        enable_subdomain(token, account, args.name)

        host = f"{args.name}.{subdomain}.workers.dev"
        print("\nDeployed.\n")
        print(f"  Host          https://{host}")
        print(f"  XHTTP path    {xhttp_path}")
        print(f"  Panel path    https://{host}{panel_path}")
        print(f"  Panel pass    {panel_password or '(panel disabled)'}")
        print(f"  Subscription  https://{host}{sub_path}")
        print(f"  VLESS UUID    {user_uuid}")
        print(f"  Trojan pass   {trojan_pw or '(disabled)'}")
        print(f"  VMess UUID    {vmess_uuid or '(disabled)'}")
        if args.ss_users is not None:
            count = len([e for e in ss_users.replace("\n", ",").split(",") if e.strip()])
            print(f"  SS users      {count} configured (as supplied)")
        else:
            print(f"  SS method     {args.ss_method if ss_password else '(disabled)'}")
            print(f"  SS password   {ss_password or '(disabled)'}")
        print("\nThese are shown once and are not saved anywhere. Copy them now.")
        return 0

    except DeployError as exc:
        print(f"\nDeployment stopped: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
