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
import contextlib
import json
import hashlib
import mimetypes
import os
import subprocess
import secrets
import sys
import tempfile
import urllib.error
import urllib.request
import uuid

API = "https://api.cloudflare.com/client/v4"

# This file lives in scripts/ inside the repository it builds.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Pins runtime behaviour. Changing this can change semantics, so it moves only
# deliberately and in step with the Rust build.
COMPATIBILITY_DATE = "2026-07-01"

# The Durable Object class exported by the Worker. Must match the Rust type
# name annotated with #[durable_object].
DO_CLASS = "XhttpSession"

# ---- release integrity -------------------------------------------------
# A build directory is anonymous: nothing recorded which source revision
# produced it, and nothing stopped a deploy from uploading files that a later
# build had already replaced. Two deploys 54s apart against two different
# builds were indistinguishable to this pipeline. The manifest below is the
# missing record, and the checks around it are the gate that reads it.
#
# They live in collect_modules()/upload() rather than in main() because the
# setup wizard (install.py) calls those two directly and never runs main(): a
# guard added only to main() would cover the CLI and nothing else.
#
# ponytail: one lock file per Worker name in the temp dir. It serializes
# deploys on this machine only; two machines can still race, which is what the
# post-upload etag check reports.

class DeployError(RuntimeError):
    """Anything that should stop the deployment with a readable message."""


MANIFEST_NAME = "release-manifest.json"

# Everything whose contents change the built modules. Untracked junk elsewhere
# in the repo is deliberately excluded, so an unrelated scratch file cannot
# block a valid deploy, while a new untracked source file does change it.
SNAPSHOT_PATHS = ("src", "public", "Cargo.toml", "Cargo.lock", "build.py", "wrangler.jsonc")

SUFFIXES = (".wasm", ".mjs", ".js")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args) -> str:
    proc = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _snapshot_root() -> str:
    """The checkout whose build inputs are hashed: the cwd, as git sees it.

    git resolves relative paths against the working directory, so the snapshot
    must too, otherwise "deploy from the repo root" and "verify from elsewhere"
    would read different trees. Falls back to this script's own repository so a
    deploy.py invoked from an unrelated directory still records a real revision
    instead of an empty one.
    """
    if _git("rev-parse", "--show-toplevel"):
        return _git("rev-parse", "--show-toplevel")
    return ROOT


def source_snapshot() -> str:
    """One value that changes whenever the build inputs change.

    A content digest of every build input, plus the commit. The content digest
    is what makes this correct rather than merely plausible: `git status` is
    byte-identical for an untracked file before and after its contents are
    edited, so a source file that was never committed could change and still
    produce the same status output. Hashing the bytes themselves cannot.

    Only SNAPSHOT_PATHS is walked, so a local .env or credential file can never
    enter this value or anything derived from it.
    """
    root = _snapshot_root()
    parts = [_git("rev-parse", "HEAD")]
    for rel_path in SNAPSHOT_PATHS:
        full = os.path.join(root, rel_path)
        if os.path.isfile(full):
            parts.append(f"{rel_path}\0{_sha256_file(full)}")
            continue
        for dirpath, dirnames, filenames in os.walk(full):
            dirnames.sort()
            for fname in sorted(filenames):
                if fname.endswith((".exe", ".dll", ".pdb")):
                    continue
                child = os.path.join(dirpath, fname)
                if not os.path.isfile(child):
                    continue
                parts.append(f"{os.path.relpath(child, root)}\0{_sha256_file(child)}")
    parts.sort()
    return hashlib.sha256("\0".join(parts).encode("utf-8", "replace")).hexdigest()

def write_manifest(build_dir: str) -> dict:
    """Record what this build is, so the deploy can prove it.

    A commit hash, a snapshot hash and a SHA-256 per module: enough to reject
    every stale or substituted artifact, and nothing sensitive to store.
    """
    artifacts = {}
    for root, _dirs, files in os.walk(build_dir):
        for fname in files:
            if fname.endswith(SUFFIXES):
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, build_dir).replace(os.sep, "/")
                artifacts[rel] = _sha256_file(full)
    if not artifacts:
        raise DeployError(f"no modules to record in {build_dir}")
    commit = _git("rev-parse", "HEAD")
    if not commit:
        raise DeployError(
            "cannot record provenance: this is not a git checkout, so deployed "
            "bytes could never be tied to a reviewed source revision."
        )
    manifest = {
        "commit": commit,
        "snapshot": source_snapshot(),
        "artifacts": dict(sorted(artifacts.items())),
    }
    with open(os.path.join(build_dir, MANIFEST_NAME), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return manifest


def read_manifest(build_dir: str) -> dict:
    """Load the manifest, failing closed when it is absent or unusable."""
    path = os.path.join(build_dir, MANIFEST_NAME)
    if not os.path.isfile(path):
        raise DeployError(
            f"No {MANIFEST_NAME} in {build_dir}. That build directory was not "
            f"produced by scripts/build.py, so its provenance cannot be "
            f"verified and it will not be deployed."
        )
    try:
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        raise DeployError(f"{path} is unreadable: {exc}") from exc
    if not isinstance(manifest.get("artifacts"), dict) or not manifest["artifacts"]:
        raise DeployError(f"{path} records no artifacts.")
    for field in ("commit", "snapshot"):
        if not manifest.get(field):
            raise DeployError(f"{path} has no {field}.")
    return manifest


def verify_release(build_dir: str, modules=None) -> dict:
    """Fail closed unless these bytes are exactly the reviewed build.

    Called twice on purpose: once before any API call, so a bad build never
    reaches the account, and again on the module bytes about to be uploaded,
    which closes the window between the two. With `modules` given, the hashes
    are taken from the in-memory bytes, so what is verified IS what is sent.

    Returns the manifest; raises DeployError on any mismatch.
    """
    manifest = read_manifest(build_dir)
    recorded = manifest["artifacts"]
    if modules is None:
        present = {}
        for root, _dirs, files in os.walk(build_dir):
            for fname in files:
                if fname.endswith(SUFFIXES):
                    full = os.path.join(root, fname)
                    present[os.path.relpath(full, build_dir).replace(os.sep, "/")] = _sha256_file(full)
    else:
        present = {rel: hashlib.sha256(data).hexdigest() for rel, _ctype, data in modules}

    missing = sorted(set(recorded) - set(present))
    if missing:
        raise DeployError(
            "recorded artifact(s) are missing from the build directory: "
            + ", ".join(missing)
            + ". A partial build would deploy a broken module set."
        )
    extra = sorted(set(present) - set(recorded))
    if extra:
        raise DeployError(
            "module(s) present but not in the manifest: "
            + ", ".join(extra)
            + ". An artifact was substituted or left over from an earlier build."
        )
    changed = sorted(name for name in recorded if recorded[name] != present[name])
    if changed:
        raise DeployError(
            "artifact(s) do not match the recorded SHA-256: "
            + ", ".join(changed)
            + ". The files changed after the build was verified."
        )
    if manifest["snapshot"] != source_snapshot():
        raise DeployError(
            "the source tree changed after this build was recorded (built from "
            f"{manifest['commit'][:7]}). Rebuild so the artifact matches the "
            "source that was reviewed."
        )
    return manifest


@contextlib.contextmanager
def deploy_lock(name: str):
    """One deploy per Worker at a time.

    Two uploads racing the same script name interleave, and the loser silently
    overwrites the winner's modules with whatever it had read. An exclusive
    create is the entire mechanism.
    """
    path = os.path.join(tempfile.gettempdir(), f"trinity-deploy-{name}.lock")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise DeployError(
            f"another deploy of {name} holds {path}. Wait for it to finish, or "
            f"delete that file if no deploy is running."
        ) from exc
    try:
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.close(fd)
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def live_revision(token: str, account: str, name: str) -> dict:
    """The newest deployed version's id and script etag, or {} if unavailable.

    Cloudflare's per-version `script.etag` is a content hash of what was
    actually stored, which is the one identity available for the deployed bytes
    without putting anything in the Worker or in a public response.

    The etag lives on the version detail resource, not in the versions LIST:
    a list item carries only id/number/metadata, so reading the etag from there
    yields an empty string that looks like a successful check. That is exactly
    the kind of "proved nothing" signal this whole gate exists to remove, so the
    detail is fetched and the etag is only reported when it is really there.
    """
    listing = _request("GET", f"/accounts/{account}/workers/scripts/{name}/versions?per_page=1", token) or {}
    items = (listing.get("items") or []) if isinstance(listing, dict) else []
    if not items:
        return {}
    top = items[0]
    version_id = top.get("id", "")
    detail = _request("GET", f"/accounts/{account}/workers/scripts/{name}/versions/{version_id}", token) or {}
    resources = (detail.get("resources") or {}) if isinstance(detail, dict) else {}
    etag = ((resources.get("script") or {}).get("etag") or "").strip()
    return {
        "version_id": version_id,
        "version_number": top.get("number"),
        "created_on": (top.get("metadata") or {}).get("created_on", ""),
        "script_etag": etag,
    }

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
    _REQUEST_DEADLINE = 300  # seconds; hard cap per API call
    url = f"{API}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    if content_type:
        headers["Content-Type"] = content_type
    last = None
    payload = None
    deadline = _time.monotonic() + _REQUEST_DEADLINE
    # Python's TLS cannot handshake with api.cloudflare.com from this host
    # (SSLEOFError on every attempt) even though curl's schannel stack does.
    # Rather than let a transport quirk abort every deploy, run the same
    # retry/backoff contract over curl, which this host can actually use.
    for attempt in range(6):
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            raise DeployError(
                f"{method} {path} timed out after {_REQUEST_DEADLINE}s "
                f"(attempt {attempt + 1}/6)."
            )
        sock_timeout = min(120, remaining)
        print(f"  [{method} {path}] curl attempt {attempt + 1}/6 (timeout {sock_timeout:.0f}s)")
        try:
            status, curl_payload = _curl_request(method, path, token, body, content_type)
        except DeployError as exc:
            last = exc
            wait = min(2 * (attempt + 1), deadline - _time.monotonic())
            if wait <= 0:
                break
            print(f"  [{method} {path}] {exc}; retrying in {wait:.0f}s")
            _time.sleep(wait)
            continue
        if status == 0 or status >= 500:
            # transport-level or server-side: retry, same as before
            last = DeployError(f"HTTP {status or 'no response'}")
            wait = min(2 * (attempt + 1), deadline - _time.monotonic())
            if wait <= 0:
                break
            print(f"  [{method} {path}] HTTP {status}; retrying in {wait:.0f}s")
            _time.sleep(wait)
            continue
        payload = curl_payload
        last = None
        break
    if last is not None or payload is None:
        raise DeployError(
            f"could not reach the Cloudflare API after retries ({last}). "
            "Check your network, and if you are behind a proxy set HTTPS_PROXY."
        ) from (last if isinstance(last, Exception) else None)

    if not payload.get("success"):
        messages = "; ".join(e.get("message", "?") for e in payload.get("errors", []))
        err = DeployError(f"{method} {path} was rejected by Cloudflare: {messages}")
        # Keep the structured error list on the exception: callers must be able
        # to branch on a specific CF code (10061) instead of parsing message
        # text, which rewords between API versions.
        err.payload = payload
        raise err
    return payload.get("result")


def _request_urllib_legacy(method: str, path: str, token: str, *, body=None, content_type=None):
    """Original urllib implementation, kept for reference. Unused."""
    import time as _time
    _REQUEST_DEADLINE = 300
    url = f"{API}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    last = None
    payload = None
    deadline = _time.monotonic() + _REQUEST_DEADLINE
    for attempt in range(6):
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            raise DeployError(
                f"{method} {path} timed out after {_REQUEST_DEADLINE}s "
                f"(attempt {attempt + 1}/6). The API accepted the connection "
                "but did not complete the response in time."
            )
        sock_timeout = min(120, remaining)
        print(f"  [{method} {path}] attempt {attempt + 1}/6 (timeout {sock_timeout:.0f}s)")
        try:
            with urllib.request.urlopen(req, timeout=sock_timeout) as resp:
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
            wait = min(2 * (attempt + 1), deadline - _time.monotonic())
            if wait <= 0:
                break
            print(f"  [{method} {path}] URLError: {exc.reason}; retrying in {wait:.0f}s")
            _time.sleep(wait)
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


_CURL = ["curl.exe", "-sS", "--max-time", "150", "-w", "\n%{http_code}"]

def _curl_request(method, path, token, body=None, content_type=None):
    """One Cloudflare API call via curl. Returns (http_status, payload_dict).

    The deploy script's Python TLS stack cannot complete a handshake with
    api.cloudflare.com from this host (OpenSSL SSLEOFError on every attempt),
    while curl's schannel TLS does. Both are "the network"; only one works,
    so the API calls route through curl and urllib is never used here.
    """
    import subprocess as _sp
    import tempfile as _tf
    cmd = list(_CURL) + ["-X", method, "-H", f"Authorization: Bearer {token}"]
    if content_type:
        cmd += ["-H", f"Content-Type: {content_type}"]
    # Callers pass `body` as raw bytes (JSON or multipart); curl wants a file
    # or a string, so bytes go to a temp file that is always cleaned up.
    body_path = None
    with _tf.NamedTemporaryFile(delete=False) as tf:
        out_path = tf.name
    try:
        if body is None:
            cmd += [f"{API}{path}", "-o", out_path]
        else:
            data = body if isinstance(body, (bytes, bytearray)) else str(body).encode()
            with _tf.NamedTemporaryFile(delete=False) as bf:
                bf.write(data)
                body_path = bf.name
            cmd += ["--data-binary", "@" + body_path, f"{API}{path}", "-o", out_path]
        proc = _sp.run(cmd, capture_output=True, text=True)
        raw_out = open(out_path, "rb").read()
        os.unlink(out_path)
    finally:
        for p_ in (out_path, body_path):
            if p_:
                try:
                    os.unlink(p_)
                except OSError:
                    pass
    # curl appends a trailing newline + status code; the body is the file.
    try:
        payload = json.loads(raw_out.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DeployError(
            f"{method} {path} via curl returned unparseable body "
            f"({len(raw_out)} bytes, stderr: {proc.stderr.strip()[:200]!r})"
        )
    status = 0
    tail = (proc.stdout or "").strip().splitlines()
    if tail:
        try:
            status = int(tail[-1].strip())
        except ValueError:
            status = 0
    return status, payload


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
    # Provenance gate, on the shared read path. Both callers (deploy.py main and
    # the setup wizard) come through here, so this is the one place that has to
    # be right.
    verify_release(build_dir)

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
    """PUT the module set, serialized per Worker, and report what landed.

    The lock is held across the whole retrying upload rather than only around
    the API call: a deploy that is still retrying a dropped connection holds
    the script slot just as much as one that is mid-request, and releasing the
    lock between attempts is exactly how two uploads interleave.
    """
    with deploy_lock(name):
        return _upload_locked(token, account, name, entry, modules, bindings, migrate_do)


def _upload_locked(token, account, name, entry, modules, bindings, migrate_do):
    metadata = {
        "main_module": entry,
        "compatibility_date": COMPATIBILITY_DATE,
        "bindings": bindings,
    }

    def _put(migrations):
        md = dict(metadata)
        if migrations:
            md["migrations"] = migrations
        parts = [("metadata", None, "application/json", json.dumps(md).encode())]
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

    # Migration semantics, measured against the live API on a disposable
    # account (scratch/mig_semantics_round5.json, 11 states):
    #   - Cloudflare compares a migration's declared `old_tag` with the
    #     script's actual tag. There is NO `current_tag` field: values of
    #     ""/false/"bogus" were all rejected identically, while a correct
    #     `old_tag` passed the tag check. Never send `current_tag`.
    #   - A script whose class is already registered rejects ANY second
    #     declaration of that class (412/10079 on the tag check first,
    #     400/10074 "already depended" once the tag matches). So a redeploy
    #     must send no migrations block at all — omitting it is a clean 200
    #     and is what every production redeploy does here.
    #   - A fresh name whose bindings reference an unregistered class is
    #     rejected atomically (400/10061 "not currently configured to
    #     implement Durable Objects"); nothing is created, and re-PUT with a
    #     tagless migration registers it in one shot (fresh actual tag is
    #     "" — measured: omitting old_tag on a fresh script → 200).
    #     That 10061 is the only trustworthy signal that registration is
    #     still owed, so it is the sole trigger to declare the class.
    try:
        return _put(None)
    except DeployError as exc:
        payload = getattr(exc, "payload", None) or {}
        codes = {e.get("code") for e in payload.get("errors", [])}
        if not migrate_do or 10061 not in codes:
            raise
    return _put({"new_sqlite_classes": [DO_CLASS]})


def enable_subdomain(token, account, name):
    _request(
        "POST",
        f"/accounts/{account}/workers/scripts/{name}/subdomain",
        token,
        body=json.dumps({"enabled": True}).encode(),
        content_type="application/json",
    )

def register_cron(token, account, name, cron):
    """Replace this Worker's Cron Triggers with `cron`.

    PUT (not POST) and the full list semantics are the API's own: the
    endpoint always sets the complete schedule set. Omitting --cron from a
    deploy leaves whatever schedules exist untouched.
    """
    _request(
        "PUT",
        f"/accounts/{account}/workers/scripts/{name}/schedules",
        token,
        body=json.dumps([{"cron": cron}]).encode(),
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
    ap.add_argument(
        "--session-diag",
        action="store_true",
        help="Add a SESSION_DIAG KV binding so session teardown publishes "
        "per-session byte counters and exit reasons to that namespace "
        "(diagnostics only; production deployments omit it)",
    )
    ap.add_argument("--no-do", action="store_true", help="Skip the Durable Object migration (redeploys)")
    ap.add_argument("--diagnostics", action="store_true", help="Set DIAGNOSTICS=true (do_error surfaces the DO error text)")
    ap.add_argument("--ws", action="store_true", help="Enable the WebSocket transport (WS_ENABLED=true); omit for XHTTP-only")
    ap.add_argument(
        "--cron",
        default=None,
        help="Register this cron expression as the Worker's Cron Trigger "
        "(e.g. '0 */2 * * *'). Omit to leave existing schedules untouched.",
    )
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

        # Diagnostics-only KV namespace for the SESSION_DIAG binding; created
        # lazily so a plain deploy never touches it.
        diag_kv = None
        if args.session_diag:
            diag_kv = ensure_kv(token, account, f"{args.name}-session-diag")

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
        # collect_modules() already verified the on-disk bytes. The second,
        # stricter check runs against the in-memory module list immediately
        # before upload(), so what is hashed is what the account will receive.
        total = sum(len(m[2]) for m in modules)
        print(f"Uploading {len(modules)} module(s), {total // 1024} KiB, entry {entry}...")

        bindings = [
            {"type": "kv_namespace", "name": "SETTINGS", "namespace_id": kv_id},
            {"type": "durable_object_namespace", "name": "XHTTP_SESSION", "class_name": DO_CLASS},
            {"type": "plain_text", "name": "XHTTP_PATH", "text": xhttp_path},
            {"type": "plain_text", "name": "PANEL_PATH", "text": panel_path},
            {"type": "plain_text", "name": "SUB_PATH", "text": sub_path},
            {"type": "plain_text", "name": "WS_ENABLED", "text": "true" if args.ws else "false"},
            {"type": "plain_text", "name": "WS_PATH", "text": "/ws"},
            {"type": "secret_text", "name": "VLESS_USERS", "text": user_uuid},
            {"type": "secret_text", "name": "TROJAN_USERS", "text": trojan_pw},
            {"type": "secret_text", "name": "VMESS_USERS", "text": vmess_uuid},
            {"type": "secret_text", "name": "SS_USERS", "text": ss_users},
            {"type": "secret_text", "name": "PANEL_PASSWORD", "text": panel_password},
        ]
        if args.diagnostics:
            # Temporary: surface DO stub errors as "DO-ERR ..." instead of the
            # decoy. Only for debugging a live deployment; remove after use.
            bindings.append({"type": "plain_text", "name": "DIAGNOSTICS", "text": "true"})
        if args.session_diag:
            # Diagnostics-only namespace: session teardown writes one small
            # JSON blob per session here. Never bound on production.
            bindings.append(
                {"type": "kv_namespace", "name": "SESSION_DIAG", "namespace_id": diag_kv}
            )

        manifest = verify_release(args.build_dir, modules)
        print(
              f"Release verified: commit {manifest['commit'][:7]}, "
              f"snapshot {manifest['snapshot'][:16]}")
        upload(token, account, args.name, entry, modules, bindings, not args.no_do)
        landed = live_revision(token, account, args.name)
        if landed:
            # The etag is Cloudflare's content hash of what it stored. Printing
            # it is the difference between "I uploaded something" and "this is
            # what the account now holds". When the API does not return one,
            # say so rather than printing an empty field that reads as a pass.
            etag = landed["script_etag"]
            shown = f"etag {etag[:16]}" if etag else "etag unavailable from the API"
            print(
                  f"  Landed     version {landed['version_number']} "
                  f"({landed['created_on']}) {shown}")
        enable_subdomain(token, account, args.name)
        if args.cron:
            register_cron(token, account, args.name, args.cron)
            print(f"  Cron          {args.cron}")

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
