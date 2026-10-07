"""Regression: DO migration payload + upload() state machine.

Measured on a disposable account against the live Cloudflare API
(scratch/mig_semantics_round5.json, mig_semantics_round6.json):

    fresh      + DO binding + no migration  -> 400 code 10061, atomically
    fresh      + {new_sqlite_classes}       -> 200 (registers the class)
    registered + any migration re-declared  -> 412/10079 then 400/10074
    registered + no migration               -> 200 (every production redeploy)
    `current_tag` is not a CF field at all: ""/false/"bogus" fail identically;
    CF compares the migration's declared `old_tag` with the script's tag.

These tests drive upload() through its REAL code path — real multipart body,
real JSON metadata — with only the transport replaced by a scripted recorder,
so a regression fails here, not in production:
  * the --no-do-era bug: migrations sent blindly on every redeploy (10079
    loop) or the DO binding silently dropped,
  * any tag field (old_tag/current_tag/new_tag) reappearing in a payload,
  * a 10061 rejection swallowed instead of retried once,
  * a non-10061 rejection retried instead of failing closed,
  * --no-do registering the class behind the operator's back.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deploy  # noqa: E402

TOKEN = "cf-test-token-abc123"
ACCOUNT = "0123456789abcdef0123456789abcdef"
PATH = f"/accounts/{ACCOUNT}/workers/scripts/probe"
BINDINGS = [
    {"type": "durable_object_namespace", "name": "XHTTP_SESSION",
     "class_name": "XhttpSession"},
    {"type": "kv_namespace", "name": "SETTINGS", "namespace_id": "1"},
]
MODULES = [("shim.mjs", "application/javascript+module", b"export default {}")]

REJECTED_10061 = deploy.DeployError(
    "PUT probe was rejected by Cloudflare: Cannot create binding for class "
    "'XhttpSession' because it is not currently configured to implement "
    "Durable Objects. Configure a migration in your configuration to add "
    "this class.")
REJECTED_10061.payload = {"success": False, "errors": [{
    "code": 10061,
    "message": "Cannot create binding for class 'XhttpSession' because it "
               "is not currently configured to implement Durable Objects."}]}

REJECTED_AUTH = deploy.DeployError(
    "PUT probe was rejected by Cloudflare: Invalid request headers")
REJECTED_AUTH.payload = {"success": False, "errors": [
    {"code": 1000, "message": "Invalid request headers"}]}


def _meta_from_body(body):
    """Pull the metadata JSON back out of the REAL multipart body."""
    i = body.index(b'name="metadata"')
    j = body.index(b"\r\n\r\n", i) + 4
    k = body.index(b"\r\n--", j)
    return json.loads(body[j:k])


class Recorder:
    """Stand-in for deploy._request that records real request construction."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def __call__(self, method, path, token, *, body=None, content_type=None):
        assert method == "PUT", f"unexpected method {method}"
        assert path == PATH, f"unexpected path {path}"
        self.calls.append({
            "token": token,
            "meta": _meta_from_body(body),
            "content_type": content_type or "",
        })
        if len(self.calls) > len(self.script):
            raise AssertionError(f"unexpected extra request #{len(self.calls)}")
        outcome = self.script[len(self.calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        # _request() returns payload["result"], not the whole envelope.
        return outcome.get("result") if isinstance(outcome, dict) else outcome


def _with_request(rec, fn, *args, **kwargs):
    real = deploy._request
    deploy._request = rec
    try:
        return fn(*args, **kwargs)
    finally:
        deploy._request = real


def _upload(migrate_do=True):
    return deploy.upload(TOKEN, ACCOUNT, "probe", "shim.mjs",
                         MODULES, BINDINGS, migrate_do)


def _upload_raising(rec, migrate_do=True):
    try:
        _with_request(rec, _upload, migrate_do=migrate_do)
    except deploy.DeployError as exc:
        return exc
    raise AssertionError("upload() did not raise")


def test_registered_redeploy_sends_no_migrations():
    """Production's every-redeploy path: one PUT, zero migrations keys."""
    rec = Recorder([{"success": True, "result": {"id": "x"}}])
    result = _with_request(rec, _upload)
    assert result == {"id": "x"}, result
    assert len(rec.calls) == 1, f"expected 1 upload, got {len(rec.calls)}"
    meta = rec.calls[0]["meta"]
    assert "migrations" not in meta, \
        f"migration re-sent on redeploy (CF answers 412/10079): {meta.get('migrations')}"
    assert meta["main_module"] == "shim.mjs"
    # --no-do-era poisoning guard: the DO binding must stay declared.
    assert any(b.get("name") == "XHTTP_SESSION" for b in meta["bindings"])
    assert rec.calls[0]["token"] == TOKEN


def test_fresh_worker_registers_class_after_10061():
    """Fresh name: reject (10061), then retry with EXACTLY the proven payload."""
    rec = Recorder([REJECTED_10061, {"success": True, "result": {"id": "y"}}])
    result = _with_request(rec, _upload)
    assert result == {"id": "y"}, result
    assert len(rec.calls) == 2, f"expected reject+retry, got {len(rec.calls)}"
    first, second = rec.calls[0]["meta"], rec.calls[1]["meta"]
    assert "migrations" not in first, "first attempt must not carry a migration"
    mig = second.get("migrations")
    # Proven live (round 6): tagless registration. No old_tag/new_tag/
    # current_tag — CF has no current_tag, and tag fields on a fresh script
    # are what produced the 10079 outage.
    assert mig == {"new_sqlite_classes": ["XhttpSession"]}, \
        f"wrong migration payload: {mig!r}"
    # Nothing but the migration may drift between attempt and retry.
    assert first["bindings"] == second["bindings"]
    assert first["main_module"] == second["main_module"]
    assert second["compatibility_date"] == first["compatibility_date"]


def test_non_10061_rejection_fails_closed():
    """Auth/other errors must surface immediately — no retry, no migration."""
    rec = Recorder([REJECTED_AUTH])
    exc = _upload_raising(rec)
    assert exc is REJECTED_AUTH, f"swallowed or replaced the error: {exc}"
    assert len(rec.calls) == 1, "retried a non-10061 failure"


def test_no_do_never_registers_behind_the_operator():
    """--no-do: registration declined, so a 10061 must propagate."""
    rec = Recorder([REJECTED_10061])
    exc = _upload_raising(rec, migrate_do=False)
    assert exc is REJECTED_10061, f"{exc}"
    assert len(rec.calls) == 1, "retried despite --no-do"
    assert "migrations" not in rec.calls[0]["meta"]


def test_request_layer_attaches_cf_payload_for_code_branching():
    """The 10061 branch depends on _request exposing CF's structured errors."""
    real_curl = deploy._curl_request
    deploy._curl_request = lambda *a, **k: (
        400, {"success": False, "errors": [{"code": 10061, "message": "x"}]})
    try:
        try:
            deploy._request("PUT", PATH, TOKEN)
            exc = None
        except deploy.DeployError as err:
            exc = err
    finally:
        deploy._curl_request = real_curl
    assert exc is not None, "_request did not raise on a 400 rejection"
    payload = getattr(exc, "payload", None)
    assert payload, "CF payload not attached to the exception"
    assert 10061 in {e.get("code") for e in payload.get("errors", [])}


def test_end_to_end_through_the_real_request_layer():
    """upload + real _request + scripted transport: the full 10061->retry path."""
    responses = [
        (400, {"success": False, "errors": [{"code": 10061, "message": "nope"}]}),
        (200, {"success": True, "result": {"id": "z"}}),
    ]
    bodies = []

    def fake_curl(method, path, token, body=None, content_type=None):
        bodies.append((method, path, body))
        return responses[len(bodies) - 1]

    real_curl = deploy._curl_request
    deploy._curl_request = fake_curl
    try:
        result = deploy.upload(TOKEN, ACCOUNT, "probe", "shim.mjs",
                               MODULES, BINDINGS, True)
    finally:
        deploy._curl_request = real_curl
    assert result == {"id": "z"}, result
    assert len(bodies) == 2, f"expected 2 PUTs, got {len(bodies)}"
    metas = [_meta_from_body(b) for _m, _p, b in bodies]
    assert "migrations" not in metas[0]
    assert metas[1].get("migrations") == {"new_sqlite_classes": ["XhttpSession"]}


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as exc:  # noqa: BLE001 — one failure must not mask the rest
                fails += 1
                print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print("FAILED" if fails else "ALL PASS")
    sys.exit(1 if fails else 0)
