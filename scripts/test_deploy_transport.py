"""Regression: the CF API transport must carry a REAL bearer token.

The curl transport replaced urllib because this host's Python TLS cannot
reach api.cloudflare.com. A redacted `Bearer ***` literal once shipped inside
the header template, which fails auth on every call while looking correct in
review. This asserts the header is built from the token argument.
"""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import deploy  # noqa: E402

TOKEN = "cf-test-token-abc123"


def _capture(argv):
    """Run the curl transport with subprocess.run replaced by a recorder."""
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        # curl writes the response body to the -o path; emulate that.
        out = cmd[cmd.index("-o") + 1]
        with open(out, "wb") as fh:
            fh.write(b'{"success": true, "result": {"ok": 1}}')
        return types.SimpleNamespace(stdout="\n200", stderr="")

    real_run = deploy.subprocess.run if hasattr(deploy, "subprocess") else None
    import subprocess as sp
    sp_run = sp.run
    sp.run = fake_run
    try:
        status, payload = deploy._curl_request("GET", "/probe", TOKEN)
    finally:
        sp.run = sp_run
    return seen["cmd"], status, payload, real_run


def test_header_carries_the_real_token():
    cmd, status, payload, _ = _capture(TOKEN)
    auth = [a for a in cmd if a.startswith("Authorization:")]
    assert auth, "no Authorization header built"
    assert auth[0] == f"Authorization: Bearer {TOKEN}", auth[0]
    assert "***" not in auth[0], "token was redacted into the live header"


def test_status_and_payload_are_returned():
    _, status, payload, _ = _capture(TOKEN)
    assert status == 200, status
    assert payload == {"success": True, "result": {"ok": 1}}, payload


def test_body_posts_bytes_from_a_file_not_a_shell_string():
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        out = cmd[cmd.index("-o") + 1]
        with open(out, "wb") as fh:
            fh.write(b'{"success": true, "result": []}')
        return types.SimpleNamespace(stdout="\n200", stderr="")

    import subprocess as sp
    sp_run = sp.run
    sp.run = fake_run
    try:
        deploy._curl_request("PUT", "/upload", TOKEN, b"\x00\x01binary", "application/octet-stream")
    finally:
        sp.run = sp_run
    cmd = seen["cmd"]
    assert "--data-binary" in cmd
    assert cmd[cmd.index("--data-binary") + 1].startswith("@"), "body not passed via file"
    assert "application/octet-stream" in " ".join(cmd), "content type missing"


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                fails += 1
                print(f"FAIL {name}: {exc}")
    print("FAILED" if fails else "ALL PASS")
    sys.exit(1 if fails else 0)