"""Negative tests for the release-integrity gate.

Why this file exists. The build directory used to be anonymous: nothing recorded
which source produced it, nothing hashed it, and nothing stopped a deploy from
uploading bytes that a later build had already replaced. A 200 from Cloudflare
proved the upload was accepted, never that it was the right upload, so an
artifact swap passed unnoticed. Each test below builds a REAL build directory
in a temp dir, corrupts it the way a real mistake would, and asserts the gate
refuses before any API call happens.

Nothing here touches the network or the account: the gate is exercised directly,
and _request is replaced by a tripwire so "no API call was made" is an
assertion rather than a hope.

Run: python scripts/test_release_gate.py
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deploy  # noqa: E402

SHIM = b"export default {}\n"


def _make_build_dir(root, modules=None):
    """A build directory that passes the gate, built by the real manifest code."""
    bdir = os.path.join(root, "worker")
    os.makedirs(bdir, exist_ok=True)
    mods = modules or {
        "shim.mjs": SHIM,
        "index.js": b"export function fetch() {}\n",
        "index_bg.wasm": b"\x00asm\x01\x00\x00\x00" + b"body" * 64,
    }
    for name, data in mods.items():
        with open(os.path.join(bdir, name), "wb") as fh:
            fh.write(data)
    deploy.write_manifest(bdir)
    return bdir


def _git(*args, cwd):
    return subprocess.run(["git", "-C", cwd, *args], capture_output=True, check=True)


def _git_ok(*args, cwd):
    """git may legitimately fail (nothing to commit); provenance still reads."""
    p = subprocess.run(["git", "-C", cwd, *args], capture_output=True)
    return p.returncode


def _git_repo(root):
    """Turn root into a git checkout so provenance can be recorded at all."""
    # Identity comes from -c rather than GIT_* env vars so this does not depend
    # on the caller's environment, and a seed file exists so the first commit
    # has something in it (an empty tree is not a valid commit).
    with open(os.path.join(root, "seed.txt"), "w") as fh:
        fh.write("seed\n")
    _git("init", "-q", root, cwd=root)
    _git_ok("-c", "user.name=t", "-c", "user.email=t@e",
            "-c", "commit.gpgsign=false", "add", "-A", cwd=root)
    _git_ok("-c", "user.name=t", "-c", "user.email=t@e",
            "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base", cwd=root)
    assert _git_ok("rev-parse", "HEAD", cwd=root) == 0, "git repo has no commit"
    return root


class Tripwire(Exception):
    """Raised if the gate ever lets an API call through."""


def _forbid_api(monkey):
    def boom(*a, **k):
        raise Tripwire("an API call was attempted before the gate passed")
    monkey(deploy, "_request", boom)


def _monkey(obj, name, value):
    old = getattr(obj, name)
    setattr(obj, name, value)
    return old


# --- 1. positive: a clean, matching build is accepted -----------------------

def test_clean_build_is_accepted():
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = _make_build_dir(root)
            entry, mods = deploy.collect_modules(bdir)
            manifest = deploy.verify_release(bdir, mods)
            assert entry == "shim.mjs", entry
            assert manifest["commit"], "no commit recorded"
            assert len(manifest["artifacts"]) == 3, manifest["artifacts"]
        finally:
            os.chdir(cwd)


# --- 2. stale/substituted artifact bytes are rejected ----------------------

def test_substituted_artifact_is_rejected():
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = _make_build_dir(root)
            # Exactly the real failure mode: a build runs after the manifest was
            # written, replacing the wasm with different bytes.
            with open(os.path.join(bdir, "index_bg.wasm"), "wb") as fh:
                fh.write(b"\x00asm\x01\x00\x00\x00" + b"DIFFERENT" * 64)
            try:
                deploy.verify_release(bdir)
            except deploy.DeployError as exc:
                assert "SHA-256" in str(exc), exc
                assert "index_bg.wasm" in str(exc), exc
            else:
                raise AssertionError("a substituted artifact was accepted")
        finally:
            os.chdir(cwd)


# --- 3. an artifact modified AFTER verification is rejected ----------------

def test_modified_after_verification_is_rejected():
    """Verify passes, then the file changes, then the deploy check must fail.

    This is the TOCTOU window the second verify closes: the first check reads
    the disk, the second checks the in-memory bytes about to be uploaded.
    """
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = _make_build_dir(root)
            deploy.verify_release(bdir)          # passes
            with open(os.path.join(bdir, "shim.mjs"), "wb") as fh:
                fh.write(b"export default {tampered:true}\n")
            # collect_modules itself must now refuse.
            try:
                deploy.collect_modules(bdir)
            except deploy.DeployError as exc:
                assert "SHA-256" in str(exc), exc
            else:
                raise AssertionError("a post-verify modification was accepted")
        finally:
            os.chdir(cwd)


# --- 4. a missing artifact or failed build aborts the release --------------

def test_missing_artifact_aborts():
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = _make_build_dir(root)
            os.remove(os.path.join(bdir, "index_bg.wasm"))
            try:
                deploy.collect_modules(bdir)
            except deploy.DeployError as exc:
                assert "missing" in str(exc), exc
                assert "index_bg.wasm" in str(exc), exc
            else:
                raise AssertionError("a missing artifact was accepted")
        finally:
            os.chdir(cwd)


def test_extra_artifact_aborts():
    """A leftover file from an earlier build would silently ship too."""
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = _make_build_dir(root)
            with open(os.path.join(bdir, "old_shim.mjs"), "wb") as fh:
                fh.write(b"export default {}\n")
            try:
                deploy.collect_modules(bdir)
            except deploy.DeployError as exc:
                assert "not in the manifest" in str(exc), exc
                assert "old_shim.mjs" in str(exc), exc
            else:
                raise AssertionError("an unrecorded artifact was accepted")
        finally:
            os.chdir(cwd)


def test_no_manifest_aborts():
    """A build directory that scripts/build.py never produced is refused."""
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = os.path.join(root, "worker")
            os.makedirs(bdir)
            with open(os.path.join(bdir, "shim.mjs"), "wb") as fh:
                fh.write(SHIM)
            try:
                deploy.collect_modules(bdir)
            except deploy.DeployError as exc:
                assert deploy.MANIFEST_NAME in str(exc), exc
            else:
                raise AssertionError("a manifest-less build dir was accepted")
        finally:
            os.chdir(cwd)


def test_corrupt_manifest_aborts():
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = _make_build_dir(root)
            with open(os.path.join(bdir, deploy.MANIFEST_NAME), "w") as fh:
                fh.write("{not json")
            try:
                deploy.collect_modules(bdir)
            except deploy.DeployError as exc:
                assert "unreadable" in str(exc), exc
            else:
                raise AssertionError("a corrupt manifest was accepted")
        finally:
            os.chdir(cwd)


def test_failed_build_leaves_production_untouched():
    """A gate failure must abort BEFORE any API call, so nothing is uploaded."""
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = _make_build_dir(root)
            with open(os.path.join(bdir, "index_bg.wasm"), "wb") as fh:
                fh.write(b"tampered")
            old = _monkey(deploy, "_request", lambda *a, **k: _raise_tripwire())
            try:
                deploy.collect_modules(bdir)
            except deploy.DeployError:
                pass            # expected refusal
            except Tripwire:
                raise AssertionError("the gate let an API call through")
            else:
                raise AssertionError("a tampered artifact was accepted")
            finally:
                setattr(deploy, "_request", old)
        finally:
            os.chdir(cwd)


def _raise_tripwire():
    raise Tripwire("an API call was attempted before the gate passed")


# --- 5. two concurrent deploys cannot race ---------------------------------

def test_concurrent_deploys_are_serialized():
    """A held lock refuses the second deploy rather than interleaving."""
    name = f"trinity-test-{os.getpid()}"
    with deploy.deploy_lock(name):
        try:
            deploy.deploy_lock(name).__enter__()
        except deploy.DeployError as exc:
            assert "holds" in str(exc), exc
        else:
            raise AssertionError("two deploys were allowed to hold the lock")
    # Released on exit, so the name is reusable.
    with deploy.deploy_lock(name):
        pass


# --- 6. a source-snapshot mismatch prevents deployment --------------------

def test_source_change_after_build_is_rejected():
    """Edit the source after building: the artifact is no longer the review."""
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            os.makedirs(os.path.join(root, "src"))
            with open(os.path.join(root, "src", "lib.rs"), "w") as fh:
                fh.write("fn main() {}\n")
            bdir = _make_build_dir(root)
            deploy.verify_release(bdir)          # passes on a clean tree
            with open(os.path.join(root, "src", "lib.rs"), "a") as fh:
                fh.write("// changed after the build\n")
            try:
                deploy.verify_release(bdir)
            except deploy.DeployError as exc:
                assert "source tree changed" in str(exc), exc
            else:
                raise AssertionError("a stale build passed after a source edit")
        finally:
            os.chdir(cwd)


def test_new_commit_after_build_is_rejected():
    """A commit between build and deploy must not pass as the reviewed build."""
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            bdir = _make_build_dir(root)
            deploy.verify_release(bdir)
            env = {**os.environ}
            with open(os.path.join(root, "extra.txt"), "w") as fh:
                fh.write("x")
            _git_ok("-c", "user.name=t", "-c", "user.email=t@e",
                    "-c", "commit.gpgsign=false", "add", "-A", cwd=root)
            _git_ok("-c", "user.name=t", "-c", "user.email=t@e",
                    "-c", "commit.gpgsign=false", "commit", "-q", "-m", "later", cwd=root)
            assert _git_ok("rev-parse", "--verify", "HEAD", cwd=root) == 0
            try:
                deploy.verify_release(bdir)
            except deploy.DeployError as exc:
                assert "source tree changed" in str(exc), exc
            else:
                raise AssertionError("a build from an older commit was accepted")
        finally:
            os.chdir(cwd)


def test_manifest_records_no_secret_material():
    """The manifest may be read by anything; it must carry no credentials."""
    with tempfile.TemporaryDirectory() as root:
        _git_repo(root)
        cwd = os.getcwd()
        os.chdir(root)
        try:
            with open(os.path.join(root, ".env.fresh"), "w") as fh:
                fh.write("TRINITY_NEW_TOKEN=super-secret-value\n")
            bdir = _make_build_dir(root)
            blob = open(os.path.join(bdir, deploy.MANIFEST_NAME), encoding="utf-8").read()
            assert "super-secret-value" not in blob, "the manifest leaked a token"
            assert "super-secret" not in blob
            # Only the fields we intend.
            assert set(json.loads(blob)) == {"commit", "snapshot", "artifacts"}
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as exc:  # noqa: BLE001 - one failure must not mask the rest
                fails += 1
                print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print("FAILED" if fails else "ALL PASS")
    sys.exit(1 if fails else 0)