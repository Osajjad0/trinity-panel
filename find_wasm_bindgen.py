#!/usr/bin/env python3
"""Locate the wasm-bindgen binary and report the version Cargo.lock pins."""
import re
from pathlib import Path

lock = Path("Cargo.lock").read_text(encoding="utf-8")
m = re.search(r'\[\[package\]\]\s*\nname = "wasm-bindgen"\s*\nversion = "([^"]+)"', lock)
print("pinned wasm-bindgen crate:", m.group(1) if m else "NOT FOUND")

candidates = []
for base in [
    Path.home() / ".cargo" / "bin",
    Path.home() / ".local" / "bin",
    Path(r"C:\tools"),
    Path(r"C:\bin"),
    Path.home() / "bin",
    Path.home() / "Downloads",
    Path.home() / "Desktop",
]:
    if base.exists():
        candidates.extend(base.glob("**/wasm-bindgen*.exe"))
import os
env = os.environ.get("WASM_BINDGEN")
print("WASM_BINDGEN env:", env or "(unset)")
for c in sorted(set(candidates))[:10]:
    print("found:", c)
