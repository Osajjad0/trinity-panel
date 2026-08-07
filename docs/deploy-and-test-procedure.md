# Deploy and test procedure

Terse checklist for someone who already knows the ground. For a full walkthrough
see [INSTALL.md](../INSTALL.md).

Note: the crate is still named `tricore-panel` internally, so the build artefact
filename below is correct and unchanged by the rebrand to Trinity Panel.

## 1. Build release WASM
from the repo root run:
- cargo build --target wasm32-unknown-unknown --release
- wasm-bindgen --target modules --out-dir build/worker --out-name index target/wasm32-unknown-unknown/release/tricore_panel.wasm

## 2. Run preflight checks
read CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID from env, then call:
- GET https://api.cloudflare.com/client/v4/accounts/<account ID>
- GET https://api.cloudflare.com/client/v4/accounts/<account ID>/workers/scripts
- GET https://api.cloudflare.com/client/v4/accounts/<account ID>/storage/kv/namespaces

## 3. Deploy
use scripts/deploy.py with --name, --build-dir build/worker, --kv-id or --kv-title, and the worker secret bindings.

## 4. Verify
probe the deployed worker:
1. PUT /api/nodes with a saved node list
2. GET /api/state immediately after
3. confirm state.source == "stored"
