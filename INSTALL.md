# Installing Trinity Panel

The recommended way to install is the setup wizard — it builds the Worker, talks to
the Cloudflare API on your behalf, generates every credential, and returns a
private panel link. If you just want to get running:

```bash
python scripts/install.py
```

This guide is the **manual CLI path** the wizard wraps. It is here for when you
want every step spelled out, every binding explained, or a deploy you script
yourself. It assumes you have **never used Cloudflare Workers and never used
Rust**.

Deploying takes about 30 minutes the first time, most of it waiting for Rust to
compile. Everything here fits inside Cloudflare's free plan.

**Contents**

1. [What you are building](#1-what-you-are-building)
2. [Install the prerequisites](#2-install-the-prerequisites)
3. [Get the code and build it](#3-get-the-code-and-build-it)
4. [Create a Cloudflare API token](#4-create-a-cloudflare-api-token)
5. [Find your account ID](#5-find-your-account-id)
6. [Deploy](#6-deploy)
7. [Access the panel](#7-access-the-panel)
8. [Connect a client](#8-connect-a-client)
9. [Every binding, explained](#9-every-binding-explained)
10. [Changing things after deployment](#10-changing-things-after-deployment)
11. [Troubleshooting](#11-troubleshooting)
12. [Deploying with wrangler instead](#12-deploying-with-wrangler-instead)

---

## 1. What you are building

A single Cloudflare Worker — a small program that runs on Cloudflare's edge
network — reachable at a URL like `https://my-worker.your-name.workers.dev`. It
serves three things on three secret, random paths:

- **the proxy transport**, which your VPN client connects to;
- **a subscription endpoint**, which hands your client its configuration;
- **an admin panel**, a web page where you view and edit settings.

Anything that hits a path it doesn't recognise gets a plain "all systems
operational" status page. That is deliberate: someone scanning your hostname
should find nothing interesting.

The Worker also needs two storage attachments, both created for you by the deploy
script:

- a **KV namespace** — a small key-value store, used to persist panel settings;
- a **Durable Object** — a single-instance object that holds one proxy session's
  network socket open across multiple HTTP requests.

You need: a free Cloudflare account, a terminal, and roughly 2 GB of free disk for
the Rust toolchain.

---

## 2. Install the prerequisites

### 2.1 Python 3.8 or newer

The build and deploy scripts are plain Python using only the standard library — no
`pip install` needed.

```bash
python --version
```

If that fails, install Python from [python.org](https://www.python.org/downloads/).
On Windows, tick **"Add Python to PATH"** during installation.

### 2.2 Rust

Install via [rustup.rs](https://rustup.rs). On Linux and macOS:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

On Windows, download and run `rustup-init.exe` from the same page. Restart your
terminal afterwards, then confirm:

```bash
cargo --version
```

This project needs Rust **1.82 or newer** (declared as `rust-version` in
`Cargo.toml`).

### 2.3 The wasm32 compilation target

Cloudflare Workers run WebAssembly, not native binaries. Rust needs that target
added explicitly:

```bash
rustup target add wasm32-unknown-unknown
```

### 2.4 wasm-bindgen — and the version trap

`wasm-bindgen` generates the JavaScript glue that lets the Workers runtime call
into the compiled WebAssembly.

> **This is the single most common way to break the build.** The `wasm-bindgen`
> **command-line tool** must match the `wasm-bindgen` **library version** in
> `Cargo.lock` *exactly*. Not "close enough" — exactly. A mismatch produces glue
> that does not match the module, and the failure surfaces at runtime as a broken
> deployment rather than at build time as an error you can read.

Find the version this repository pins:

```bash
grep -A1 'name = "wasm-bindgen"' Cargo.lock
```

At the time of writing that is **0.2.126**. Install exactly that:

```bash
cargo install wasm-bindgen-cli --version 0.2.126
```

Then verify the two agree:

```bash
wasm-bindgen --version
```

If you would rather not compile it, prebuilt binaries for every version are at
[github.com/rustwasm/wasm-bindgen/releases](https://github.com/rustwasm/wasm-bindgen/releases).
Download the one matching `Cargo.lock`, put it on your `PATH`, or point the build
script straight at it:

```bash
export WASM_BINDGEN=/full/path/to/wasm-bindgen
```

**If you ever update dependencies, re-check this.** A `cargo update` that bumps the
`wasm-bindgen` library silently invalidates the CLI you installed.

### 2.5 What you do *not* need

- **Node.js / npm** — not required for the Python deploy path.
- **wrangler** — Cloudflare's CLI. Optional; see [section 12](#12-deploying-with-wrangler-instead).
- **A domain name** — the free `*.workers.dev` subdomain works.
- **`worker-build`** — the official build tool. `scripts/build.py` exists precisely
  because `worker-build` depends on `zstd-sys`, whose build script needs a C
  toolchain and fails on hosts that link with Rust's bundled `rust-lld`.

---

## 3. Get the code and build it

```bash
git clone https://github.com/Osajjad0/trinity-panel.git
cd trinity-panel
```

Run the tests first. They are fast and need no network, no Cloudflare account and
no WebAssembly — a green run means the protocol parsers, the wire layer and the
config emitters are all working before you deploy anything.

```bash
cargo test --lib
```

Expect roughly 369 passing tests in well under a minute.

Now build the Worker:

```bash
python scripts/build.py
```

The first run compiles every dependency and can take 5–15 minutes. Subsequent runs
take seconds. When it finishes you will see something like:

```
Built:
  index.js               42.1 KiB
  index_bg.wasm         610.3 KiB
  shim.mjs                3.4 KiB
  total                 655.8 KiB
```

Those files live in `build/worker/`. That directory is gitignored — it is build
output, not source.

If the build fails, jump to [Troubleshooting](#11-troubleshooting).

---

## 4. Create a Cloudflare API token

The deploy script talks to Cloudflare's REST API and needs a token. **Do not use a
Global API Key** — it can do everything to your account, and nothing here needs
that.

1. Sign in at [dash.cloudflare.com](https://dash.cloudflare.com).
2. Go to **My Profile → API Tokens**
   ([direct link](https://dash.cloudflare.com/profile/api-tokens)).
3. Click **Create Token**, then **Create Custom Token → Get started**.
4. Give it a name — `trinity-panel-deploy` is fine.
5. Under **Permissions**, add exactly these three rows:

   | Type | Resource | Level |
   |---|---|---|
   | Account | Workers Scripts | **Edit** |
   | Account | Workers KV Storage | **Edit** |
   | Account | Account Settings | **Read** |

   Why each: *Workers Scripts: Edit* uploads the Worker. *Workers KV Storage: Edit*
   creates the settings namespace. *Account Settings: Read* discovers your
   `workers.dev` subdomain, which is part of your final URL.

6. Under **Account Resources**, select the account you are deploying to.
7. Click **Continue to summary**, then **Create Token**.
8. **Copy the token now.** Cloudflare shows it exactly once.

**Only if you later attach a custom domain** do you also need `Zone → DNS: Edit`
and `Zone → Zone: Read`. Skip both for a `workers.dev` deployment. Do not grant
more than you need — a broader token is a larger loss if it leaks.

> Cloudflare's own "verify token" endpoint (`GET /user/tokens/verify`) will report
> a correctly-scoped account token as **invalid**. That endpoint is user-scoped and
> an account-scoped token cannot call it. Ignore it; the deploy script probes the
> endpoints it actually uses instead.

---

## 5. Find your account ID

In the Cloudflare dashboard, open **Workers & Pages**. The **Account ID** is shown
in the right-hand sidebar — a 32-character hex string. Copy it.

It is also visible in any dashboard URL:
`https://dash.cloudflare.com/<account-id>/workers`.

---

## 6. Deploy

Put both values in your shell. They are read from the environment and never from a
file in the repository.

macOS / Linux:

```bash
export CLOUDFLARE_API_TOKEN=your_token_here
export CLOUDFLARE_ACCOUNT_ID=your_account_id_here
```

Windows PowerShell:

```powershell
$env:CLOUDFLARE_API_TOKEN="your_token_here"
$env:CLOUDFLARE_ACCOUNT_ID="your_account_id_here"
```

If you prefer a file, copy `.env.example` to `.env` and fill it in — `.env` is
gitignored — then load it into your shell yourself. The scripts read the
environment, not the file.

Pick a Worker name. It becomes your hostname, so choose something unremarkable:

> Cloudflare has been known to act on accounts running recognisably-named proxy
> panels. `my-status-page` is a better name than `free-vless-proxy`. Lowercase
> letters, digits and hyphens only.

Deploy:

```bash
python scripts/deploy.py --name my-status-page --build-dir build/worker
```

The script will:

1. verify your token really has the three permissions, by using them;
2. create a KV namespace called `<name>-settings` (or reuse it if it exists);
3. generate a random UUID, a Trojan password, a Shadowsocks-2022 key, a panel
   password, and three random 8-byte-hex path prefixes;
4. upload the WebAssembly module set with every binding attached;
5. register the Durable Object migration;
6. enable the `workers.dev` subdomain;
7. print everything.

Output looks like this:

```
Deployed.

  Host          https://my-status-page.your-name.workers.dev
  XHTTP path    /1f4c7a9e02b6d835
  Panel path    https://my-status-page.your-name.workers.dev/7d3e10c8b5a24f9b
  Panel pass    xK2p-QvR8nT4wYzA6bCdEfGh
  Subscription  https://my-status-page.your-name.workers.dev/c92a6f04e71b38dd
  VLESS UUID    ...
  Trojan pass   ...
  VMess UUID    ...
  SS method     2022-blake3-aes-256-gcm
  SS password   ...
```

> **Copy all of it into your password manager right now.** Nothing is written to
> disk. The panel password and the protocol credentials are stored as Cloudflare
> secrets, which are write-only — you cannot read them back from the dashboard or
> the API. Losing them means redeploying with new ones.

### Useful flags

| Flag | Effect |
|---|---|
| `--uuid <uuid>` | Use a specific VLESS UUID instead of a generated one |
| `--vmess-uuid <uuid>` | Separate VMess UUID (defaults to the VLESS one) |
| `--trojan-password <pw>` | Set the Trojan password |
| `--ss-method <method>` | `2022-blake3-aes-256-gcm` (default), `...-aes-128-gcm`, `...-chacha20-poly1305` |
| `--ss-password <b64>` | Shadowsocks key, base64. Length is fixed by the method — 16 bytes for the 128-bit method, 32 otherwise |
| `--ss-users <list>` | Several users or methods at once: comma-separated `method:base64key` entries |
| `--panel-password <pw>` | Set the panel password |
| `--xhttp-path`, `--panel-path`, `--sub-path` | Fix a path prefix instead of generating one |
| `--kv-id <id>` | Reuse an existing KV namespace by id |
| `--kv-title <title>` | Name the KV namespace something other than `<name>-settings` |
| `--no-do` | Skip the Durable Object migration. **Use this on every redeploy after the first** |

**Passing an empty string disables a protocol.** `--trojan-password ""` deploys with
Trojan off; `--panel-password ""` deploys with no panel at all, which is different
from an unprotected one.

---

## 7. Access the panel

Open the **Panel path** URL from the deploy output. You will get a sign-in page.
Enter the panel password.

If instead you see the "all systems operational" status page, one of these is true:

- the URL is wrong — the prefix is random and case-sensitive;
- `PANEL_PASSWORD` is unset or empty, so the panel is closed by design;
- your session cookie expired (they last 12 hours) — reload and sign in again.

The panel deliberately does not distinguish these. There is no error message
telling a scanner which mistake it made.

Inside, **Get connected** lists each supported client app with a copyable
subscription link and a QR code. **Advanced** exposes every setting, with options
that cannot work for your chosen client switched off and the reason attached.

> **Known limitation:** the panel UI has not been verified end-to-end against a
> live deployment. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md). Subscription serving
> *has* been verified and works whether or not you ever open the panel.

---

## 8. Connect a client

The subscription endpoint works immediately after deployment, with no panel visit
required — nodes are derived from the bindings the Worker was deployed with.

Take the **Subscription** URL from the deploy output and append your client's name:

| Client | Subscription URL |
|---|---|
| v2rayN | `<sub-url>/v2rayn` |
| v2rayNG | `<sub-url>/v2rayng` |
| Hiddify | `<sub-url>/hiddify` |
| Karing | `<sub-url>/karing` |
| mihomo / Clash Meta | `<sub-url>/mihomo` |
| sing-box (upstream) | `<sub-url>/sing-box` |
| NekoBox | `<sub-url>/nekobox` |

Add `.json` (or `.yaml` for mihomo) to get a full configuration file instead of
base64 share links:

```
https://my-status-page.your-name.workers.dev/c92a6f04e71b38dd/v2rayn.json
```

Paste the plain URL into your client's "add subscription" field. An unknown client
name returns the decoy page, so the endpoint cannot be used to enumerate what you
serve.

**Upstream sing-box and NekoBox cannot import XHTTP nodes** — upstream sing-box has
never supported the transport. Use Hiddify or Karing on mobile, both of which ship
patched forks that do. The panel tells you this per client rather than emitting a
config that will not work.

---

## 9. Every binding, explained

This is the complete list the Worker reads, verified against both the source and a
live deployment. The deploy script sets all of them.

### Secrets (`secret_text` — write-only, never readable back)

| Name | Read by | Contents |
|---|---|---|
| `VLESS_USERS` | `config::env`, `transport::xhttp::durable`, `transport::websocket` | One or more UUIDs. Separators: comma, newline or semicolon. Empty disables VLESS |
| `TROJAN_USERS` | same | One or more passwords. Hashed to the wire key at startup, never stored raw. Empty disables Trojan |
| `VMESS_USERS` | same | One or more UUIDs. Key material is derived once at startup, not per request. Empty disables VMess |
| `SS_USERS` | same | Comma-separated `method:base64key`. Self-describing because a Shadowsocks-2022 key is only valid against one method. Empty disables Shadowsocks |
| `PANEL_PASSWORD` | `panel::serve` | Plaintext admin password. **Empty or unset means the panel does not exist**, not that it is open |

A malformed entry in a user list is skipped rather than failing the whole list —
one bad paste should cost you one user, not every user.

> **Note on `.dev.vars.example`:** it documents `PANEL_PASSWORD` only, matching the
> table above. The Worker reads plaintext `PANEL_PASSWORD` and derives the
> session-signing key from it via BLAKE3 — there is no `PANEL_PASSWORD_HASH` or
> `SESSION_SIGNING_KEY` binding, despite what older copies of this file said.

### Plain-text variables (`plain_text` — visible in the dashboard)

| Name | Default set by deploy | Purpose |
|---|---|---|
| `XHTTP_PATH` | random 8-byte hex, e.g. `/1f4c7a9e02b6d835` | Base path for the proxy transport. **Empty means every request gets the decoy** — an unconfigured deployment exposes nothing rather than serving on a guessable path |
| `PANEL_PATH` | random 8-byte hex | Base path for the admin panel |
| `SUB_PATH` | random 8-byte hex | Base path for subscriptions |
| `WS_ENABLED` | `true` (script) / `false` (`wrangler.jsonc`) | WebSocket transport on/off. Only active when `WS_PATH` is also non-empty |
| `WS_PATH` | `/ws` | WebSocket path. Unproven — see [KNOWN_ISSUES.md](KNOWN_ISSUES.md) |
| `DIAGNOSTICS` | not set | Set to `true` to enable the connect-probe endpoint. **Leave unset in production** — it dials an arbitrary host and port and reports the result, which turns your Worker into a port scanner |

### Storage bindings

| Binding | Type | Purpose |
|---|---|---|
| `SETTINGS` | KV namespace | Panel settings, under the single key `panel:settings`. Empty until you save from the panel; the subscription falls back to nodes derived from the bindings above |
| `XHTTP_SESSION` | Durable Object (`class_name: XhttpSession`) | Holds one XHTTP session: the outbound socket, the uplink reorder buffer, the downlink stream |
| `ASSETS` | Static assets (`wrangler` path only) | Serves the decoy page. The Python deploy path does not upload assets; the Worker falls back to a built-in decoy, and the panel HTML is compiled into the module either way |

> The Durable Object migration **must** use `new_sqlite_classes`, not `new_classes`.
> The KV-backed form fails outright on accounts with no pre-existing KV-backed
> namespace, and SQLite-backed objects are the only kind on the free plan. Both the
> script and `wrangler.jsonc` get this right; if you write your own deploy, don't.

---

## 10. Changing things after deployment

**Adding or removing a proxy user is a redeploy, not a panel edit.** Credentials
live in secret bindings that the Durable Object reads on the request path.
Deliberately: moving them to KV would add a storage round trip in front of every
new session, and a panel bug could then lock every user out of a working
deployment.

To change credentials, redeploy with the new values and `--no-do` (the Durable
Object already exists):

```bash
python scripts/deploy.py --name my-status-page --build-dir build/worker \
  --kv-id <your-kv-id> --no-do \
  --uuid <uuid-1> --panel-password <same-or-new>
```

Pass `--kv-id` to keep your saved settings; without it the script reuses the
namespace matching `<name>-settings`, which is normally the same one.

What the **panel** owns instead is everything client-side: hostnames, SNI,
transport parameters, per-core options, chains. That is where the configuration
effort actually is.

To rotate the panel password, redeploy with a new `--panel-password`. Every
outstanding session is invalidated automatically, because the session key is
derived from the password.

---

## 11. Troubleshooting

**`wasm-bindgen not found`** — install it at the version in `Cargo.lock`
([2.4](#24-wasm-bindgen--and-the-version-trap)), or set `WASM_BINDGEN` to its full
path.

**The Worker uploads but every request fails** — almost always a `wasm-bindgen`
version mismatch. Re-read [2.4](#24-wasm-bindgen--and-the-version-trap), reinstall
at the exact version, rebuild, redeploy.

**`No such module` at runtime, after a successful upload** — `wasm-bindgen` emits
inline JS snippets into `snippets/<hash>/inline0.js`, and they must be uploaded
under exactly those relative paths. `scripts/deploy.py` walks the build directory
for this reason. A hand-rolled upload that only lists the top level will hit this.

**Linker errors on Windows without Visual Studio** — install the
`x86_64-pc-windows-gnullvm` host toolchain, which links with Rust's bundled
`rust-lld`. Note that its bundled `self-contained` object set is incomplete
(missing `libadvapi32.a`, `libole32.a`, `liboleaut32.a`), so **any crate whose
build script pulls in the `cc` crate will fail to link**. That is why BLAKE3 is
implemented in-tree here rather than taken from the `blake3` crate. If you add a
dependency with a C-building build script, you will hit the same wall.

**`cargo` or `rustup` hangs downloading** — if you are behind a TUN-mode proxy
using fake-IP DNS (hostnames resolving into `198.18.0.0/15` or `fc00::/18`), their
HTTP client stalls on the synthetic IPv6 record with no fallback. Ordinary browsing
still works, which makes it look like an intermittent network fault. Set
`HTTPS_PROXY` and `HTTP_PROXY` to the proxy's own address to bypass DNS entirely.

**Every protocol fails at once, including ones that worked yesterday** — suspect
your own machine before the deployment. The same fake-IP DNS breaks proxy clients:
the core resolves your hostname to a synthetic address, dials it, and gets your
local proxy's HTML error page. Xray reports `unexpected response version. Expecting
0 but actually 60` — and `60` is `0x3C`, the `<` of `<html`. Fix: resolve the
hostname out of band via DNS-over-HTTPS and point the client's `address` at a real
Cloudflare edge IP, leaving `serverName` and the transport `host` as the hostname.
That is the same clean-IP mechanism the panel exposes as a feature.

**The proxy connects but nothing loads, and your test URL is an IP-echo service** —
outbound connections from Workers to Cloudflare's own IP ranges are refused. Port
443 is fine; the address range is what is blocked. Most public IP-echo services are
Cloudflare-fronted. Test against a non-Cloudflare host.

**`Cannot read the account` / `Cannot list Workers` / `Cannot list KV namespaces`**
— the token is missing that specific permission. Recreate it per
[section 4](#4-create-a-cloudflare-api-token). Remember that Cloudflare's
verify-token endpoint lies about account-scoped tokens.

**`This account has no workers.dev subdomain yet`** — register one in the dashboard
under **Workers & Pages**, then re-run.

**Redeploy fails on the Durable Object migration** — pass `--no-do`. The migration
creates the class and only runs once.

**Network resets mid-deploy (`WinError 10054`)** — the script already retries
failed requests with backoff. If it still fails, re-run; upload is idempotent.

---

## 12. Deploying with wrangler instead

`wrangler.jsonc` is provided for the CLI path. It needs Node.js and three edits
before it will work:

1. Set `"name"` to your Worker name.
2. Create a KV namespace and paste its id:

   ```bash
   npx wrangler kv namespace create SETTINGS
   ```

3. **Replace the `XHTTP_PATH` and `PANEL_PATH` defaults.** Both ship as `"/"`,
   which is a placeholder the Python script overwrites. Deploying as-is serves the
   transport on your root path — exactly what the random-prefix design exists to
   prevent. Generate random values and add `SUB_PATH` too, which the file omits.

Then set the secrets and deploy:

```bash
npx wrangler secret put VLESS_USERS
npx wrangler secret put TROJAN_USERS
npx wrangler secret put VMESS_USERS
npx wrangler secret put SS_USERS
npx wrangler secret put PANEL_PASSWORD
npx wrangler deploy
```

Note that `wrangler.jsonc` does not reference `npm run build` or any npm script —
there is no `package.json` in this repository. Build with
`python scripts/build.py`; generate a panel password with any password manager.
The `wrangler.jsonc` `main` points at `build/worker/shim.mjs`, which that build
produces; `worker-build` (the tool behind `build.command` in older configs) may not
install on your host (see [2.5](#25-what-you-do-not-need)), which is why the Python
build path exists.

The Python path in [section 6](#6-deploy) is the tested one; the wizard wraps it.
Prefer either over `wrangler`.
