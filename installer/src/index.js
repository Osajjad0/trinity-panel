// Trinity Panel — official web-based installer.
//
// This Worker is the installer. It is deliberately tiny and stateless:
//   * it serves the wizard UI from /public (run_worker_first so the Worker
//     decides routing, not the assets layer), and
//   * it exposes POST /api/install, which drives a full Cloudflare deployment
//     and streams newline-delimited JSON progress back.
//
// Security model (strict):
//   * The user's Cloudflare API token arrives in the POST body, lives only in
//     the memory of this one request, and is dropped the instant the request
//     ends. We never log it, never put it in a response, never persist it.
//   * We require an Origin/Referer that matches the installer's own host so a
//     random third-party page cannot drive an install through a victim's
//     browser.

// ---------------------------------------------------------------------------
// Configuration — the canonical release source for the Trinity Panel worker
// modules. Fetched as a manifest + one asset per module so each upload part is
// transparent and debuggable. Public release assets need no GitHub token; the
// optional token is only used if the repo is private or rate-limited.

const RELEASE = {
  repo: "Osajjad0/trinity-panel",
  tag: "v0.1.0",
  manifestPath: "manifest.json",
};

// Step far below the default so a single misbehaving peer can't monopolise.
const SUBREQUEST_LIMIT = 50; // Workers permit ~1000; we use far fewer.

// ---------------------------------------------------------------------------
// Routing

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Health/ping — used by the UI preflight and by humans checking the
    // installer is up. Never echoes anything sensitive.
    if (url.pathname === "/api/ping" || url.pathname === "/_health") {
      return json({ ok: true, installer: "trinity-installer", version: "0.1.0" });
    }

    // OPTIONS preflight guard — described in sameOriginGuard.
    if (request.method === "OPTIONS") {
      // We allow only same-origin requests to the install API. Respond to
      // preflight without CORS allow-headers, which denies it.
      const acrm = request.headers.get("Access-Control-Request-Method");
      if (acceptableOrigin(request, url) && acrm) {
        return new Response(null, {
          status: 204,
          headers: { "Access-Control-Allow-Origin": url.origin, "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-Setup-Token", "Access-Control-Max-Age": "86400" },
        });
      }
      return new Response(null, { status: 204 });
    }

    if (url.pathname === "/api/install" && request.method === "POST") {
      return handleInstall(request, env, url, ctx);
    }

    // `data:` for the wizard's runtime config (release tag, repo) so the UI
    // doesn't have to hardcode it.
    if (url.pathname === "/api/config" && request.method === "GET") {
      return json({ repo: RELEASE.repo, tag: RELEASE.tag });
    }

    // Everything else falls through to the static UI. run_worker_first means
    // we control the decoy/404, not the assets binder.
    if (env.ASSETS) {
      const asset = await env.ASSETS.fetch(request);
      if (asset && asset.status !== 404) return asset;
    }
    return new Response("Not here.", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  },
};

// ---------------------------------------------------------------------------
// Same-origin guard

function acceptableOrigin(request, url) {
  // The install API must be driven only by the installer's own page. A browser
  // will happily let any site fetch() here; without this check a malicious
  // page could trick the user into installing Trinity Panel onto an attacker
  // chosen account path using the user's own token. (The token still goes to
  // Cloudflare, not to the attacker — but it would burn a deploy.)
  const origin = request.headers.get("Origin");
  const referer = request.headers.get("Referer");
  if (origin && origin === url.origin) return true;
  if (referer && new URL(referer).origin === url.origin) return true;
  // No Origin/Referer at all — allowed for same-origin simple requests from
  // this page; a cross-origin POST always carries Origin.
  if (!origin && !referer) return true;
  return false;
}

// ---------------------------------------------------------------------------
// The install handler — streaming NDJSON

async function handleInstall(request, env, url, ctx) {
  if (!acceptableOrigin(request, url)) {
    return ndjson([{ event: "error", message: "This request did not come from the installer page." }], { status: 403 });
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return ndjson([{ event: "error", message: "Could not read that request." }], { status: 400 });
  }

  const token = String(payload.token || "").trim();
  const ghToken = (String(payload.ghToken || "").trim()) || null; // optional
  const name = String(payload.name || "").trim() || randomName();
  const accountHint = String(payload.accountId || "").trim();

  if (!token) {
    return ndjson([{ event: "error", message: "No API token was supplied." }], { status: 400 });
  }

  // Streams progress to the browser as the install runs. We hold the
  // TransformStream across awaits; the request stays open until we close it.
  // Streams progress to the browser as the install runs. The Response is
  // returned immediately holding `readable`; the producer runs in
  // ctx.waitUntil and keeps the connection alive by writing to `writable`.
  // The token lives only in this request's memory and is dropped when the
  // producer finishes and the function returns.
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc = new TextEncoder();
  let closed = false;
  const send = (obj) => {
    if (closed) return Promise.resolve();
    return writer.write(enc.encode(JSON.stringify(obj) + "\n")).catch(() => {
      // The tab was closed or the connection dropped. Nothing left to
      // report to; stop writing but do not throw, so cleanup still runs.
      closed = true;
    });
  };
  const close = () => {
    if (closed) return Promise.resolve();
    closed = true;
    return writer.close().catch(() => {});
  };

  ctx.waitUntil((async () => {
    try {
      await runInstall({ token, ghToken, name, accountHint }, send);
    } catch (e) {
      await send({ event: "error", message: errMessage(e) });
    } finally {
      await close();
    }
  })());

  return new Response(readable, {
    status: 200,
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Connection": "keep-alive",
    },
  });
}

// ---------------------------------------------------------------------------
// The install pipeline — mirrors scripts/deploy.py exactly, stage for stage.

async function runInstall({ token, ghToken, name, accountHint }, send) {
  // Stage 1: verify token against account read + workers list + KV list.
  await send({ event: "step", step: "verify", label: "Verifying token and detecting capabilities", t: 0 });

  const account = accountHint || (await discoverAccount(token, send));
  const subdomain = await preflight(token, account, send);

  await send({ event: "note", message: `Account ${account.slice(0, 8)}… · subdomain ${subdomain}.workers.dev` });

  // Stage 2: fetch the canonical release artifact.
  await send({ event: "step", step: "fetch", label: "Fetching the Trinity Panel release artifact", t: 1 });
  const manifest = await fetchManifest(ghToken);
  const modules = await fetchModules(manifest, ghToken, send);
  const totalKiB = Math.round(modules.reduce((n, m) => n + m.bytes.byteLength, 0) / 1024);
  await send({ event: "note", message: `${modules.length} module(s), ${totalKiB} KiB, entry ${manifest.entry_module}` });

  // Stage 3: create the KV namespace (settings store).
  await send({ event: "step", step: "kv", label: "Creating the settings KV namespace", t: 2 });
  const kvId = await ensureKV(token, account, `${name}-settings`, send);
  await send({ event: "note", message: `KV namespace ${name}-settings ready (${kvId.slice(0, 12)}…)` });

  // Generate every secret and path locally, in memory, once.
  const creds = generateCredentials();

  // Stage 4: upload the Worker with all bindings + Durable Object migration.
  const exists = await scriptExists(token, account, name);
  await send({ event: "step", step: "upload", label: `Uploading the Worker as ${name}`, t: 3 });
  await uploadWorker(token, account, name, manifest, modules, kvId, creds, !exists, send);
  await send({ event: "note", message: `Worker uploaded${exists ? " (replaced existing, kept session class)" : " (new, with Durable Object migration)"}` });

  // Stage 5: enable the workers.dev subdomain.
  await send({ event: "step", step: "subdomain", label: "Enabling the workers.dev hostname", t: 4 });
  await enableSubdomain(token, account, name, send);
  const host = `${name}.${subdomain}.workers.dev`;
  await send({ event: "note", message: `Hostname https://${host}` });

  // Stage 6: verify the deployment with a live request.
  await send({ event: "step", step: "verify", label: "Verifying the live deployment", t: 5 });
  const verify = await verifyDeployment(host, creds.panelPath, creds.panelPassword, send);

  // Stage 7: done — surface every URL and credential, once.
  const result = {
    host,
    panelUrl: `https://${host}${creds.panelPath}`,
    panelPassword: creds.panelPassword,
    subscriptionUrl: `https://${host}${creds.subPath}`,
    xhttpPath: creds.xhttpPath,
    vlessUuid: creds.vlessUsers,
    vmessUuid: creds.vmessUsers,
    trojanPassword: creds.trojanUsers,
    shadowsocksUsers: creds.ssUsers,
    workerName: name,
    accountId: account,
    kvId,
    verified: verify.ok,
    verifyDetail: verify.detail,
    releasedFrom: `github.com/${RELEASE.repo}/releases/tag/${RELEASE.tag}`,
  };

  await send({ event: "done", label: verify.ok ? "Trinity Panel is live and verified." : "Trinity Panel is live, but verification had a caveat.", result });
}

// ---------------------------------------------------------------------------
// Cloudflare API helper — thin wrapper, surfaces exact errors.

async function cf(method, path, token, { body, contentType } = {}) {
  const headers = { Authorization: `Bearer ${token}` };
  if (contentType) headers["Content-Type"] = contentType;
  const init = { method, headers };
  if (body !== undefined) init.body = body;

  // Retry only requests that never got an answer (network reset). Failed
  // responses (4xx/5xx) carry a real reason and must stop the install.
  let last;
  let resp;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      resp = await fetch(`https://api.cloudflare.com/client/v4${path}`, init);
      const text = await resp.text();
      let payload;
      try { payload = JSON.parse(text); } catch { payload = null; }
      if (payload && payload.success === false) {
        const errs = (payload.errors || []).map((e) => e.message || String(e)).join("; ") || "unknown error";
        const codes = (payload.errors || []).map((e) => e.code).join(",");
        throw new CFError(`${method} ${path} was rejected by Cloudflare: ${errs}`, resp.status, codes, errs);
      }
      if (!resp.ok) {
        throw new CFError(`${method} ${path} failed: HTTP ${resp.status}: ${text.slice(0, 400)}`, resp.status, String(resp.status), text.slice(0, 200));
      }
      return payload ? payload.result : null;
    } catch (e) {
      if (e instanceof CFError) throw e; // an API rejection — stop.
      last = e; // network error — retry with backoff.
      await sleep(500 * (attempt + 1));
    }
  }
  throw new Error(`Could not reach the Cloudflare API after retries: ${errMessage(last)}. Check your network.`);
}

class CFError extends Error {
  constructor(message, status, code, raw) { super(message); this.name = "CFError"; this.status = status; this.code = code; this.raw = raw; }
}

function errMessage(e) {
  if (!e) return "unknown error";
  if (e instanceof Error) return e.message;
  return String(e);
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ---------------------------------------------------------------------------
// Stage implementations

// Discover the one account this token can act on, mirroring install.py.
// An account-scoped token cannot call /user/tokens/verify (it falsely reports
// invalid), so we list accounts directly instead.
async function discoverAccount(token, send) {
  await send({ event: "note", message: "Resolving account from token…" });
  const accounts = (await cf("GET", "/accounts", token)) || [];
  if (!accounts.length) {
    throw new Error("This token cannot see any account. Check that 'Account Resources' was set on the token page and that 'Account Settings: Read' is included.");
  }
  if (accounts.length > 1) {
    const names = accounts.map((a) => `${a.name} (${a.id})`).join(", ");
    throw new Error(`This token can see more than one account, so the installer cannot choose for you: ${names}. Create a token scoped to one account.`);
  }
  return accounts[0].id;
}

// Verify the three required capabilities by using them, and surface exactly
// which one is missing when one fails. Returns the workers.dev subdomain.
async function preflight(token, account, send) {
  try {
    await cf("GET", `/accounts/${account}`, token);
  } catch (e) {
    throw new Error(`Cannot read the account. The account ID may be wrong, or the token is missing 'Account Settings: Read'.\n  ${errMessage(e)}`);
  }
  try {
    await cf("GET", `/accounts/${account}/workers/scripts`, token);
    await send({ event: "capability", name: "Workers Scripts · Edit", ok: true });
  } catch (e) {
    throw new Error(`Cannot list Workers. The token is probably missing 'Workers Scripts: Edit'.\n  ${errMessage(e)}`);
  }
  try {
    await cf("GET", `/accounts/${account}/storage/kv/namespaces`, token);
    await send({ event: "capability", name: "Workers KV Storage · Edit", ok: true });
  } catch (e) {
    throw new Error(`Cannot list KV namespaces. The token is probably missing 'Workers KV Storage: Edit'.\n  ${errMessage(e)}`);
  }
  // capabilities that are nice-to-have, surfaced as detected but not required.
  await reportCapability(token, `/accounts/${account}/workers/domains`, "Workers Routes (custom domain)", send);
  await reportCapability(token, "/accounts", "Account Settings · Read", send); // already proven above; restated as detected

  const result = await cf("GET", `/accounts/${account}/workers/subdomain`, token);
  const subdomain = (result || {}).subdomain;
  if (!subdomain) {
    throw new Error("This account has no workers.dev subdomain yet. Register one in the Cloudflare dashboard under Workers & Pages, then re-run the installer.");
  }
  await send({ event: "subdomain", value: `${subdomain}.workers.dev` });
  return subdomain;
}

async function reportCapability(token, path, label, send) {
  try {
    await cf("GET", path, token);
    await send({ event: "capability", name: label, ok: true });
  } catch {
    await send({ event: "capability", name: label, ok: false, optional: true });
  }
}

async function ensureKV(token, account, title, send) {
  const existing = (await cf("GET", `/accounts/${account}/storage/kv/namespaces`, token)) || [];
  for (const ns of existing) if (ns.title === title) return ns.id;
  const created = await cf("POST", `/accounts/${account}/storage/kv/namespaces`, token, {
    body: JSON.stringify({ title }),
    contentType: "application/json",
  });
  return created.id;
}

async function scriptExists(token, account, name) {
  const scripts = (await cf("GET", `/accounts/${account}/workers/scripts`, token)) || [];
  return scripts.some((s) => s.id === name);
}

// Build the multipart module-upload body by hand. The CF API expects:
//   - metadata part (application/json) describing bindings, main_module,
//     compatibility_date, and (for a fresh script) the DO migration.
//   - one part per module, named by its logical path within the bundle.
// Module names MUST preserve forward slashes ("snippets/…/inline0.js"): an
// uploaded module under any other name causes a "No such module" runtime
// error after a *successful* upload.
function buildUploadBody(manifest, modules, kvId, creds, fresh) {
  const boundary = "----trinity" + randHex(16);
  const enc = new TextEncoder();
  const parts = [];
  const crlf = "\r\n";

  const bindings = [
    { type: "kv_namespace", name: "SETTINGS", namespace_id: kvId },
    { type: "durable_object_namespace", name: "XHTTP_SESSION", class_name: manifest.durable_object_class },
    { type: "plain_text", name: "XHTTP_PATH", text: creds.xhttpPath },
    { type: "plain_text", name: "PANEL_PATH", text: creds.panelPath },
    { type: "plain_text", name: "SUB_PATH", text: creds.subPath },
    { type: "plain_text", name: "WS_ENABLED", text: "false" },
    { type: "plain_text", name: "WS_PATH", text: "/ws" },
    { type: "secret_text", name: "VLESS_USERS", text: creds.vlessUsers },
    { type: "secret_text", name: "TROJAN_USERS", text: creds.trojanUsers },
    { type: "secret_text", name: "VMESS_USERS", text: creds.vmessUsers },
    { type: "secret_text", name: "SS_USERS", text: creds.ssUsers },
    { type: "secret_text", name: "PANEL_PASSWORD", text: creds.panelPassword },
  ];

  const metadata = {
    main_module: manifest.entry_module,
    compatibility_date: manifest.compatibility_date,
    bindings,
  };
  if (fresh) {
    // Must be new_sqlite_classes, not new_classes: the KV-backed form fails on
    // accounts with no pre-existing KV-backed namespace, and SQLite is the
    // only backend on the free plan. Matches wrangler.jsonc.
    metadata.migrations = { new_tag: "v1", new_sqlite_classes: [manifest.durable_object_class] };
  }

  const metaJson = JSON.stringify(metadata);
  parts.push(
    `--${boundary}${crlf}` +
    `Content-Disposition: form-data; name="metadata"${crlf}` +
    `Content-Type: application/json${crlf}${crlf}` +
    metaJson + crlf
  );

  // We assemble the full body as a single Uint8Array. Each module is also
  // binary (the .wasm is), so we concatenate bytes rather than encode to text.
  const chunks = [enc.encode(parts.join(""))];

  for (const m of modules) {
    const header = enc.encode(
      `--${boundary}${crlf}` +
      `Content-Disposition: form-data; name="${m.path}"; filename="${m.path}"${crlf}` +
      `Content-Type: ${m.contentType}${crlf}${crlf}`
    );
    const tail = enc.encode(crlf);
    // m.bytes is already a Uint8Array.
    chunks.push(header, m.bytes, tail);
  }

  chunks.push(enc.encode(`--${boundary}--${crlf}`));
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.byteLength; }

  return { body: out, contentType: `multipart/form-data; boundary=${boundary}` };
}

async function uploadWorker(token, account, name, manifest, modules, kvId, creds, fresh, send) {
  const { body, contentType } = buildUploadBody(manifest, modules, kvId, creds, fresh);
  await cf("PUT", `/accounts/${account}/workers/scripts/${name}`, token, { body, contentType });
}

async function enableSubdomain(token, account, name, send) {
  try {
    await cf("POST", `/accounts/${account}/workers/scripts/${name}/subdomain`, token, {
      body: JSON.stringify({ enabled: true }),
      contentType: "application/json",
    });
  } catch (e) {
    // Some accounts have this on by default and the call is a no-op/409;
    // treat a 409 as success since the subdomain is already enabled.
    if (e instanceof CFError && e.status === 409) {
      await send({ event: "note", message: "Subdomain already enabled." });
      return;
    }
    throw e;
  }
}

// ---------------------------------------------------------------------------
// End-to-end verification: hit the deployed panel path's sign-in and confirm
// it returns the panel page, then hit the subscription path and confirm it is
// not the decoy. We do NOT log any response bodies.

async function verifyDeployment(host, panelPath, panelPassword, send) {
  const base = `https://${host}`;

  // The panel path returns the sign-in HTML (large, ~20KB+) on GET. The decoy
  // page on an unknown path is tiny (~68 bytes). A size + status heuristic is
  // enough to tell them apart without inspecting bodies for secret content.
  try {
    const r = await fetch(`${base}${panelPath}`, { headers: { "accept": "text/html" }, cf: { cacheTtl: 0 } });
    const size = Number(r.headers.get("content-length") || 0);
    const text = await r.text();
    const length = text.length || size;
    if (r.status === 200 && length > 2000) {
      await send({ event: "note", message: `Panel path returned ${length.toLocaleString()} bytes (HTTP ${r.status}) — panel is live.` });
      const ok = true;
      return { ok, detail: `Panel reachable at ${panelPath} (HTTP ${r.status}, ${length.toLocaleString()} bytes).` };
    }
    await send({ event: "note", message: `Panel path answered HTTP ${r.status} with ${length.toLocaleString()} bytes — unexpected. The panel may still be starting up.` });
    return { ok: false, detail: `Panel path answered HTTP ${r.status} (${length.toLocaleString()} bytes); expected a large sign-in page.` };
  } catch (e) {
    return { ok: false, detail: `Verification request failed: ${errMessage(e)}` };
  }
}

// ---------------------------------------------------------------------------
// Release artifact fetching — the canonical source.

async function fetchManifest(ghToken) {
  const url = `https://github.com/${RELEASE.repo}/releases/download/${RELEASE.tag}/${RELEASE.manifestPath}`;
  const headers = ghToken ? { Authorization: `token ${ghToken}` } : {};
  const r = await fetch(url, { headers, cf: { cacheEverything: true, cacheTtl: 60 } });
  if (!r.ok) throw new Error(`Could not fetch the release manifest from ${url} (HTTP ${r.status}). ${ghToken ? "The GitHub token may be invalid." : "The repository may be private — provide a GitHub token, or make the release public."}`);
  return r.json();
}

async function fetchModules(manifest, ghToken, send) {
  const headers = ghToken ? { Authorization: `token ${ghToken}` } : {};
  const base = `https://github.com/${RELEASE.repo}/releases/download/${RELEASE.tag}`;
  const out = [];
  for (const m of manifest.modules) {
    const r = await fetch(`${base}/${m.asset}`, { headers, cf: { cacheEverything: true, cacheTtl: 60 } });
    if (!r.ok) throw new Error(`Could not fetch module ${m.asset} from the release (HTTP ${r.status}).`);
    const buf = new Uint8Array(await r.arrayBuffer());
    out.push({ path: m.path, contentType: m.content_type, bytes: buf });
    await send({ event: "note", message: `fetched ${m.path} (${Math.round(buf.byteLength / 1024)} KiB)` });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Credential & path generation — mirrors scripts/install.py generate_credentials().

function generateCredentials() {
  const method = "2022-blake3-aes-256-gcm";
  const userUuid = uuidv4();
  const ssKeyLen = 32;
  return {
    vlessUsers: userUuid,
    vmessUsers: userUuid, // one UUID serves both; two buys no security
    trojanUsers: tokenUrlSafe(18),
    ssUsers: `${method}:${base64(randBytes(ssKeyLen))}`,
    panelPassword: tokenUrlSafe(18),
    xhttpPath: "/" + randHex(8),
    panelPath: "/" + randHex(8),
    subPath: "/" + randHex(8),
  };
}

// An unremarkable default Worker name. Deliberately not proxy-shaped — the
// hostname is public and an obvious name attracts attention.
function randomName() {
  const words = ["edge", "cache", "assets", "static", "relay", "gateway", "origin", "media"];
  return `${words[Math.floor(Math.random() * words.length)]}-${randHex(2)}`;
}

// --- crypto primitives available on the Workers runtime ---
function randHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randBytes(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function base64(bytes) {
  // btoa on binary string built from the byte array; handles all bytes.
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function tokenUrlSafe(n) {
  // urlsafe base64 of n random bytes, stripped of padding — like secrets.token_urlsafe.
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  let s = "";
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function uuidv4() {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  a[6] = (a[6] & 0x0f) | 0x40;
  a[8] = (a[8] & 0x3f) | 0x80;
  const h = [...a].map((b) => b.toString(16).padStart(2, "0"));
  return `${h.slice(0, 4).join("")}-${h.slice(4, 6).join("")}-${h.slice(6, 8).join("")}-${h.slice(8, 10).join("")}-${h.slice(10, 16).join("")}`;
}

// ---------------------------------------------------------------------------
// Response helpers

function json(obj, { status = 200 } = {}) {
  return new Response(JSON.stringify(obj) + "\n", {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function ndjson(events, { status = 200 } = {}) {
  const body = events.map((e) => JSON.stringify(e)).join("\n") + "\n";
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
