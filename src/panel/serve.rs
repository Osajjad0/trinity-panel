//! HTTP handlers for the panel and the subscription endpoints.
//!
//! Deliberately thin. Every decision — which client, which shape, whether the
//! session is valid, what the node set is, which values a control may take — is
//! made by a pure function in [`super::api`], [`super::auth`], [`super::store`],
//! [`super::advisor`] or [`crate::subscription::bundle`], all of which are
//! tested on the host. What is left here is the I/O those decisions imply,
//! which is the part a unit test could not reach anyway.
//!
//! # Why a failure here still renders the decoy
//!
//! A subscription path that answers `404` for an unknown client and `200` for a
//! known one is an oracle: a scanner that has found the prefix can enumerate
//! what the deployment serves. So an unparseable request is not an error, it is
//! the same status page the root serves. The same applies to the panel prefix,
//! with one deliberate exception described in [`super::api`].

use serde::Serialize;
use worker::{Env, Headers, Request, Response, Result};

use super::api::{self, Api, Source};
use super::store::{Deployment, Settings};
use crate::subscription::bundle::{self, Shape};
use crate::subscription::qr::{Ecc, Qr};

/// KV binding holding the settings document.
const KV_BINDING: &str = "SETTINGS";

/// The panel page. Built into the binary rather than uploaded as a static
/// asset: asset upload is a separate API call that a deployment can skip, and a
/// panel that is missing because of a partial deploy is worse than a larger
/// module.
const PANEL_HTML: &str = include_str!("../../public/panel.html");

/// The Beta UI document. Served instead of [`PANEL_HTML`] when the operator's
/// `ui` cookie (or a `?ui=` query parameter) asks for it; every other property
/// of the panel — routes, session handling, API responses — is untouched.
const PANEL_BETA_HTML: &str = include_str!("../../public/panel-beta.html");

/// Which UI variant this request asked for. `?ui=beta` in the URL wins over
/// the `ui` cookie; the value must be exactly `beta` or `legacy` — anything
/// else counts as no preference, so a typo can never strand the operator on a
/// variant they did not choose.
fn ui_preference(req: &Request) -> Option<bool> {
    let from_query = req
        .url()
        .ok()
        .and_then(|u| u.query_pairs().find(|(k, _)| k == "ui").map(|(_, v)| v.into_owned()));
    match from_query.as_deref() {
        Some("beta") => return Some(true),
        Some("legacy") => return Some(false),
        _ => {}
    }
    let Ok(Some(cookies)) = req.headers().get("Cookie") else {
        return None;
    };
    cookies
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == "ui")
        .and_then(|(_, v)| match v.trim() {
            "beta" => Some(true),
            "legacy" => Some(false),
            _ => None,
        })
}

/// The variant a request with no `ui` cookie and no `ui` query parameter gets.
/// TEST deployments run Beta so the redesign is what an operator sees; flipping
/// this one constant restores the Legacy default.
const DEFAULT_UI_BETA: bool = true;

/// Read a binding, or the empty string.
fn var(env: &Env, name: &str) -> String {
    env.var(name).map(|v| v.to_string()).unwrap_or_default()
}

/// Seconds since the epoch, from the runtime's clock.
fn now_secs() -> u64 {
    worker::Date::now().as_millis() / 1000
}

/// Load settings, saying where they came from.
///
/// The derived fallback is not an error path — it is the normal state of a
/// deployment nobody has customised yet, and it is what makes the subscription
/// work immediately after deploying rather than after a visit to the panel.
async fn load(env: &Env, host: &str) -> (Settings, Source, Option<String>) {
    let stored = match env.kv(KV_BINDING) {
        Ok(kv) => kv.get(super::store::KEY).text().await.ok().flatten(),
        Err(_) => None,
    };

    let mut warning = None;
    if let Some(raw) = stored {
        match Settings::parse(&raw) {
            // An empty stored document still means "nothing configured", so
            // fall through to the derived set rather than serving zero nodes.
            Ok(settings) if !settings.nodes.is_empty() => {
                return (settings, Source::Stored, None);
            }
            Ok(_) => {}
            // A malformed or too-new document is not silently replaced: the
            // derived set is served so the deployment keeps working, and the
            // panel reports the problem when someone logs in.
            Err(e) => warning = Some(format!("Saved settings could not be read ({e}).")),
        }
    }

    let derived = Settings::derive_from_env(&Deployment {
        host,
        xhttp_path: &var(env, "XHTTP_PATH"),
    ws_path: &var(env, "WS_PATH"),
        vless_users: &var(env, "VLESS_USERS"),
        trojan_users: &var(env, "TROJAN_USERS"),
        vmess_users: &var(env, "VMESS_USERS"),
        shadowsocks_users: &var(env, "SS_USERS"),
    });
    (derived, Source::Derived, warning)
}

/// Load settings for a request that does not care where they came from.
pub async fn load_settings(env: &Env, host: &str) -> Settings {
    load(env, host).await.0
}

/// The hostname a request arrived on, which is the hostname a client must dial.
fn host_of(req: &Request) -> String {
    req.url()
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Serve a subscription request.
///
/// `rest` is the path after the subscription prefix.
///
/// # Errors
/// Only for response construction; every routing failure renders the decoy.
pub async fn subscription(req: &Request, env: &Env, rest: &str) -> Result<Response> {
    let Some((target, shape)) = bundle::parse_request(rest) else {
        return crate::entry::decoy(env).await;
    };

    let host = host_of(req);
    let settings = load_settings(env, &host).await;

    let Ok(rendered) = bundle::render(&settings.nodes, target, shape, settings.enhanced_reachability) else {
        // Nothing this client can use. Rendering the decoy keeps the endpoint
        // uninformative; the panel is where a user is told why.
        return crate::entry::decoy(env).await;
    };

    let mut out = Response::ok(rendered.body)?;
    let headers = out.headers_mut();
    headers.set("Content-Type", rendered.content_type)?;
    // Subscriptions are polled; a cached one hides an edit the user just made.
    headers.set("Cache-Control", "no-store")?;
    // What every subscription-aware client reads to name the profile.
    headers.set("Profile-Title", "Trinity Panel")?;
    set_download_name(headers, &rendered.filename, shape)?;
    Ok(out)
}

/// Offer a filename for the shapes a browser would otherwise render inline.
fn set_download_name(headers: &mut Headers, filename: &str, shape: Shape) -> Result<()> {
    if matches!(shape, Shape::FullConfig) {
        headers.set("Content-Disposition", &format!("attachment; filename=\"{filename}\""))?;
    }
    Ok(())
}

/// Serve a panel request.
///
/// # Errors
/// Only for response construction.
pub async fn panel(mut req: Request, env: &Env, rest: &str) -> Result<Response> {
    let action = api::route(req.method().as_ref(), rest);

    // A deployment with no password configured has no panel, rather than an
    // open one. This is checked before anything else so an unconfigured
    // deployment is indistinguishable from one with no panel prefix at all.
    let password = var(env, "PANEL_PASSWORD");
    if password.is_empty() || matches!(action, Api::Unknown) {
        return crate::entry::decoy(env).await;
    }

    if !action.is_public() && !has_session(&req, &password) {
        return refuse("Your session has expired. Sign in again.");
    }

    match action {
        Api::Page => {
            // The panel ships its own API client; a cached stale document
            // posts payloads the current backend may misread. Always fresh.
            let mut page = Response::from_html(if ui_preference(&req).unwrap_or(DEFAULT_UI_BETA) { PANEL_BETA_HTML } else { PANEL_HTML })?;
            page.headers_mut().set("Cache-Control", "no-store")?;
            Ok(page)
        }
        Api::Login => login(&mut req, &password).await,
        Api::Logout => logout(),
        Api::State => state(&req, env).await,
        Api::Save => save(&mut req, env).await,
        Api::Check => check(&mut req).await,
        Api::Export => export(&req, env).await,
        Api::Qr => qr(&req, env).await,
        Api::ProbeProxy => probe_proxy(env).await,
        Api::CatalogSync => catalog_sync(env).await,
        Api::PoolDialTest => pool_dial_test(&req, env).await,
        Api::CatalogMeta => {
            let meta = load_catalog_meta(env).await;
            json(&meta)
        }
        Api::Unknown => crate::entry::decoy(env).await,
    }
}

/// Whether the request carries a valid session cookie.
fn has_session(req: &Request, password: &str) -> bool {
    let Ok(Some(cookies)) = req.headers().get("Cookie") else {
        return false;
    };
    super::auth::token_from_cookies(&cookies)
        .is_some_and(|token| super::auth::verify(token, password, now_secs()).is_ok())
}

async fn login(req: &mut Request, password: &str) -> Result<Response> {
    let Ok(body) = req.json::<api::LoginRequest>().await else {
        return refuse("That request could not be read.");
    };
    if !super::auth::password_matches(&body.password, password) {
        // One message for a wrong password and for a malformed request. There
        // is nothing useful to tell a caller apart from "no".
        return refuse("That password is not right.");
    }

    let token = super::auth::issue(password, now_secs());
    let mut out = json(&Ok2 { ok: true })?;
    out.headers_mut().set("Set-Cookie", &super::auth::set_cookie(&token))?;
    Ok(out)
}

fn logout() -> Result<Response> {
    let mut out = json(&Ok2 { ok: true })?;
    out.headers_mut().set("Set-Cookie", &super::auth::clear_cookie())?;
    Ok(out)
}

async fn state(req: &Request, env: &Env) -> Result<Response> {
    let host = host_of(req);
    let (settings, source, warning) = load(env, &host).await;
    let sub_base = format!("https://{host}{}", var(env, "SUB_PATH"));
    let xhttp_path = var(env, "XHTTP_PATH");
    // One read serves both consumers: `load_health` fetched the SAME
    // panel:outbound_state document that `load_outbound_state` re-read below,
    // then kept only `.geo` (V24.6.10 B). Parse once, share the result.
    let outbound_state = load_outbound_state(env).await;
    let geo = outbound_state.geo.clone();
    let catalog = load_catalog_meta(env).await;
    let catalog_hosts = catalog_hosts_for_state(env, &settings.outbound).await;
    // V24.6 §3: the panel may pass its LOCAL location selection (?preview_country=XX).
    // The runtime preview then derives from the UI selection instead of the persisted
    // config, so the panel can never show "Location=US, source=DE". Read-only:
    // nothing here persists, and the relay keeps dialing from the SAVED config.
    let preview_country = query(req)
        .into_iter()
        .find(|(k, _)| k == "preview_country")
        .map(|(_, v)| v)
        .filter(|v| v.len() == 2 && v.chars().all(|c| c.is_ascii_alphabetic()))
        .map(|v| v.to_ascii_uppercase());
    let preview_cfg = preview_country.map(|cc| crate::relay::outbound::OutboundConfig {
        catalog_country: cc,
        ..settings.outbound.clone()
    });
    let runtime_candidates =
        runtime_candidates_for_state(env, preview_cfg.as_ref().unwrap_or(&settings.outbound)).await;
    let fallback = crate::relay::outbound_state::fallback_fresh(&outbound_state, now_secs() * 1000)
        .then(|| api::FallbackView {
            primary: settings.outbound.catalog_country.clone(),
            active: outbound_state.fallback_active.clone(),
        });
    json(&api::state(&settings, &host, &sub_base, &xhttp_path, source, warning, &geo, catalog, &catalog_hosts, &runtime_candidates, fallback))
}

/// The EXACT catalog candidates the dial path will use for the current
/// mode/location — the same pool_for + cap the sessions apply. Informational
/// only; the stored snapshot is recomputed on every panel load.
#[cfg(target_arch = "wasm32")]
async fn runtime_candidates_for_state(
    env: &Env,
    cfg: &crate::relay::outbound::OutboundConfig,
) -> Vec<String> {
    if !matches!(cfg.mode,
        crate::relay::outbound::ProxyMode::ProxyIp | crate::relay::outbound::ProxyMode::Pool)
    {
        return Vec::new();
    }
    // Explicit override wins.
    if !cfg.verified_catalog_candidates.is_empty() {
        return cfg.verified_catalog_candidates
            .iter()
            .take(crate::catalog::MAX_POOL_CANDIDATES)
            .cloned()
            .collect();
    }
    // Pool mode derives from the stored verified snapshot; Custom has no
    // snapshot-derived candidates.
    if cfg.mode != crate::relay::outbound::ProxyMode::Pool {
        return Vec::new();
    }
    let Ok(kv) = env.kv(KV_BINDING) else { return Vec::new() };
    let Ok(Some(raw)) = kv.get(crate::catalog::KV_KEY).text().await else {
        return Vec::new();
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Vec::new();
    };
    let Ok(snapshot) =
        serde_json::from_value::<crate::catalog::Snapshot>(document["snapshot"].clone())
    else {
        return Vec::new();
    };
    crate::catalog::pool_for(cfg, Some(&snapshot))
        .unwrap_or_default()
        .into_iter()
        .map(|e| format!("{}:{}", e.host, e.port))
        .collect()
}

/// The generated (healthy-only) catalog candidates for the panel view.
#[cfg(target_arch = "wasm32")]
async fn catalog_hosts_for_state(
    env: &Env,
    cfg: &crate::relay::outbound::OutboundConfig,
) -> Vec<String> {
    if !cfg.catalog_pool {
        return Vec::new();
    }
    cfg.verified_catalog_candidates.clone()
}


/// The stored catalog sync metadata, or `None` when never synced. Tiny read:
/// the 865 KB snapshot itself is deliberately not loaded for panel renders.
async fn load_catalog_meta(
    env: &Env,
) -> Option<crate::catalog::Meta> {
    let kv = env.kv(KV_BINDING).ok()?;
    let raw = kv.get(crate::catalog::KV_META_KEY).text().await.ok().flatten()?;
    crate::catalog::Meta::from_json(&raw)
}

/// The probe's health map, or empty when nothing has been measured yet.
///
/// A missing or malformed document degrades to "not measured" rather than
/// failing the panel: health is decoration on top of the settings, never a
/// precondition for editing them.
async fn load_health(
    env: &Env,
) -> std::collections::BTreeMap<String, crate::relay::outbound_state::Health> {
    use crate::relay::outbound_state::{self, OutboundState};

    let Ok(kv) = env.kv(KV_BINDING) else {
        return std::collections::BTreeMap::new();
    };
    match kv.get(outbound_state::KV_KEY).text().await {
        Ok(Some(raw)) => OutboundState::from_json(&raw).geo,
        _ => std::collections::BTreeMap::new(),
    }
}

async fn save(req: &mut Request, env: &Env) -> Result<Response> {
    let Ok(body) = req.json::<api::SaveRequest>().await else {
        return refuse("Those settings could not be read.");
    };
    if let Err(message) = api::validate(&body.nodes) {
        return refuse(&message);
    }
    if let Err(message) = api::validate_outbound(&body.outbound) {
        return refuse(&message);
    }

    // Optimistic concurrency: compare what the client loaded against what is
    // stored now. A mismatch means another tab or session saved first; their
    // edit wins and this one is refused with instructions rather than
    // silently overwriting it. Old clients send no expectation at all.
    let host = host_of(req);
    let (stored, _, _) = load(env, &host).await;
    let Ok(new_rev) = api::resolve_save_rev(body.expected_rev, stored.rev) else {
        return refuse(api::REV_CONFLICT_MESSAGE);
    };

    let settings = Settings { version: super::store::VERSION, nodes: body.nodes, outbound: body.outbound, enhanced_reachability: body.enhanced_reachability, rev: new_rev };
    let Ok(document) = settings.to_json() else {
        return refuse("Those settings could not be stored.");
    };
    let Ok(kv) = env.kv(KV_BINDING) else {
        return refuse("This deployment has no settings storage bound.");
    };
    match kv.put(super::store::KEY, document) {
        Ok(put) => {
            if put.execute().await.is_err() {
                return refuse("Saving failed. Nothing was changed.");
            }
        }
        Err(_) => return refuse("Saving failed. Nothing was changed."),
    }
    let sub_base = format!("https://{host}{}", var(env, "SUB_PATH"));
    let xhttp_path = var(env, "XHTTP_PATH");
    // Health comes back with the saved state too: the panel replaces its whole
    // working copy from this response, so omitting it would blank the candidate
    // list on every save until the next reload.
    let geo = load_health(env).await;
    let catalog = load_catalog_meta(env).await;
    let catalog_hosts = catalog_hosts_for_state(env, &settings.outbound).await;
    let runtime_candidates = runtime_candidates_for_state(env, &settings.outbound).await;
    let state = api::state(&settings, &host, &sub_base, &xhttp_path, Source::Stored, None, &geo, catalog, &catalog_hosts, &runtime_candidates, None);
    Ok(json(&SavedResponse { ok: true, state })?)
}

#[derive(Serialize)]
struct SavedResponse {
    ok: bool,
    #[serde(flatten)]
    state: api::State,
}

#[derive(Serialize)]
struct Ok2 {
    ok: bool,
}

async fn check(req: &mut Request) -> Result<Response> {
    let Ok(body) = req.json::<api::CheckRequest>().await else {
        return refuse("That connection could not be read.");
    };
    let Some(target) = bundle::client_from_name(&body.client) else {
        return refuse("That app is not one this panel knows.");
    };
    let mut node = body.node;
    if let Some(edit) = body.edit {
        super::advisor::apply(&mut node, &edit.field, &edit.value);
    }
    let advice = super::advisor::advise(&node, target, body.enhanced_reachability);
    json(&api::Checked { node, advice })
}
/// A rendered subscription, as JSON, so the panel can preview and copy it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    body: String,
    content_type: &'static str,
    filename: String,
    included: usize,
    skipped: Vec<bundle::Skipped>,
}

async fn export(req: &Request, env: &Env) -> Result<Response> {
    let pairs = query(req);
    let Some((target, shape)) =
        api::export_subject(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    else {
        return refuse("That export could not be read.");
    };

    let settings = load_settings(env, &host_of(req)).await;
    match bundle::render(&settings.nodes, target, shape, settings.enhanced_reachability) {
        Ok(b) => json(&Export {
            body: b.body,
            content_type: b.content_type,
            filename: b.filename,
            included: b.included,
            skipped: b.skipped,
        }),
        Err(e) => refuse(&format!("Nothing to export for this app: {e}")),
    }
}

async fn qr(req: &Request, env: &Env) -> Result<Response> {
    let pairs = query(req);
    let Some(subject) = api::qr_subject(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    else {
        return refuse("That QR code could not be read.");
    };

    let host = host_of(req);
    let text = match subject {
        api::QrSubject::Subscription(client) => {
            format!("https://{host}{}/{}", var(env, "SUB_PATH"), bundle::client_slug(client))
        }
        api::QrSubject::Node { tag, client } => {
            let settings = load_settings(env, &host).await;
            let Some(node) = settings.node(&tag) else {
                return refuse("That connection no longer exists.");
            };
            match crate::subscription::to_uri(node, client, settings.enhanced_reachability) {
                Ok(uri) => uri,
                Err(e) => return refuse(&format!("This app cannot import that connection: {e}")),
            }
        }
    };

    let Ok(code) = Qr::encode(text.as_bytes(), Ecc::Medium) else {
        return refuse("That is too long to put in a QR code.");
    };

    let mut out = Response::ok(code.to_svg(4))?;
    let headers = out.headers_mut();
    headers.set("Content-Type", "image/svg+xml; charset=utf-8")?;
    // A QR of a share link is a credential. It must not sit in a disk cache.
    headers.set("Cache-Control", "no-store")?;
    Ok(out)
}

/// Operator-initiated: TLS to each Proxy-IP candidate, GET `/cdn-cgi/trace`,
/// cache `loc=` on the LKG document. Never on the session path.
async fn probe_proxy(env: &Env) -> Result<Response> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = env;
        return refuse("Probe only runs on the Worker.");
    }
    #[cfg(target_arch = "wasm32")]
    {
        probe_proxy_live(env).await
    }
}

#[cfg(target_arch = "wasm32")]
async fn probe_proxy_live(env: &Env) -> Result<Response> {
    use crate::relay::outbound_state::{self, OutboundState};

    let settings = load_settings(env, "").await;
    // Manual candidates only. Catalog endpoints are verified by the GitHub
    // scanner; Trinity never probes them (V24.4.1).
    let mut candidates = settings.outbound.proxy_candidates.clone();
    if candidates.is_empty() {
        return refuse("No Proxy-IP candidates to measure.");
    }

    let kv = match env.kv(KV_BINDING) {
        Ok(kv) => kv,
        Err(_) => return refuse("Settings store is not bound."),
    };
    let mut state = match kv.get(outbound_state::KV_KEY).text().await.ok().flatten() {
        Some(raw) => OutboundState::from_json(&raw),
        None => OutboundState::default(),
    };

    let wanted = "";
    let now = worker::Date::now().as_millis();

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Row {
        host: String,
        port: u16,
        /// Address the socket actually connected to (runtime-reported). For
        /// an IP candidate this IS the candidate; for a hostname it is the
        /// runtime's resolution. Never a substitute candidate address.
        dial_ip: String,
        /// TCP connect RTT (None when the dial itself failed).
        tcp_ms: Option<u32>,
        /// TLS handshake + HTTP trace RTT after TCP (None when TCP failed).
        probe_ms: Option<u32>,
        ok: bool,
        country: String,
        colo: String,
        exit_ip: String,
        latency_ms: u32,
        healthy: bool,
        rotating: bool,
        success_rate: f64,
        score: f64,
        #[serde(skip_serializing_if = "String::is_empty")]
        error: String,
    }
    candidates.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    let mut results = Vec::new();
    for host in candidates {
        let port: u16 = 443;
        // Health key matches `candidate_key` (host:port) so dial-path demotion,
        // LKG and the panel all read and write the same record. Port-443
        // configured candidates keep their historical bare-host keys via the
        // same canonical form the dialer already uses.
        let key = crate::relay::outbound_state::candidate_key(&crate::protocol::Target {
            host: host.parse::<std::net::IpAddr>().map_or_else(
                |_| crate::protocol::Host::Domain(host.trim().to_owned().into_boxed_str()),
                crate::protocol::Host::Ip,
            ),
            port,
        });
        let prior = state.geo.get(&key).cloned().unwrap_or_default();
        // The probe returns, separately: the address the runtime actually
        // dialed, the TCP connect RTT, and the TLS+HTTP RTT. The health
        // record keeps the total (candidate_key format) as before.
        let (health, dial_ip, tcp_ms, probe_ms) = match probe_one(&host, port).await {
            Ok(trace) => (
                prior.observed_ok(trace.country, trace.colo, trace.exit_ip, trace.latency_ms, now),
                trace.dial_ip,
                Some(trace.tcp_ms),
                Some(trace.probe_ms),
            ),
            Err((e, dial_ip, tcp_ms)) => (
                prior.observed_fail(e, now),
                dial_ip,
                tcp_ms,
                None,
            ),
        };
        results.push(Row {
            host,
            port,
            dial_ip,
            tcp_ms,
            probe_ms,
            ok: health.ok,
            country: health.country.clone(),
            colo: health.colo.clone(),
            exit_ip: health.exit_ip.clone(),
            latency_ms: health.latency_ms,
            healthy: health.healthy(),
            rotating: health.rotating,
            success_rate: health.success_rate(),
            score: health.score(&wanted),
            error: health.error.clone(),
        });
        state.geo.insert(key, health);
    }
    // Best score first: the panel shows the same order the dial path will use.
    results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(core::cmp::Ordering::Equal));
    if let Ok(document) = serde_json::to_string(&state) {
        if let Ok(pending) = kv.put(outbound_state::KV_KEY, document) {
            let _ = pending.execute().await;
        }
    }
    json(&serde_json::json!({ "ok": true, "results": results }))
}

/// One candidate's measured identity, with the dial evidence kept separate
/// from the application result. `dial_ip` is the runtime-reported remote
/// address — the proof the probe dialed the candidate, not something else.
#[cfg(target_arch = "wasm32")]
struct Trace {
    country: String,
    colo: String,
    exit_ip: String,
    latency_ms: u32,
    dial_ip: String,
    /// TCP connect RTT only (socket opened).
    tcp_ms: u32,
    /// TLS handshake + HTTP trace round trip after TCP.
    probe_ms: u32,
}

/// A failed probe, with whatever dial evidence was gathered first.
#[cfg(target_arch = "wasm32")]
type ProbeError = (String, String, Option<u32>);

/// Measure one candidate: TLS to :443, `GET /cdn-cgi/trace`, read the exit
/// identity Cloudflare reports back through that egress.
///
/// Cloudflare-only by construction — the trace endpoint is served by the edge
/// the candidate egresses through, so no third-party geo API is involved.
/// Measured on this deployment: plain HTTP on :80 answers 404 with no trace
/// body, and outbound TCP to Cloudflare-owned ranges is refused outright, so
/// TLS to the candidate itself is the only technique that returns geo.
#[cfg(target_arch = "wasm32")]
async fn probe_one(host: &str, port: u16) -> core::result::Result<Trace, ProbeError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use worker::SecureTransport;

    let host = host.trim();
    if host.is_empty() {
        return Err(("empty host".into(), String::new(), None));
    }
    // DIAL ADDRESS = candidate address, DIAL PORT = candidate port. SNI and
    // the HTTP Host header are separate layers below; neither rewrites these.
    // DIAL: exactly the candidate address + port. SNI/Host are separate
    // layers below and are NOT rewritten into the dial address.
    let t0 = worker::Date::now().as_millis();
    let mut sock = worker::Socket::builder()
        .allow_half_open(true)
        .secure_transport(SecureTransport::On)
        .connect(host, port)
        // On dial failure the attempted target IS the evidence: candidate:port.
        .map_err(|e| (e.to_string(), format!("{host}:{port}"), None))?;
    let dial_ip = match sock.opened().await {
        // The runtime reports the resolved remote address (e.g. `IP:port` for
        // a hostname candidate). Empty for some dials: fall back to the
        // candidate address itself so the panel never shows another IP.
        Ok(info) => {
            let remote = info.remote_address.unwrap_or_default();
            if remote.is_empty() { host.to_owned() } else { remote }
        }
        Err(e) => return Err((format!("tcp connect: {e}"), format!("{host}:{port}"), None)),
    };
    let tcp_ms = u32::try_from(worker::Date::now().as_millis().saturating_sub(t0)).unwrap_or(u32::MAX);
    // SNI = the dial host (the runtime derives it from `connect`). Host header
    // = the dial host too: the trace endpoint on the candidate's edge expects
    // its own name. Both are the candidate's identity, never the Worker's.
    let t1 = worker::Date::now().as_millis();
    let req = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = sock.write_all(req.as_bytes()).await {
        return Err((format!("tls/write: {e}"), dial_ip, Some(tcp_ms)));
    }
    if let Err(e) = sock.flush().await {
        return Err((format!("tls/flush: {e}"), dial_ip, Some(tcp_ms)));
    }
    let mut buf = vec![0u8; 2048];
    let n = match sock.read(&mut buf).await {
        Ok(n) => n,
        Err(e) => return Err((format!("tls/read: {e}"), dial_ip, Some(tcp_ms))),
    };
    let probe_ms = u32::try_from(worker::Date::now().as_millis().saturating_sub(t1)).unwrap_or(u32::MAX);
    let _ = sock.close().await;
    let text = String::from_utf8_lossy(&buf[..n]);
    let field = |name: &str| -> String {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(name).map(str::to_owned))
            .unwrap_or_default()
    };
    let loc = field("loc=");
    if loc.len() != 2 || !loc.bytes().all(|b| b.is_ascii_alphabetic()) {
        // No usable country: report it as a failure so the record's success
        // rate reflects that this candidate cannot satisfy a preference.
        let reason = if loc.is_empty() { "no loc= in trace".to_owned() } else { format!("bad loc={loc}") };
        return Err((reason, dial_ip, Some(tcp_ms)));
    }
    Ok(Trace {
        country: loc.to_ascii_uppercase(),
        colo: field("colo="),
        // NOTE: `ip=` from /cdn-cgi/trace is the address the candidate's edge
        // saw as the CLIENT — i.e. this Worker's egress, not the candidate.
        // It is stored for diagnostics only; the panel must not read it as
        // "the candidate's exit IP".
        exit_ip: field("ip="),
        latency_ms: tcp_ms.saturating_add(probe_ms),
        dial_ip,
        tcp_ms,
        probe_ms,
    })
}

/// Operator-initiated: fetch + validate + persist the public catalog
/// snapshot. Never on the session path. Fail-closed: any failure leaves the
/// previous snapshot in KV untouched and reports the error.
#[cfg(target_arch = "wasm32")]
async fn catalog_sync(env: &Env) -> Result<Response> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = env;
        return refuse("Catalog sync only runs on the Worker.");
    }
    #[cfg(target_arch = "wasm32")]
    {
        let report = crate::catalog::sync(env).await;
        // Refresh the panel's tiny meta document so the next load shows the
        // new revision without re-reading the full snapshot. Only on an actual
        // content change: an unchanged feed leaves the stored catalog — and
        // therefore the meta derived from it — byte-identical (V24.6.10 A),
        // so rewriting both would be two KV writes for nothing.
        if report.ok && report.changed {
            refresh_catalog_meta(env).await;
        }
        json(&report)
    }
}


/// The session-written outbound state (LKG + V24.4.4 fallback), for the panel.
#[cfg(target_arch = "wasm32")]
async fn load_outbound_state(env: &Env) -> crate::relay::outbound_state::OutboundState {
    let Ok(kv) = env.kv(KV_BINDING) else {
        return Default::default();
    };
    match kv.get(crate::relay::outbound_state::KV_KEY).text().await {
        Ok(Some(raw)) => crate::relay::outbound_state::OutboundState::from_json(&raw),
        _ => Default::default(),
    }
}

/// The published verified feed, read straight from GitHub (test path only;
/// nothing here is persisted).
#[cfg(target_arch = "wasm32")]
async fn fetch_verified_feed() -> Result<crate::catalog::Snapshot, String> {
    use crate::catalog::Snapshot;
    let request = worker::Request::new(crate::catalog::FEED_URL, worker::Method::Get)
        .map_err(|e| e.to_string())?;
    let mut response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if response.status_code() >= 400 {
        return Err(format!("feed fetch returned {}", response.status_code()));
    }
    let raw = response.text().await.map_err(|e| e.to_string())?;
    let feed: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("feed parse: {e}"))?;
    serde_json::from_value::<Snapshot>(feed).map_err(|e| format!("feed schema: {e}"))
}

/// Runtime-faithful TCP probe for bare-IP candidates: TLS OFF, exactly how the
/// relay dials a Proxy-IP (the session protocol supplies SNI inside). Returns
/// the same Trace shape with probe/country fields empty.
#[cfg(target_arch = "wasm32")]
async fn probe_tcp_one(host: &str, port: u16) -> core::result::Result<Trace, ProbeError> {
    use worker::SecureTransport;
    let t0 = worker::Date::now().as_millis();
    let mut sock = worker::Socket::builder()
        .allow_half_open(true)
        .secure_transport(SecureTransport::Off)
        .connect(host, port)
        .map_err(|e| (e.to_string(), format!("{host}:{port}"), None))?;
    let dial_ip = match sock.opened().await {
        Ok(info) => {
            let remote = info.remote_address.unwrap_or_default();
            if remote.is_empty() { host.to_owned() } else { remote }
        }
        Err(e) => return Err((format!("tcp connect: {e}"), format!("{host}:{port}"), None)),
    };
    let tcp_ms =
        u32::try_from(worker::Date::now().as_millis().saturating_sub(t0)).unwrap_or(u32::MAX);
    let _ = sock.close().await;
    Ok(Trace {
        country: String::new(),
        colo: String::new(),
        exit_ip: String::new(),
        latency_ms: tcp_ms,
        dial_ip,
        tcp_ms,
        probe_ms: 0,
    })
}

/// The verified snapshot in KV, if present and parseable.
#[cfg(target_arch = "wasm32")]
async fn load_catalog_snapshot(env: &Env) -> Option<crate::catalog::Snapshot> {
    let kv = env.kv(KV_BINDING).ok()?;
    let raw = kv.get(crate::catalog::KV_KEY).text().await.ok().flatten()?;
    let document: serde_json::Value = serde_json::from_str(&raw).ok()?;
    serde_json::from_value::<crate::catalog::Snapshot>(document["snapshot"].clone()).ok()
}

/// Rebuild `panel:catalog_meta` from the snapshot just stored. A failure here
/// is non-fatal: the panel degrades to the previous meta view.
#[cfg(target_arch = "wasm32")]
async fn refresh_catalog_meta(env: &Env) {
    let Ok(kv) = env.kv(KV_BINDING) else { return };
    let Some(document) = kv.get(crate::catalog::KV_KEY).text().await.ok().flatten() else {
        return;
    };
    let parsed: Option<serde_json::Value> = serde_json::from_str(&document).ok();
    let Some(document) = parsed else { return };
    let fetched_at = document.get("fetchedAt").and_then(|v| v.as_str()).unwrap_or_default();
    let Ok(snapshot) =
        serde_json::from_value::<crate::catalog::Snapshot>(document["snapshot"].clone())
    else {
        return;
    };
    let meta = crate::catalog::Meta::from_snapshot(&snapshot, fetched_at);
    if let Ok(document) = serde_json::to_string(&meta) {
        if let Ok(pending) = kv.put(crate::catalog::KV_META_KEY, document) {
            let _ = pending.execute().await;
        }
    }
}

/// Decoded query pairs, owned so the borrow of the URL ends here.
fn query(req: &Request) -> Vec<(String, String)> {
    req.url().map_or_else(
        |_| Vec::new(),
        |url| {
            url.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        },
    )
}


#[derive(Serialize)]
struct Refusal<'a> {
    ok: bool,
    error: &'a str,
}

/// A refusal the panel's own script can render.
///
/// Status 401 for every refusal, including a malformed body: the script's only
/// reaction is to show the message and, if there is no session, the login form.
/// Distinguishing them would add an oracle for no benefit to the operator.
fn refuse(message: &str) -> Result<Response> {
    let out = json(&Refusal { ok: false, error: message })?;
    Ok(out.with_status(401))
}

fn json<T: Serialize>(value: &T) -> Result<Response> {
    let body = serde_json::to_string(value).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let mut out = Response::ok(body)?;
    let headers = out.headers_mut();
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    // Everything here is either a credential or a view of one.
    headers.set("Cache-Control", "no-store")?;
    Ok(out)
}

/// V24.4.3.4: dial-test the VERIFIED pool for a requested location without
/// persisting anything. Uses the same `probe_one` the runtime handshake check
/// uses; reads the verified snapshot; honors Pool-mode selection semantics
/// (location-only override of the saved config). KV-quota-independent.
#[cfg(target_arch = "wasm32")]
async fn pool_dial_test(req: &Request, env: &Env) -> Result<Response> {
    let location = query(req)
        .into_iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v)
        .unwrap_or_default();
    if location.len() != 2 || !location.chars().all(|c| c.is_ascii_alphabetic()) {
        return refuse("Provide ?location=CC (ISO-2, e.g. US).");
    }

    let source = query(req)
        .into_iter()
        .find(|(k, _)| k == "source")
        .map(|(_, v)| v)
        .unwrap_or_default();
    // `source=feed` reads the published verified feed directly (read-only,
    // never persisted) so a stale/unsyncable KV snapshot can be validated
    // against what the next Sync would install. Default stays the snapshot.
    let fetched = if source == "feed" {
        Some(fetch_verified_feed().await)
    } else {
        None
    };
    let (snapshot, settings) =
        futures_util::future::join(load_catalog_snapshot(env), load_settings(env, "")).await;
    let snapshot = match fetched {
        Some(Ok(fresh)) => Some(fresh),
        Some(Err(reason)) => return refuse(&format!("Feed fetch failed: {reason}")),
        None => snapshot,
    };
    let Some(snapshot) = snapshot else {
        return refuse("No verified catalog snapshot. Sync first.");
    };

    // Same shape the runtime derives in Pool mode; only the location differs
    // for this one request. Nothing is persisted.
    let mut cfg = settings.outbound.clone();
    cfg.mode = crate::relay::outbound::ProxyMode::Pool;
    cfg.catalog_pool = true;
    cfg.catalog_country = location.to_ascii_uppercase();
    let Some(pool) = crate::catalog::pool_for(&cfg, Some(&snapshot)) else {
        return refuse(&format!(
            "No verified Proxy-IP candidates available for {location}."
        ));
    };

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Row {
        candidate: String,
        dial_ip: String,
        tcp_ms: Option<u32>,
        probe_ms: Option<u32>,
        observed_country: String,
        colo: String,
        exit_ip: String,
        ok: bool,
        #[serde(skip_serializing_if = "String::is_empty")]
        error: String,
    }
    let mut rows = Vec::new();
    for endpoint in &pool {
        let candidate = format!("{}:{}", endpoint.host, endpoint.port);
        // Bare-IP candidates are dialed by the runtime with TLS OFF (the proxy
        // protocol carries the real SNI inside), so a TLS-on probe with SNI=IP
        // misreports them as dead. Probe IPs the way the runtime dials them.
        let is_ip = endpoint.host.parse::<std::net::IpAddr>().is_ok();
        if is_ip {
            match probe_tcp_one(&endpoint.host, endpoint.port).await {
                Ok(t) => rows.push(Row {
                    candidate,
                    dial_ip: t.dial_ip,
                    tcp_ms: Some(t.tcp_ms),
                    probe_ms: None,
                    observed_country: String::new(),
                    colo: String::new(),
                    exit_ip: String::new(),
                    ok: true,
                    error: String::new(),
                }),
                Err((reason, attempted, tcp_ms)) => rows.push(Row {
                    candidate: if attempted.is_empty() { candidate } else { attempted },
                    dial_ip: String::new(),
                    tcp_ms,
                    probe_ms: None,
                    observed_country: String::new(),
                    colo: String::new(),
                    exit_ip: String::new(),
                    ok: false,
                    error: reason,
                }),
            }
            continue;
        }
        match probe_one(&endpoint.host, endpoint.port).await {
            Ok(t) => rows.push(Row {
                candidate,
                dial_ip: t.dial_ip,
                tcp_ms: Some(t.tcp_ms),
                probe_ms: Some(t.probe_ms),
                observed_country: t.country,
                colo: t.colo,
                exit_ip: t.exit_ip,
                ok: true,
                error: String::new(),
            }),
            Err((reason, attempted, tcp_ms)) => rows.push(Row {
                candidate: if attempted.is_empty() { candidate } else { attempted },
                dial_ip: String::new(),
                tcp_ms,
                probe_ms: None,
                observed_country: String::new(),
                colo: String::new(),
                exit_ip: String::new(),
                ok: false,
                error: reason,
            }),
        }
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Report {
        location: String,
        verified_pool: usize,
        runtime_selected: usize,
        persisted: bool,
        rows: Vec<Row>,
    }
    let verified = snapshot
        .countries
        .get(&cfg.catalog_country)
        .map_or(0, Vec::len);
    json(&Report {
        location: cfg.catalog_country.clone(),
        verified_pool: verified,
        runtime_selected: pool.len(),
        persisted: false,
        rows,
    })
}
