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
    let from_query = req.url().ok().and_then(|u| {
        u.query_pairs()
            .find(|(k, _)| k == "ui")
            .map(|(_, v)| v.into_owned())
    });
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
    // The DO store mirrors `panel:settings` whenever a KV write was refused
    // (daily quota). Either side can be the fresher one — KV after the quota
    // reset, the DO right after a fallback save — so the document with the
    // higher revision wins. Comparing revisions is what prevents a stale KV
    // copy from silently reverting a saved country change.
    let do_stored = super::settings_do::read(env, super::store::KEY).await;
    let parsed = |raw: &Option<String>| -> Option<Settings> {
        raw.as_deref()
            .and_then(|r| Settings::parse(r).ok())
            .filter(|s| !s.nodes.is_empty())
    };
    let (kv_parsed, do_parsed) = (parsed(&stored), parsed(&do_stored));
    let (raw, warning) = match (&kv_parsed, &do_parsed) {
        (Some(a), Some(b)) if b.rev > a.rev => (do_stored.clone(), None),
        (Some(_), Some(_)) | (Some(_), None) => (stored.clone(), None),
        (None, Some(_)) => (do_stored.clone(), None),
        // Neither store has a live document (or both are unreadable): the
        // malformed warning only matters when something was actually stored.
        (None, None) => {
            let warning = stored.as_deref().and_then(|raw| match Settings::parse(raw) {
                Err(e) => Some(format!("Saved settings could not be read ({e}).")),
                Ok(_) => None,
            });
            (None, warning)
        }
    };

    if let Some(raw) = raw {
        if let Ok(settings) = Settings::parse(&raw) {
            if !settings.nodes.is_empty() {
                return (settings, Source::Stored, warning);
            }
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

    let Ok(rendered) = bundle::render(
        &settings.nodes,
        target,
        shape,
        settings.enhanced_reachability,
        &settings.common,
    ) else {
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
        headers.set(
            "Content-Disposition",
            &format!("attachment; filename=\"{filename}\""),
        )?;
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
            let mut page =
                Response::from_html(if ui_preference(&req).unwrap_or(DEFAULT_UI_BETA) {
                    PANEL_BETA_HTML
                } else {
                    PANEL_HTML
                })?;
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
        Api::VerifyCatalog => verify_catalog(&req, env).await,
        Api::HealthOverlay => health_overlay(env).await,
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
    out.headers_mut()
        .set("Set-Cookie", &super::auth::set_cookie(&token))?;
    Ok(out)
}

fn logout() -> Result<Response> {
    let mut out = json(&Ok2 { ok: true })?;
    out.headers_mut()
        .set("Set-Cookie", &super::auth::clear_cookie())?;
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
    let snapshot = crate::catalog::stored(env).await;
    let country_quality = snapshot.as_ref().map(|snapshot| {
        let now = worker::Date::now().as_millis();
        crate::catalog::country_quality(snapshot, &geo, now)
    });
    json(&api::state(
        &settings,
        &host,
        &sub_base,
        &xhttp_path,
        source,
        warning,
        &geo,
        catalog,
        &catalog_hosts,
        &runtime_candidates,
        fallback,
        country_quality,
        api::quality_by_endpoint(snapshot.as_ref()),
        super::api::session_winner_view(&outbound_state),
        snapshot.as_ref(),
        worker::Date::now().as_millis() / 1000,
    ))
}

/// The EXACT catalog candidates the dial path will use for the current
/// mode/location — the same pool_for + cap the sessions apply. Informational
/// only; the stored snapshot is recomputed on every panel load.
#[cfg(target_arch = "wasm32")]
async fn runtime_candidates_for_state(
    env: &Env,
    cfg: &crate::relay::outbound::OutboundConfig,
) -> Vec<String> {
    if !matches!(
        cfg.mode,
        crate::relay::outbound::ProxyMode::ProxyIp | crate::relay::outbound::ProxyMode::Pool
    ) {
        return Vec::new();
    }
    // Explicit override wins.
    if !cfg.verified_catalog_candidates.is_empty() {
        return cfg
            .verified_catalog_candidates
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
    let Ok(kv) = env.kv(KV_BINDING) else {
        return Vec::new();
    };
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
    // Trinity's worker-vantage verdicts gate eligibility here exactly as on
    // the dial path: the panel never shows a pool the runtime would refuse.
    let state = load_outbound_state(env).await;
    crate::catalog::pool_for_with_health(cfg, Some(&snapshot), &state.geo)
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
async fn load_catalog_meta(env: &Env) -> Option<crate::catalog::Meta> {
    let kv = env.kv(KV_BINDING).ok()?;
    let raw = kv
        .get(crate::catalog::KV_META_KEY)
        .text()
        .await
        .ok()
        .flatten()?;
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
    let mut common = body.common.clone();
    common.normalize();
    if let Err(message) = common.validate() {
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

    let settings = Settings {
        version: super::store::VERSION,
        nodes: body.nodes,
        outbound: body.outbound,
        enhanced_reachability: body.enhanced_reachability,
        rev: new_rev,
        common,
    };
    // No-op guard: when the incoming content equals the stored content (rev
    // excluded), nothing was changed and no store is written — identical saves
    // must not consume KV quota. The stored document (and its rev) stands.
    if stored.nodes == settings.nodes
        && stored.outbound == settings.outbound
        && stored.enhanced_reachability == settings.enhanced_reachability
        && stored.common == settings.common
    {
        let sub_base = format!("https://{host}{}", var(env, "SUB_PATH"));
        let xhttp_path = var(env, "XHTTP_PATH");
        let geo = load_health(env).await;
        let catalog = load_catalog_meta(env).await;
        let catalog_hosts = catalog_hosts_for_state(env, &stored.outbound).await;
        let runtime_candidates =
            runtime_candidates_for_state(env, &stored.outbound).await;
        let snapshot = crate::catalog::stored(env).await;
        let country_quality = snapshot.as_ref().map(|snapshot| {
            let now = worker::Date::now().as_millis();
            crate::catalog::country_quality(snapshot, &geo, now)
        });
        let state = api::state(
            &stored,
            &host,
            &sub_base,
            &xhttp_path,
            Source::Stored,
            None,
            &geo,
            catalog,
            &catalog_hosts,
            &runtime_candidates,
            None,
            country_quality,
            api::quality_by_endpoint(snapshot.as_ref()),
            super::api::session_winner_view(&load_outbound_state(env).await),
            snapshot.as_ref(),
            worker::Date::now().as_millis() / 1000,
        );
        return json(&SavedResponse { ok: true, state });
    }
    let Ok(document) = settings.to_json() else {
        return refuse("Those settings could not be stored.");
    };
    // Primary write: KV. When KV refuses (the free-tier daily write cap, or a
    // missing binding) the DO settings store takes the write — DO storage does
    // not count against the KV daily cap, so a country change still lands.
    // Only when BOTH stores refuse is the save refused.
    let kv_put_ok = match env.kv(KV_BINDING) {
        Ok(kv) => match kv.put(super::store::KEY, document.clone()) {
            Ok(put) => put.execute().await.is_ok(),
            Err(_) => false,
        },
        Err(_) => false,
    };
    if !kv_put_ok {
        if let Err(do_err) = super::settings_do::write(env, super::store::KEY, &document).await {
            return refuse(&format!(
                "Saving failed: the settings stores refused the write ({do_err}). Nothing was changed."
            ));
        }
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
    let snapshot = crate::catalog::stored(env).await;
    let country_quality = snapshot.as_ref().map(|snapshot| {
        let now = worker::Date::now().as_millis();
        crate::catalog::country_quality(snapshot, &geo, now)
    });
    let state = api::state(
        &settings,
        &host,
        &sub_base,
        &xhttp_path,
        Source::Stored,
        None,
        &geo,
        catalog,
        &catalog_hosts,
        &runtime_candidates,
        None,
        country_quality,
        api::quality_by_endpoint(snapshot.as_ref()),
        super::api::session_winner_view(&load_outbound_state(env).await),
        snapshot.as_ref(),
        worker::Date::now().as_millis() / 1000,
    );
    Ok(json(&SavedResponse { ok: true, state })?)
}

#[derive(Serialize)]
struct SavedResponse {
    ok: bool,
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
    match bundle::render(
        &settings.nodes,
        target,
        shape,
        settings.enhanced_reachability,
        &settings.common,
    ) {
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
    let Some(subject) = api::qr_subject(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))) else {
        return refuse("That QR code could not be read.");
    };

    let host = host_of(req);
    let text = match subject {
        api::QrSubject::Subscription(client) => {
            format!(
                "https://{host}{}/{}",
                var(env, "SUB_PATH"),
                bundle::client_slug(client)
            )
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
    // Probe scope = manual candidates UNION the runtime pool. The V24.4.1
    // rule (never probe catalog endpoints) covered only the EDGE identity
    // check; v1.9.8 §8/§9: the relayed-TCP verdict is meaningless unless it
    // touches the boxes sessions actually dial, so the runtime pool is
    // included for the through-probe. Catalog rows are marked source=catalog
    // and their health records are NOT written (scanner stays authoritative
    // for geo/capability class; Trinity only adds the worker-vantage relay
    // verdict it uniquely can measure).
    let mut candidates = settings.outbound.proxy_candidates.clone();
    let mut scope: Vec<(String, &'static str)> =
        candidates.iter().map(|h| (h.clone(), "manual")).collect();
    for h in runtime_candidates_for_state(env, &settings.outbound).await {
        if !candidates.contains(&h) {
            scope.push((h.clone(), "catalog"));
            candidates.push(h);
        }
    }
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
        /// [github, speedtest, google]: through-the-box generic-TCP verdicts
        /// (ClientHello -> ServerHello) for a diversified SNI set. None when
        /// the edge probe already failed (no box to probe through). One SNI
        /// is never proof of universal capability (v1.9.8 §9).
        relayed: Option<[bool; 3]>,
        /// manual = operator-configured; catalog = runtime pool member (its
        /// geo/capability class stays scanner-authoritative; only the relay
        /// verdict is Trinity-measured).
        source: &'static str,
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
    let mut results = Vec::new();
    for (entry, source) in scope {
        // A scope entry is EITHER a bare host (a configured candidate)
        // OR "host:port" (a runtime-pool candidate, which the catalog
        // publishes with its real port). Hardcoding 443 dialed the wrong
        // port for every pool entry and made the host unparseable as an
        // IP, so the transport/egress split below never fired. Split it
        // here: the IPv6 form keeps its brackets (probe_dial_address
        // expects them).
        let (host, port) = super::api::split_host_port(&entry);
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
        // A bare-IP candidate CANNOT pass this trace: the hop is TLS
        // passthrough (connect.rs, SecureTransport::Off) and worker::Socket
        // cannot set SNI for an IP dial, so probe_one always fails there
        // with a "tcp connect: ..." error — which is the exact string
        // Health::quarantined() reads as "the worker cannot reach this".
        // Recording that manufactured a hard unreachable verdict out of a
        // diagnostic limitation, quarantining candidates whose transport
        // is fine (and, via fail_count, permanently). For an IP candidate
        // measure TRANSPORT with probe_tcp_one — the runtime's own dial — and
        // leave egress identity untouched; the relay verdicts below are the
        // capability evidence. A hostname candidate still gets the full
        // trace, which can genuinely verify an exit.
        let is_ip = super::api::probe_kind(&host) == super::api::ProbeKind::Transport;
        let (health, dial_ip, tcp_ms, probe_ms) = if is_ip {
            // Clone the identity out first: `observed_ok` takes `self`,
            // so a borrow inside its own argument list would move a
            // value it still needs (same shape as the verify pass).
            let (c, colo, ip) = (
                prior.country.clone(),
                prior.colo.clone(),
                prior.exit_ip.clone(),
            );
            match probe_tcp_one(&host, port).await {
                Ok(t) => (
                    prior.observed_ok(c, colo, ip, t.latency_ms, now),
                    t.dial_ip,
                    Some(t.tcp_ms),
                    None,
                ),
                Err((e, dial_ip, tcp_ms)) => (prior.observed_fail(e, now), dial_ip, tcp_ms, None),
            }
        } else {
            match probe_one(&host, port).await {
                Ok(trace) => (
                    prior.observed_ok(
                        trace.country,
                        trace.colo,
                        trace.exit_ip,
                        trace.latency_ms,
                        now,
                    ),
                    trace.dial_ip,
                    Some(trace.tcp_ms),
                    Some(trace.probe_ms),
                ),
                Err((e, dial_ip, tcp_ms)) => (prior.observed_fail(e, now), dial_ip, tcp_ms, None),
            }
        };
        // Diversified generic-TCP relay check (3 SNIs: own-origin / Fastly
        // / generic), one plain-TCP dial per SNI. Independent of the edge
        // probe: worker::Socket cannot set SNI for an IP candidate, so the
        // edge probe legitimately fails there while the relay path (no TLS
        // at the dial, destination SNI inside the payload) stays fully
        // testable. Observability only — no demotion from any verdict.
        let relayed = Some([
            relay_probe_ok(&host, port, &RELAY_GH_HELLO).await,
            relay_probe_ok(&host, port, &RELAY_ST_HELLO).await,
            relay_probe_ok(&host, port, &RELAY_GO_HELLO).await,
        ]);
        results.push(Row {
            host,
            port,
            dial_ip,
            tcp_ms,
            probe_ms,
            relayed,
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
            source,
        });
        // Catalog rows: relay verdict only. Their geo/health/quarantine state
        // stays scanner-authoritative (V24.4.1 contract preserved).
        if source == "manual" {
            state.geo.insert(key, health);
        }
    }
    // Best score first: the panel shows the same order the dial path will use.
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(core::cmp::Ordering::Equal)
    });
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

/// TLS 1.2 ClientHello, SNI=github.com (own-origin infra). Live-validated.
const RELAY_GH_HELLO: [u8; 158] = [
    0x16, 0x03, 0x01, 0x00, 0x99, 0x01, 0x00, 0x00, 0x95, 0x03, 0x03, 0xc9, 0x2a, 0x40, 0x4e,
    0x1d, 0x7b, 0xe7, 0xc4, 0xd4, 0xcc, 0x42, 0x04, 0xa2, 0x5a, 0xd1, 0x42, 0xf5, 0x8a, 0x30,
    0xc3, 0x25, 0xa6, 0xde, 0x92, 0xe9, 0x7f, 0xf4, 0x67, 0x39, 0x94, 0x6b, 0x3a, 0x00, 0x00,
    0x02, 0xc0, 0x2f, 0x01, 0x00, 0x00, 0x6a, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
    0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a,
    0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x18, 0x00, 0x19, 0x00, 0x23, 0x00, 0x00, 0x00,
    0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03,
    0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x03, 0x01,
    0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
];

/// TLS 1.2 ClientHello, SNI=speedtest.net (Fastly-fronted; the user-facing speedtest class). Live-validated.
const RELAY_ST_HELLO: [u8; 161] = [
    0x16, 0x03, 0x01, 0x00, 0x9c, 0x01, 0x00, 0x00, 0x98, 0x03, 0x03, 0xbe, 0x0b, 0xfb, 0xaa,
    0x59, 0xb1, 0x99, 0x07, 0xbb, 0xee, 0x00, 0xd4, 0xdc, 0xa9, 0xd2, 0xc5, 0x57, 0x44, 0x4f,
    0xfa, 0x3a, 0xeb, 0x40, 0xbe, 0xb3, 0xbb, 0x15, 0x08, 0x28, 0x99, 0x38, 0xd4, 0x00, 0x00,
    0x02, 0xc0, 0x2f, 0x01, 0x00, 0x00, 0x6d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x00, 0x10, 0x00, 0x00, 0x0d, 0x73, 0x70, 0x65, 0x65, 0x64, 0x74, 0x65, 0x73, 0x74,
    0x2e, 0x6e, 0x65, 0x74, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00,
    0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x18, 0x00, 0x19, 0x00, 0x23,
    0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x2a, 0x00,
    0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a,
    0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03,
    0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
];

/// TLS 1.2 ClientHello, SNI=www.google.com (generic mega-site, non-Fastly origin). Live-validated.
const RELAY_GO_HELLO: [u8; 162] = [
    0x16, 0x03, 0x01, 0x00, 0x9d, 0x01, 0x00, 0x00, 0x99, 0x03, 0x03, 0x27, 0x92, 0xd7, 0x8b,
    0x2f, 0x6a, 0xf2, 0xf0, 0x73, 0xc5, 0xad, 0x5a, 0x1b, 0xd9, 0xf1, 0x91, 0x99, 0xcf, 0x38,
    0xcb, 0x86, 0xef, 0xf5, 0x57, 0x2a, 0x3d, 0xb7, 0x8e, 0x58, 0x83, 0xc1, 0x9f, 0x00, 0x00,
    0x02, 0xc0, 0x2f, 0x01, 0x00, 0x00, 0x6e, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
    0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a,
    0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x18, 0x00, 0x19, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x2a,
    0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08,
    0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
    0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
];

/// Forward-probe one candidate: speak a TLS ClientHello (github.com SNI) to
/// the candidate and require a ServerHello-class record back.
///
/// `Ok(true)`  — the box relays generic TCP for CF-source connections.
/// `Ok(false)` — the TCP port answered but the handshake was refused/blackholed.
/// `Err`       — the dial itself failed (already surfaced by `probe_one`).
///
/// Budget: one 5 s handshake budget, a single 256-byte read. Bounded by
/// construction: one socket, one round trip, no payload beyond the constant.
#[cfg(target_arch = "wasm32")]
async fn relay_probe_ok(host: &str, port: u16, hello: &[u8]) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let target = crate::protocol::Target {
        host: host
            .parse::<std::net::IpAddr>()
            .map_or_else(|_| crate::protocol::Host::Domain(host.trim().to_owned().into_boxed_str()), crate::protocol::Host::Ip),
        port,
    };
    // Dial through the SAME code path sessions use (connect::open) so the
    // probe measures the relay, not a divergent socket recipe.
    let Ok(mut sock) = crate::relay::connect::open(&target) else {
        return false;
    };
    // The connect is lazy: await the TCP handshake before writing, exactly
    // like the session dial path (open_with_plan_tracked) does. Writing into
    // a socket whose handshake has not completed silently loses the bytes.
    let handshook = futures_util::future::select(
        Box::pin(sock.opened()),
        Box::pin(gloo_timers::future::TimeoutFuture::new(5_000)),
    )
    .await;
    // `handshook` still owns the losing future (holding the `sock` borrow),
    // so extract the verdict and drop it before touching `sock` again.
    let ok_open = matches!(handshook, futures_util::future::Either::Left(_));
    drop(handshook);
    if !ok_open {
        let _ = sock.close().await;
        return false;
    }
    if sock.write_all(hello).await.is_err() {
        let _ = sock.close().await;
        return false;
    }
    if sock.flush().await.is_err() {
        let _ = sock.close().await;
        return false;
    }
    let mut buf = [0u8; 256];
    let read = async {
        match sock.read(&mut buf).await {
            Ok(n) if n > 0 => Some(buf[0] == 0x16),
            _ => None,
        }
    };
    let outcome =
        futures_util::future::select(Box::pin(read), Box::pin(gloo_timers::future::TimeoutFuture::new(5_000)));
    let ok = matches!(
        outcome.await,
        futures_util::future::Either::Left((Some(true), _))
    );
    let _ = sock.close().await;
    ok
}


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
    let dial_addr = probe_dial_address(host);
    let mut sock = worker::Socket::builder()
        .allow_half_open(true)
        .secure_transport(SecureTransport::On)
        .connect(&dial_addr, port)
        // On dial failure the attempted target IS the evidence: candidate:port.
        .map_err(|e| (e.to_string(), format!("{host}:{port}"), None))?;
    let dial_ip = match sock.opened().await {
        // The runtime reports the resolved remote address (e.g. `IP:port` for
        // a hostname candidate). Empty for some dials: fall back to the
        // candidate address itself so the panel never shows another IP.
        Ok(info) => {
            let remote = info.remote_address.unwrap_or_default();
            if remote.is_empty() {
                host.to_owned()
            } else {
                remote
            }
        }
        Err(e) => return Err((format!("tcp connect: {e}"), format!("{host}:{port}"), None)),
    };
    let tcp_ms =
        u32::try_from(worker::Date::now().as_millis().saturating_sub(t0)).unwrap_or(u32::MAX);
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
    let probe_ms =
        u32::try_from(worker::Date::now().as_millis().saturating_sub(t1)).unwrap_or(u32::MAX);
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
        let reason = if loc.is_empty() {
            "no loc= in trace".to_owned()
        } else {
            format!("bad loc={loc}")
        };
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
/// Dial address for the panel probes: bare IPv6 literals from the verified
/// feed must be bracketed for workerd's `connect(address, port)` (same
/// boundary rule as `Target::socket_address`; V24.6.11). Domains and IPv4
/// pass through unchanged; an already-bracketed string is left alone.
#[must_use]
fn probe_dial_address(host: &str) -> String {
    let host = host.trim();
    if host.starts_with('[') || !host.contains(':') {
        return host.to_owned();
    }
    // Bare IPv6: parses as an address exactly when it contains a colon and
    // is not a bracketed string. Domains never contain colons.
    host.parse::<std::net::IpAddr>()
        .map(|ip| match ip {
            std::net::IpAddr::V6(_) => format!("[{host}]"),
            std::net::IpAddr::V4(_) => host.to_owned(),
        })
        .unwrap_or_else(|_| host.to_owned())
}

/// Upper bound on TCP probes per invocation: stays under the Workers
/// subrequest budget (free plan 50) with headroom for KV ops, and bounds the
/// worst-case wall time (sequential probes; Cloudflare connect refusals fail
/// fast in practice — `ponytail:` no per-probe timer race, add one if
/// ever make a pass exceed the workflow's patience).
#[cfg(target_arch = "wasm32")]
const VERIFY_MAX_PER_CALL: usize = 40;

/// Wall-clock ceiling for ONE verification pass. The workflow re-invokes with
/// the returned cursor until `done`, so an unfinished pass is a pause, not a
/// failure. Measured: blackhole candidates hang `opened()` until the runtime's
/// own connect timeout, and 40 of those killed the whole request with a 503
/// (run 36056854232) — the pass budget, not more retries, is the fix.
#[cfg(target_arch = "wasm32")]
const VERIFY_PASS_BUDGET_MS: u64 = 80_000;

/// Per-probe connect ceiling for [`probe_tcp_one`]. Under the pass budget:
/// even 40 consecutive worst-case probes fit inside one pass.
#[cfg(target_arch = "wasm32")]
const VERIFY_PROBE_TIMEOUT_MS: u64 = 8_000;

/// One bounded worker-vantage verification pass over the catalog.
///
/// The decisive reachability verdict for a candidate is a TCP connect FROM
/// THIS WORKER'S EGRESS — the vantage that will actually dial it at runtime.
/// GitHub-side health is source evidence only: a candidate the scanner loves
/// but the worker cannot reach (the 44-IP US failure) gets a `tcp connect`
/// verdict here, which quarantines it out of every pool until a later pass
/// proves otherwise. Verdicts fold into the outbound-state health map — the
/// same records runtime feedback and the panel read — with ONE batched KV
/// write per pass, only when something changed.
///
/// Stateless cursor: `?cursor=N&budget=M` slices the deterministic
/// [`crate::catalog::verify_order`] list; the 2-hour workflow loops until
/// `done: true`, so no verification queue or shared schedule state exists.
#[cfg(target_arch = "wasm32")]
async fn verify_catalog(req: &Request, env: &Env) -> Result<Response> {
    let cursor = query(req)
        .into_iter()
        .find(|(k, _)| k == "cursor")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let budget = query(req)
        .into_iter()
        .find(|(k, _)| k == "budget")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(VERIFY_MAX_PER_CALL)
        .clamp(1, VERIFY_MAX_PER_CALL);
    verify_catalog_run(cursor, budget, env).await
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn verify_catalog_run(cursor: usize, budget: usize, env: &Env) -> Result<Response> {
    let Some(snapshot) = crate::catalog::stored(env).await else {
        return refuse("No verified catalog snapshot. Sync first.");
    };
    let mut state = load_outbound_state(env).await;
    // The country in use is verified first (see `catalog::verify_order`).
    let configured = {
        let Ok(kv) = env.kv(KV_BINDING) else {
            return refuse("KV unavailable.");
        };
        match kv.get(crate::panel::store::KEY).text().await {
            Ok(Some(raw)) => crate::relay::outbound::from_settings_json(&raw)
                .catalog_country
                .trim()
                .to_ascii_uppercase(),
            _ => String::new(),
        }
    };
    let order = crate::catalog::verify_order(&snapshot, &state.geo, &configured);
    let total = order.len();
    let start = cursor.min(total);
    // Clamp a zero/negative budget to one probe: a caller asking for 0 would
    // otherwise loop forever on the same cursor without ever advancing.
    let budget = budget.max(1);
    let end = (start + budget).min(total);
    let now = worker::Date::now().as_millis();
    // Verdict-relevant fingerprint BEFORE the fold: the KV write below only
    // fires when one of these changes (new record, reachability flip,
    // quarantine flip, identity change). Steady-state passes — the common
    // case in a 2-hour cycle — write nothing.
    type Fingerprint = (bool, bool, bool, String, String, String, bool);
    let fingerprint = |state: &crate::relay::outbound_state::OutboundState, key: &str| -> Option<Fingerprint> {
        state.geo.get(key).map(|h| {
            (
                h.quarantined(),
                h.ok,
                h.rotating,
                h.country.clone(),
                h.colo.clone(),
                h.exit_ip.clone(),
                h.fail_count >= 2,
            )
        })
    };
    let key_of = |e: &crate::catalog::Endpoint| -> String {
        crate::relay::outbound_state::candidate_key(&crate::protocol::Target {
            host: e.host.parse::<std::net::IpAddr>().map_or_else(
                |_| crate::protocol::Host::Domain(e.host.trim().to_owned().into_boxed_str()),
                crate::protocol::Host::Ip,
            ),
            port: e.port,
        })
    };
    let before: Vec<(String, Option<Fingerprint>)> = order[start..end]
        .iter()
        .map(|e| {
            let key = key_of(e);
            let fp = fingerprint(&state, &key);
            (key, fp)
        })
        .collect();
    let mut probed = 0u32;
    let mut reachable = 0u32;
    let pass_started = worker::Date::now().as_millis();
    let mut paused = false;
    for e in &order[start..end] {
        // Pass wall-clock guard: stop cleanly and report a resume cursor
        // instead of blowing the request limit with a 503. The workflow loops.
        if worker::Date::now().as_millis().saturating_sub(pass_started)
            > VERIFY_PASS_BUDGET_MS
        {
            paused = true;
            break;
        }
        let target = crate::protocol::Target {
            host: e.host.parse::<std::net::IpAddr>().map_or_else(
                |_| crate::protocol::Host::Domain(e.host.trim().to_owned().into_boxed_str()),
                crate::protocol::Host::Ip,
            ),
            port: e.port,
        };
        let key = crate::relay::outbound_state::candidate_key(&target);
        let prior = state.geo.get(&key).cloned().unwrap_or_default();
        // probe_tcp_one classifies for us: every failure arrives as
        // "tcp connect: …" — the hard—unreachable verdict — while a success
        // preserves any exit identity learned elsewhere (a TCP connect knows
        // nothing about the exit IP or country). The identity is cloned
        // before the call: `observed_ok` takes `self`.
        let (c, colo, ip) = (
            prior.country.clone(),
            prior.colo.clone(),
            prior.exit_ip.clone(),
        );
        let updated = match probe_tcp_one(&e.host, e.port).await {
            Ok(trace) => {
                reachable += 1;
                prior.observed_ok(c, colo, ip, trace.latency_ms, now)
            }
            Err((error, _, _)) if error.contains("Too many subrequests") => {
                // Platform budget exhaustion (free-plan 50-subrequest
                // invocation limit), not candidate evidence — recording it
                // would poison country states (09-28 Bug #4). Stop the pass;
                // the workflow's next invocation starts with a fresh budget.
                paused = true;
                break;
            }
            Err((error, _, _)) => prior.observed_fail(error, now),
        };
        state.geo.insert(key, updated);
        probed += 1;
    }
    // One batched write per pass, and only when a verdict actually changed
    // (see the fingerprint above): counts and timestamps may move in memory,
    // but nothing is persisted unless reachability/quarantine/identity flips.
    let changed = before.iter().any(|(key, fp)| fingerprint(&state, key) != *fp);
    if changed {
        if let Ok(kv) = env.kv(KV_BINDING) {
            // Merge, don't clobber: a probe or session write that landed while
            // this pass ran must survive. Our probed keys' verdicts are the
            // freshest (just measured); everything else — including the
            // stored last-known-good preference — stays as stored.
            let merged = match kv.get(crate::relay::outbound_state::KV_KEY).text().await {
                Ok(Some(raw)) => {
                    let stored = crate::relay::outbound_state::OutboundState::from_json(&raw);
                    let mut merged = stored.clone();
                    for (key, health) in &state.geo {
                        match merged.geo.get(key) {
                            Some(old) if old.updated_at_ms > health.updated_at_ms => {}
                            _ => {
                                merged.geo.insert(key.clone(), health.clone());
                            }
                        }
                    }
                    merged
                }
                _ => state.clone(),
            };
            if let Ok(document) = serde_json::to_string(&merged) {
                if let Ok(pending) = kv.put(crate::relay::outbound_state::KV_KEY, document) {
                    let _ = pending.execute().await;
                }
            }
        }
    }
    // Resume cursor: the natural slice boundary, or wherever the wall-clock
    // guard paused us. Both are "continue from here" for the workflow loop.
    let resumed_at = if paused { start + probed as usize } else { end };
    let done = !paused && end >= total;
    json(&serde_json::json!({
        "ok": true,
        "cursor": if done { 0 } else { resumed_at },
        "done": done,
        "probed": probed,
        "reachable": reachable,
        "total": total,
        "paused": paused,
        "counts": health_counts(&snapshot, &state),
    }))
}

/// Per-country health counts for the debug view — the honest numbers:
/// discovered (feed) vs Trinity-reachable vs quarantined. "8 healthy" is
/// never shown when Trinity can reach 0 of them.
#[cfg(target_arch = "wasm32")]
fn health_counts(
    snapshot: &crate::catalog::Snapshot,
    state: &crate::relay::outbound_state::OutboundState,
) -> serde_json::Value {
    use std::collections::BTreeMap;
    let mut out: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (country, list) in &snapshot.countries {
        let mut discovered = 0u32;
        let mut reachable = 0u32;
        let mut quarantined = 0u32;
        let mut unverified = 0u32;
        for e in list {
            discovered += 1;
            let key = format!("{}:{}", e.host.to_ascii_lowercase(), e.port);
            match state.geo.get(&key) {
                Some(h) if h.quarantined() => quarantined += 1,
                Some(h) if h.ok => reachable += 1,
                Some(_) => unverified += 1,
                None => unverified += 1,
            }
        }
        // Stage-C census from the feed (absent on older feeds).
        let capabilities = snapshot.capability_counts.get(country);
        out.insert(
            country.clone(),
            serde_json::json!({
                "discovered": discovered,
                "trinityReachable": reachable,
                "quarantined": quarantined,
                "unverified": unverified,
                "passthrough": capabilities.and_then(|c| c.get("passthrough")).copied().unwrap_or(0),
                "cfRelay": capabilities.and_then(|c| c.get("cf-relay")).copied().unwrap_or(0),
                "sniTerminate": capabilities.and_then(|c| c.get("sni-terminate")).copied().unwrap_or(0),
            }),
        );
    }
    serde_json::Value::Object(out.into_iter().map(|(k, v)| (k, v)).collect())
}

/// The full country-quality aggregation for the health overlay: per-country
/// state (`full`/`degraded`/`limited`/`unavailable`), deterministic quality
/// score, and the underlying capability counts that caused the verdict.
#[cfg(target_arch = "wasm32")]
fn country_quality_json(
    snapshot: &crate::catalog::Snapshot,
    state: &crate::relay::outbound_state::OutboundState,
) -> serde_json::Value {
    let now = worker::Date::now().as_millis();
    let map = crate::catalog::country_quality(snapshot, &state.geo, now);
    serde_json::to_value(&map).unwrap_or(serde_json::Value::Null)
}

/// The health overlay itself, for the panel/API debug view.
#[cfg(target_arch = "wasm32")]
async fn health_overlay(env: &Env) -> Result<Response> {
    let Some(snapshot) = crate::catalog::stored(env).await else {
        return refuse("No verified catalog snapshot. Sync first.");
    };
    let state = load_outbound_state(env).await;
    let quarantined: Vec<String> = state
        .geo
        .iter()
        .filter(|(_, h)| h.quarantined())
        .map(|(k, h)| format!("{k} [{}]", h.error))
        .collect();
    json(&serde_json::json!({
        "ok": true,
        "counts": health_counts(&snapshot, &state),
        "countryQuality": country_quality_json(&snapshot, &state),
        "quarantined": quarantined,
    }))
}

async fn probe_tcp_one(host: &str, port: u16) -> core::result::Result<Trace, ProbeError> {
    use worker::SecureTransport;
    let t0 = worker::Date::now().as_millis();
    let dial_addr = probe_dial_address(host);
    let mut sock = worker::Socket::builder()
        .allow_half_open(true)
        .secure_transport(SecureTransport::Off)
        .connect(&dial_addr, port)
        .map_err(|e| (e.to_string(), format!("{host}:{port}"), None))?;
    // opened() has no internal deadline; a blackhole address would hang until
    // the runtime's own connect timeout and — repeated — killed whole passes
    // with a 503 (run 36056854232). Race it against a per-probe ceiling: the
    // loser is a plain "tcp connect" verdict, exactly like any other refusal.
    // Scoping the select drops the (finished) futures before `sock.close()`
    // — the loser borrows `sock` immutably and must be gone by then.
    enum Dial { Ok(String), Err(String), Timeout }
    let verdict = {
        let opened = core::pin::pin!(sock.opened());
        let budget = core::pin::pin!(gloo_timers::future::sleep(
            std::time::Duration::from_millis(VERIFY_PROBE_TIMEOUT_MS)
        ));
        match futures_util::future::select(opened, budget).await {
            futures_util::future::Either::Left((Ok(info), _)) => {
                let remote = info.remote_address.unwrap_or_default();
                Dial::Ok(if remote.is_empty() { host.to_owned() } else { remote })
            }
            futures_util::future::Either::Left((Err(e), _)) => {
                Dial::Err(format!("tcp connect: {e}"))
            }
            futures_util::future::Either::Right((_, _)) => {
                Dial::Timeout
            }
        }
    };
    let dial_ip = match verdict {
        Dial::Ok(ip) => ip,
        Dial::Err(e) => {
            let _ = sock.close().await;
            return Err((e, format!("{host}:{port}"), None));
        }
        Dial::Timeout => {
            // No Drop on worker::Socket — an abandoned handle on the timeout
            // path would leak until the invocation ends (Bug Hunter 2).
            let _ = sock.close().await;
            return Err((
                "tcp connect: handshake timed out".into(),
                format!("{host}:{port}"),
                None,
            ));
        }
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
pub(crate) async fn refresh_catalog_meta(env: &Env) {
    let Ok(kv) = env.kv(KV_BINDING) else { return };
    let Some(document) = kv.get(crate::catalog::KV_KEY).text().await.ok().flatten() else {
        return;
    };
    let parsed: Option<serde_json::Value> = serde_json::from_str(&document).ok();
    let Some(document) = parsed else { return };
    let fetched_at = document
        .get("fetchedAt")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
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
    let out = json(&Refusal {
        ok: false,
        error: message,
    })?;
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
    let trace_egress = query(req)
        .into_iter()
        .any(|(k, v)| k == "egress" && v == "1");
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
    // for this one request. Nothing is persisted. The worker-vantage overlay
    // gates eligibility exactly as on the dial path.
    let mut cfg = settings.outbound.clone();
    cfg.mode = crate::relay::outbound::ProxyMode::Pool;
    cfg.catalog_pool = true;
    cfg.catalog_country = location.to_ascii_uppercase();
    let health_state = load_outbound_state(env).await;
    let Some(pool) =
        crate::catalog::pool_for_with_health(&cfg, Some(&snapshot), &health_state.geo)
    else {
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
            // ?egress=1: attempt the stage-A style TLS trace through the box so
            // the OPERATOR can see the box's egress from the worker's own
            // vantage (scanner evidence is measured from the scanner's vantage
            // and a multi-upstream box can route differently per source). A
            // failed TLS attempt degrades to the plain TCP row — never a
            // misreported death. Diagnostic only: no state is written.
            if trace_egress {
                match probe_one(&endpoint.host, endpoint.port).await {
                    Ok(t) => {
                        rows.push(Row {
                            candidate,
                            dial_ip: t.dial_ip,
                            tcp_ms: Some(t.tcp_ms),
                            probe_ms: Some(t.probe_ms),
                            observed_country: t.country,
                            colo: t.colo,
                            exit_ip: t.exit_ip,
                            ok: true,
                            error: String::new(),
                        });
                        continue;
                    }
                    Err((reason, _, _)) => {
                        // The edge trace CANNOT succeed on a bare-IP candidate:
                        // this hop is TLS passthrough (`relay::connect::open`,
                        // SecureTransport::Off) and worker::Socket cannot set
                        // SNI for an IP dial, so the handshake never completes
                        // and EVERY candidate "fails" the trace — including
                        // ones a real session proves good. Falling through
                        // silently reported `ok: true` with an empty
                        // country/exitIp, which reads as "verified ES" while
                        // proving nothing. Keep the TCP verdict (unchanged) but
                        // carry the reason, so the operator sees the exit
                        // country is UNVERIFIED rather than absent by design.
                        let unverified = super::api::unverified_reason(&reason);
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
                                error: unverified,
                            }),
                            Err((r2, attempted, tcp_ms)) => rows.push(Row {
                                candidate: if attempted.is_empty() {
                                    candidate
                                } else {
                                    attempted
                                },
                                dial_ip: String::new(),
                                tcp_ms,
                                probe_ms: None,
                                observed_country: String::new(),
                                colo: String::new(),
                                exit_ip: String::new(),
                                ok: false,
                                error: r2,
                            }),
                        }
                        continue;
                    }
                }
            }
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
                    candidate: if attempted.is_empty() {
                        candidate
                    } else {
                        attempted
                    },
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
                candidate: if attempted.is_empty() {
                    candidate
                } else {
                    attempted
                },
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
