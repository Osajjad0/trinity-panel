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

    let Ok(rendered) = bundle::render(&settings.nodes, target, shape) else {
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
    headers.set("Profile-Title", target.name())?;
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
        Api::Page => Response::from_html(PANEL_HTML),
        Api::Login => login(&mut req, &password).await,
        Api::Logout => logout(),
        Api::State => state(&req, env).await,
        Api::Save => save(&mut req, env).await,
        Api::Check => check(&mut req).await,
        Api::Export => export(&req, env).await,
        Api::Qr => qr(&req, env).await,
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
    json(&api::state(&settings, &host, &sub_base, &xhttp_path, source, warning))
}

async fn save(req: &mut Request, env: &Env) -> Result<Response> {
    let Ok(body) = req.json::<api::SaveRequest>().await else {
        return refuse("Those settings could not be read.");
    };
    if let Err(message) = api::validate(&body.nodes) {
        return refuse(&message);
    }

    let settings = Settings { version: super::store::VERSION, nodes: body.nodes };
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
    let host = host_of(req);
    let sub_base = format!("https://{host}{}", var(env, "SUB_PATH"));
    let xhttp_path = var(env, "XHTTP_PATH");
    let state = api::state(&settings, &host, &sub_base, &xhttp_path, Source::Stored, None);
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
    let advice = super::advisor::advise(&node, target);
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
    match bundle::render(&settings.nodes, target, shape) {
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
            match crate::subscription::to_uri(node, client) {
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
