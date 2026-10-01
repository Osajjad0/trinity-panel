//! Settings storage fallback via the XHTTP_SESSION Durable Object (SQLite).
//!
//! KV writes have a hard account-wide daily cap on Cloudflare's free plan;
//! DO storage writes do not count against it. When a KV put is quota-refused,
//! the panel stores the settings document in the DO under the same key name
//! and reads from there whenever KV has no copy. The DO route is
//! password-guarded (see transport::xhttp::durable).

use worker::{Env, Headers, Method, Request, RequestInit};

/// DO namespace binding name (the same one the XHTTP transport uses).
const NS: &str = "XHTTP_SESSION";
/// Dedicated object id — never collides with real session ids.
const DO_NAME: &str = "panel-settings";
/// Secret header the DO checks before serving /settings.
const KEY_HEADER: &str = "x-trinity-settings-key";

async fn call(env: &Env, method: Method, path: &str, body: Option<String>) -> Option<String> {
    let password = env.var("PANEL_PASSWORD").ok()?.to_string();
    let ns = env.durable_object(NS).ok()?;
    let id = ns.id_from_name(DO_NAME).ok()?;
    let stub = id.get_stub().ok()?;
    let url = format!("https://do.internal/settings/{path}");
    let mut init = RequestInit::new();
    init.method = method;
    init.with_headers(Headers::from_iter([(KEY_HEADER, password.as_str())]));
    if let Some(b) = &body {
        init.with_body(Some(b.clone().into()));
    }
    let req = Request::new_with_init(&url, &init).ok()?;
    let mut resp = stub.fetch_with_request(req).await.ok()?;
    if resp.status_code() == 200 {
        resp.text().await.ok()
    } else {
        None
    }
}

/// Read a value from the DO store (None = absent or unreachable).
pub async fn read(env: &Env, key: &str) -> Option<String> {
    call(env, Method::Get, key, None).await
}

/// Write a value to the DO store. Err carries a stable failure text.
pub async fn write(env: &Env, key: &str, value: &str) -> Result<(), String> {
    match call(env, Method::Put, key, Some(value.to_owned())).await {
        Some(_) => Ok(()),
        None => Err("Durable Object settings store refused the write.".to_owned()),
    }
}
