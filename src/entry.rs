//! The Worker entry point.
//!
//! Thin by design. Everything it decides is decided in [`crate::router`],
//! which is pure and tested on the host; this module only performs the I/O
//! that decision implies. Keeping the branching out of here is what makes the
//! routing logic testable at all — a `fetch` handler cannot be unit tested
//! without a runtime, but a function from `(method, path)` to an enum can.
//!
//! # The invariant this module exists to preserve
//!
//! Anything not positively identified resolves to the decoy page, and the
//! decoy is served identically no matter why it was reached. There is no
//! branch here that returns a distinguishable 404, no error body, and no
//! timing difference worth measuring. A scanner sweeping this hostname sees a
//! plain status page and nothing else.

use worker::{event, Context, Env, Request, Response, Result};

use crate::router::{route, Route, Routes};
use crate::transport::xhttp::wire::Class;

/// Header that marks a WebSocket upgrade.
const UPGRADE: &str = "Upgrade";

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // A panic in a WASM isolate takes every connection on it down, so the
    // handler is written to have no panicking path at all. This is belt and
    // braces for anything the compiler cannot prove.
    match dispatch(req, &env).await {
        Ok(resp) => Ok(resp),
        // Never surface an internal error to the peer: an error page is a
        // signal that something is here. Fall back to the decoy.
        Err(_) => decoy(&env).await,
    }
}

async fn dispatch(req: Request, env: &Env) -> Result<Response> {
    let routes = load_routes(env);
    let method = req.method().to_string();
    let path = req.path();
    let is_upgrade = req
        .headers()
        .get(UPGRADE)?
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    match route(&method, &path, is_upgrade, &routes) {
        Route::Xhttp(class) => xhttp(req, env, class).await,
        Route::DuplexProbe => duplex_probe(req).await,
        // Off unless explicitly enabled. This endpoint dials an
        // attacker-chosen host and port and reports what happened, which makes
        // the Worker a port scanner and a probe for otherwise-unreachable
        // internal services. The secret path prefix is not sufficient
        // protection for that — it is a diagnostic, so it is opt-in.
        Route::ConnectProbe => {
            if env.var("DIAGNOSTICS").map(|v| v.to_string()).unwrap_or_default() == "true" {
                connect_probe(&req, env).await
            } else {
                decoy(env).await
            }
        }
        Route::WebSocket => crate::transport::websocket::handle(&req, env),
        Route::Subscription { rest } => crate::panel::serve::subscription(&req, env, rest).await,
        Route::Panel { rest } => crate::panel::serve::panel(req, env, rest).await,
        Route::Decoy => decoy(env).await,
    }
}

/// Forward an XHTTP request to the Durable Object that owns its session.
///
/// The session id in the URL is the routing key, which is what makes the
/// downlink `GET` and every uplink `POST` land on the same object — and hence
/// on the same open socket — regardless of which isolate received them.
async fn xhttp(req: Request, env: &Env, class: Class<'_>) -> Result<Response> {
    let session = match class {
        Class::Downlink { session } | Class::PacketUp { session, .. } => session.as_str(),
        // Answer the preflight here rather than waking an object for it.
        Class::Preflight => return Response::empty(),
        // stream-one carries both directions in one request and needs no
        // cross-request state, so it never reaches a Durable Object. Not yet
        // implemented; it stays behind the duplex probe.
        Class::StreamOne | Class::StreamUp { .. } | Class::NotOurs => {
            return decoy(env).await;
        }
    };

    let ns = match env.durable_object("XHTTP_SESSION") {
        Ok(ns) => ns,
        Err(e) => return do_error(env, &format!("stub: {e}")).await,
    };
    let id = match ns.id_from_name(session) {
        Ok(id) => id,
        Err(e) => return do_error(env, &format!("stub: {e}")).await,
    };
    let stub = match id.get_stub() {
        Ok(s) => s,
        Err(e) => return do_error(env, &format!("stub: {e}")).await,
    };
    match stub.fetch_with_request(req).await {
        Ok(resp) => Ok(resp),
        Err(e) => do_error(env, &format!("fetch: {e}")).await,
    }
}

/// Diagnostic: surface the Durable Object error instead of the decoy.
///
/// Active only when DIAGNOSTICS=true, i.e. on throwaway test deployments
/// that need the actual failure text; anywhere else this is a no-op wrapper
/// and the decoy is served exactly as before.
async fn do_error(env: &Env, msg: &str) -> Result<Response> {
    if env.var("DIAGNOSTICS").map(|v| v.to_string()).unwrap_or_default() == "true" {
        Response::ok(format!("DO-ERR {msg}"))
    } else {
        decoy(env).await
    }
}

/// Measure whether this deployment can actually stream a request body in
/// before the response body goes out.
///
/// The evidence on whether Cloudflare supports full duplex is genuinely
/// contradictory — see `docs/research/phase-0-report.md` §4 — and it decides
/// whether the `stream-up` and `stream-one` XHTTP modes are usable. Rather
/// than guess, or copy another project's guess, this endpoint measures it on
/// the real deployment and the panel reports what it found.
///
/// The client posts a body in two parts with a delay between them. If the
/// first part reaches us before the second is sent, duplex works.
async fn duplex_probe(mut req: Request) -> Result<Response> {
    /// The probe needs only enough body to observe whether it arrives in
    /// pieces. Without a cap this endpoint is an unauthenticated way to make
    /// the isolate allocate arbitrarily.
    const MAX_PROBE_BYTES: usize = 64 * 1024;

    let declared = req
        .headers()
        .get("Content-Length")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_none_or(|n| n > MAX_PROBE_BYTES) {
        return Response::empty().map(|r| r.with_status(413));
    }

    let started = worker::Date::now().as_millis();
    let body = req.bytes().await?;
    let elapsed = worker::Date::now().as_millis().saturating_sub(started);

    // If the edge buffered the whole body before invoking us, the read
    // returns instantly with everything. If it streamed, we waited for the
    // client's own delay.
    let verdict = if elapsed >= 400 { "duplex" } else { "buffered" };
    Response::ok(format!(
        r#"{{"verdict":"{verdict}","elapsed_ms":{elapsed},"bytes":{}}}"#,
        body.len()
    ))
}

/// Dial a destination and report exactly what happened at each step.
///
/// The relay cannot tell a refused connection from a destination that simply
/// never speaks — both appear as a read that yields nothing. This separates
/// them, and reports the failure text rather than swallowing it, which is what
/// the relay must do in production but is useless when diagnosing.
///
/// Reachable only under the secret XHTTP prefix, so it is not discoverable
/// without already knowing the path.
async fn connect_probe(req: &Request, env: &Env) -> Result<Response> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let url = req.url()?;
    let mut host = "example.com".to_owned();
    let mut port: u16 = 80;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "host" => host = v.into_owned(),
            "port" => port = v.parse().unwrap_or(80),
            _ => {}
        }
    }

    let mut steps: Vec<String> = Vec::new();
    let target = crate::protocol::Target {
        host: crate::protocol::Host::Domain(host.clone().into_boxed_str()),
        port,
    };
    if target.is_locally_rejectable() {
        steps.push("refused: destination not permitted".into());
        return json_steps(&steps);
    }

    // Load the operator's real outbound config so this probe diagnoses the
    // path the relay actually takes. Falls back to Off on any error.
    let outbound_cfg = crate::relay::outbound::load(env).await;
    let plan = outbound_cfg.resolve(&target);
    steps.push(format!("mode: {:?}, candidates: {}", outbound_cfg.mode, plan.candidates.len()));

    // open_with_plan already awaits opened() for multi-candidate plans, so
    // the socket returned here has a completed handshake. For single-candidate
    // (Off mode) it returns the lazy socket, which we verify below.
    let mut sock = match crate::relay::connect::open_with_plan(&plan).await {
        Ok(s) => {
            steps.push("connect() returned a socket".into());
            s
        }
        Err(e) => {
            steps.push(format!("connect() failed: {e}"));
            return json_steps(&steps);
        }
    };

    // For Off mode (single candidate), open_with_plan returns the lazy socket
    // without awaiting opened(). Verify the handshake explicitly so the probe
    // reports the same information regardless of mode.
    if plan.candidates.len() == 1 {
        match sock.opened().await {
            Ok(_) => steps.push("socket opened".into()),
            Err(e) => {
                steps.push(format!("opened() failed: {e}"));
                return json_steps(&steps);
            }
        }
    } else {
        steps.push("socket opened (verified by open_with_plan)".into());
    }

    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    match sock.write_all(request.as_bytes()).await {
        Ok(()) => steps.push("wrote request".into()),
        Err(e) => {
            steps.push(format!("write failed: {e}"));
            return json_steps(&steps);
        }
    }
    if let Err(e) = sock.flush().await {
        steps.push(format!("flush failed: {e}"));
    }

    let mut buf = vec![0u8; 512];
    match sock.read(&mut buf).await {
        Ok(0) => steps.push("read returned 0 (destination closed without replying)".into()),
        Ok(n) => {
            let head = String::from_utf8_lossy(&buf[..n.min(80)]).replace(['\r', '\n'], " ");
            steps.push(format!("read {n} bytes: {head}"));
        }
        Err(e) => steps.push(format!("read failed: {e}")),
    }

    json_steps(&steps)
}

fn json_steps(steps: &[String]) -> Result<Response> {
    let body = serde_json::json!({ "steps": steps }).to_string();
    let mut resp = Response::ok(body)?;
    resp.headers_mut().set("Content-Type", "application/json")?;
    Ok(resp)
}

/// Serve the decoy page.
///
/// Every negative outcome in this module ends here, with the same bytes and
/// the same status. If the asset is missing the fallback is still a plain 200
/// rather than an error, because a deployment that answers 500 to a scanner
/// has told it something.
pub(crate) async fn decoy(env: &Env) -> Result<Response> {
    const FALLBACK: &str = "<!doctype html><title>Status</title><h1>All systems operational</h1>";

    let Ok(assets) = env.assets("ASSETS") else {
        return Response::from_html(FALLBACK);
    };
    let Ok(url) = worker::Url::parse("https://assets.invalid/index.html") else {
        return Response::from_html(FALLBACK);
    };
    match Request::new(url.as_str(), worker::Method::Get) {
        Ok(r) => match assets.fetch_request(r).await {
            Ok(resp) => Ok(resp),
            Err(_) => Response::from_html(FALLBACK),
        },
        Err(_) => Response::from_html(FALLBACK),
    }
}

/// Read the configured path prefixes.
///
/// Defaults are deliberately unroutable rather than guessable: a deployment
/// whose operator has not set a prefix serves the decoy for everything instead
/// of exposing a transport on a predictable path.
fn load_routes(env: &Env) -> Routes {
    let get = |name: &str| env.var(name).map(|v| v.to_string()).unwrap_or_default();

    let ws = get("WS_PATH");
    Routes {
        xhttp: get("XHTTP_PATH"),
        websocket: if get("WS_ENABLED") == "true" && !ws.is_empty() {
            Some(ws)
        } else {
            None
        },
        panel: get("PANEL_PATH"),
        subscription: get("SUB_PATH"),
    }
}
