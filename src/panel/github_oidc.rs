//! GitHub Actions OIDC verification for the catalog sync endpoint (V24.7).
//!
//! The scheduled scanner authenticates as GitHub, not as a human: its OIDC
//! identity token is a signed JWT whose issuer, audience and subject bind it
//! to exactly one repository, ref and workflow. This module decides whether a
//! presented token is that identity. Signature verification itself needs
//! WebCrypto and a network fetch, so it is injected here as a future — what
//! stays pure (and host-testable) is every decision made *about* the claims.
//!
//! # Fail-closed
//!
//! Every field that is not exactly the expected value rejects the token. The
//! expected values are constants: a workflow file change, a branch rename or
//! a fork all fail. Nothing here trusts a bare assertion.

/// The one audience this deployment accepts. Fixed on both sides (workflow
/// requests it, verifier demands it); a token minted for anything else is
/// worthless here.
pub const AUDIENCE: &str = "trinity-catalog-sync";

/// GitHub's Actions OIDC issuer.
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The only repository allowed to sync.
pub const TRUSTED_REPO: &str = "Osajjad0/trinity-proxy-catalog";

/// The only ref allowed to sync.
pub const TRUSTED_REF: &str = "refs/heads/main";

/// The only workflow allowed to sync (the scheduled scanner).
pub const TRUSTED_WORKFLOW: &str = ".github/workflows/scanner.yml";

/// Only event types that publish a reviewed feed. `pull_request` and forks
/// never reach here even if the workflow path matched.
pub const TRUSTED_EVENTS: [&str; 2] = ["schedule", "workflow_dispatch"];

/// One accepted identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The job's subject claim, verbatim — worth keeping for audit output.
    pub subject: String,
}

/// Why a token was refused. Deliberately coarse: the caller is an unattended
/// workflow, and a detailed taxonomy is an oracle for whoever is probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Structurally not a JWT (wrong segment count, bad base64, not JSON).
    Malformed,
    /// Expired, or outside its validity window.
    Expired,
    /// Issuer/audience not ours.
    WrongParty,
    /// Signature did not verify against GitHub's published keys.
    BadSignature,
    /// Signature is fine but the identity is not the trusted workflow.
    Untrusted,
}

/// Base64url decode (no padding accepted — JWT form). Returns `None` on any
/// non-alphabet byte.
#[must_use]
pub fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            // JWTs are unpadded; '=' here means someone sent the wrong form.
            _ => return None,
        };
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation)]
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero, like the padded decoder in `crypto::base64`.
    if bits >= 8 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// The three decoded parts of a compact JWT: header, payload, signature.
/// Anything but exactly three dot-separated segments is malformed.
#[must_use]
pub fn split_token(token: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    Some((b64url_decode(h)?, b64url_decode(p)?, b64url_decode(s)?))
}

/// The claims this verifier reads, decoded from the payload segment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Claims {
    /// Issuer. Must be exactly [`ISSUER`].
    pub iss: String,
    /// Audience. Must be exactly [`AUDIENCE`].
    pub aud: String,
    /// Expiry, seconds since epoch.
    pub exp: i64,
    /// Issued-at, seconds since epoch.
    #[serde(default)]
    pub iat: Option<i64>,
    /// `repo` claim — GitHub binds this server-side; never free text.
    pub repository: String,
    /// Ref that triggered the run.
    #[serde(default)]
    pub r#ref: Option<String>,
    /// Full workflow ref: `owner/repo/.github/workflows/file.yml@ref`.
    /// GitHub sets this server-side; unlike `workflow` (which carries the
    /// workflow's display *name*) it always identifies the file.
    #[serde(default)]
    pub workflow_ref: Option<String>,
    /// Not-before, seconds since epoch. Enforced when present.
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Event that triggered the run.
    #[serde(default)]
    pub event_name: Option<String>,
    /// Subject — `repo:org/name:ref:...`; kept for the audit trail only.
    #[serde(default)]
    pub sub: Option<String>,
}

/// Parse the payload segment into claims. Structural only.
///
/// # Errors
/// Not JSON, or not shaped like the claim set above.
pub fn parse_claims(payload: &[u8]) -> Result<Claims, Rejection> {
    serde_json::from_slice(payload).map_err(|_| Rejection::Malformed)
}

/// Whether the time-window claims hold at `now` (unix seconds). Expiry is
/// enforced; `iat`/`nbf` are enforced when present, with a small skew for
/// clock differences between GitHub and the runtime.
///
/// GitHub clocks are NTP-disciplined and the Worker's clock is authoritative
/// at the edge; 60s covers the remainder.
const CLOCK_SKEW_SECS: i64 = 60;

#[must_use]
pub fn time_window_ok(claims: &Claims, now: i64) -> bool {
    // exp is required by the spec and always present on GitHub tokens.
    if now >= claims.exp + CLOCK_SKEW_SECS {
        return false;
    }
    if let Some(iat) = claims.iat {
        if iat > now + CLOCK_SKEW_SECS {
            return false;
        }
    }
    if let Some(nbf) = claims.nbf {
        if now + CLOCK_SKEW_SECS < nbf {
            return false;
        }
    }
    true
}

/// Identity decision on the claims alone (issuer, audience, repo, ref,
/// workflow, event). Signature and time checks are separate concerns.
#[must_use]
pub fn identity_ok(claims: &Claims) -> Result<(), Rejection> {
    if claims.iss != ISSUER || claims.aud != AUDIENCE {
        return Err(Rejection::WrongParty);
    }
    if claims.repository != TRUSTED_REPO {
        return Err(Rejection::Untrusted);
    }
    if claims.r#ref.as_deref() != Some(TRUSTED_REF) {
        return Err(Rejection::Untrusted);
    }
    // `workflow` carries the workflow's display NAME; `workflow_ref` carries
    // the file path the mission binds to. Require the full
    // `owner/repo/.github/workflows/scanner.yml@refs/heads/main` form so
    // repo and ref are re-pinned by the same server-set string.
    let expected_workflow_ref = format!(
        "{}/{}@{}",
        TRUSTED_REPO, TRUSTED_WORKFLOW, TRUSTED_REF
    );
    if claims.workflow_ref.as_deref() != Some(expected_workflow_ref.as_str()) {
        return Err(Rejection::Untrusted);
    }
    let event_ok = claims
        .event_name
        .as_deref()
        .is_some_and(|e| TRUSTED_EVENTS.contains(&e));
    if !event_ok {
        return Err(Rejection::Untrusted);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Wasm side: signature verification via WebCrypto, JWKS via fetch.
//
// On the Worker, `verify_wasm` is the full pipeline: decode → parse → verify
// the RS256 signature against GitHub's published JWKS keys → check the time
// window → check the identity. Any step that cannot complete is a rejection;
// nothing falls back to "accept" — fail-closed by construction.
// ---------------------------------------------------------------------------

/// GitHub's JWKS. Fetched fresh on every verification: keys rotate, and a
/// sync happens once a day at most — the request is not a bottleneck.
const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

#[cfg(target_arch = "wasm32")]
pub async fn verify_wasm(token: &str) -> Result<Identity, Rejection> {
    // 1. Shape: exactly three segments, all decodable.
    let (header_bytes, payload_bytes, signature) =
        split_token(token).ok_or(Rejection::Malformed)?;

    // 2. Header: RS256 only. A different alg is a different identity scheme.
    #[derive(serde::Deserialize)]
    struct Header {
        #[serde(rename = "alg")]
        _alg: String,
        kid: String,
    }
    let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| Rejection::Malformed)?;
    if header._alg != "RS256" {
        return Err(Rejection::BadSignature);
    }

    // 3. Parse the claims now so a malformed token never triggers a fetch.
    let claims = parse_claims(&payload_bytes)?;

    // 4. Signature: RS256 over `<header>.<payload>` with GitHub's key.
    verify_signature(
        token.rsplit_once('.').map_or(token, |(h, _)| h),
        &header.kid,
        &signature,
    )
    .await?;

    // 5. Time window at the edge's clock.
    let now = worker::Date::now().as_millis() / 1000;
    let now = i64::try_from(now).map_err(|_| Rejection::Expired)?;
    if !time_window_ok(&claims, now) {
        return Err(Rejection::Expired);
    }

    // 6. Identity: the one trusted workflow, repo, ref, event.
    identity_ok(&claims)?;

    Ok(Identity {
        subject: claims.sub.unwrap_or_default(),
    })
}

/// RS256 verification against GitHub's JWKS. Returns `Err(BadSignature)` for
/// a wrong signature, an unknown kid, or any fetch/import/verify failure.
#[cfg(target_arch = "wasm32")]
async fn verify_signature(
    signing_input: &str,
    kid: &str,
    signature: &[u8],
) -> Result<(), Rejection> {
    use js_sys::{Object, Uint8Array, JSON};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use worker::{Fetch, Method, Request as WRequest};

    // Fetch the JWKS from GitHub. Network or format failures reject.
    let request = WRequest::new(JWKS_URL, Method::Get).map_err(|_| Rejection::BadSignature)?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| Rejection::BadSignature)?;
    if response.status_code() >= 400 {
        return Err(Rejection::BadSignature);
    }
    let jwks_text = response.text().await.map_err(|_| Rejection::BadSignature)?;

    // Parse and find the key whose kid matches. Unknown kid = reject (the
    // token was signed with a key GitHub is not currently publishing).
    let jwks: JsValue = JSON::parse(jwks_text.as_str()).map_err(|_| Rejection::BadSignature)?;
    let key_json = find_jwk(&jwks, kid).ok_or(Rejection::BadSignature)?;

    // importKey('jwk', ..., {name:'RSASSA-PKCS1-v1_5'}, false, ['verify']).
    // `key_usages` must be a JS array; extractable=false — we never export.
    let global = js_sys::global();
    let crypto_obj = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|_| Rejection::BadSignature)?;
    let crypto: web_sys::Crypto = crypto_obj.dyn_into().map_err(|_| Rejection::BadSignature)?;
    let subtle = crypto.subtle();

    let algorithm =
        JSON::parse(r#"{"name":"RSASSA-PKCS1-v1_5","hash":"SHA-256"}"#)
            .map_err(|_| Rejection::BadSignature)?;
    let usages = js_sys::Array::of1(&JsValue::from_str("verify"));

    let imported: JsValue = JsFuture::from(
        subtle
            .import_key_with_object(
                "jwk",
                key_json.as_ref().unchecked_ref::<Object>(),
                algorithm.as_ref().unchecked_ref::<Object>(),
                false,
                usages.as_ref(),
            )
            .map_err(|_| Rejection::BadSignature)?,
    )
    .await
    .map_err(|_| Rejection::BadSignature)?;
    let key: web_sys::CryptoKey = imported.dyn_into().map_err(|_| Rejection::BadSignature)?;

    // crypto.subtle.verify(alg, key, signature, data). The data is the raw
    // `header.payload` bytes; the signature is the decoded third segment.
    let signing = Uint8Array::from(signing_input.as_bytes());
    let sig = Uint8Array::from(signature);
    let verified: JsValue = JsFuture::from(
        subtle
            .verify_with_str_and_js_u8_array_and_js_u8_array(
                "RSASSA-PKCS1-v1_5",
                &key,
                &sig,
                &signing,
            )
            .map_err(|_| Rejection::BadSignature)?,
    )
    .await
    .map_err(|_| Rejection::BadSignature)?;

    if verified.as_bool() != Some(true) {
        return Err(Rejection::BadSignature);
    }
    Ok(())
}

/// Find the JWK object with `kid` in a parsed JWKS document.
#[cfg(target_arch = "wasm32")]
fn find_jwk(jwks: &wasm_bindgen::JsValue, kid: &str) -> Option<wasm_bindgen::JsValue> {
    use wasm_bindgen::{JsCast, JsValue};
    let keys = js_sys::Reflect::get(jwks, &JsValue::from_str("keys")).ok()?;
    let keys: js_sys::Array = keys.dyn_into().ok()?;
    for entry in keys.iter() {
        let entry_kid = js_sys::Reflect::get(&entry, &JsValue::from_str("kid")).ok()?;
        if entry_kid.as_string().as_deref() == Some(kid) {
            return Some(entry);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Claims {
        Claims {
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            exp: 1_800_000_000,
            iat: Some(1_799_999_000),
            repository: TRUSTED_REPO.into(),
            r#ref: Some(TRUSTED_REF.into()),
            workflow_ref: Some(format!(
                "{}/{}@{}",
                TRUSTED_REPO, TRUSTED_WORKFLOW, TRUSTED_REF
            )),
            nbf: Some(1_799_999_000),
            event_name: Some("schedule".into()),
            sub: Some("repo:Osajjad0/trinity-proxy-catalog:ref:refs/heads/main".into()),
        }
    }

    #[test]
    fn b64url_decodes_without_padding_and_rejects_garbage() {
        assert_eq!(b64url_decode("aGVsbG8"), Some(b"hello".to_vec()));
        assert_eq!(b64url_decode("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(b64url_decode("a+b/"), None); // standard alphabet is wrong here
        assert_eq!(b64url_decode("!!!"), None);
    }

    /// Test-local base64url encoder so segments are always valid encodings.
    fn b64url_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
            let (count, chars): (usize, [u32; 4]) = match chunk.len() {
                1 => (2, [n >> 18, n >> 12, 0, 0]),
                2 => (3, [n >> 18, n >> 12, n >> 6, 0]),
                _ => (4, [n >> 18, n >> 12, n >> 6, n]),
            };
            for shift in chars.into_iter().take(count) {
                #[allow(clippy::cast_possible_truncation)]
                out.push(ALPHABET[(shift & 63) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn token_split_needs_exactly_three_segments() {
        let token = format!(
            "{}.{}.{}",
            b64url_encode(br#"{"alg":"RS256"}"#),
            b64url_encode(br#"{"iss":"x"}"#),
            b64url_encode(b"signature-bytes")
        );
        assert!(split_token(&token).is_some());
        assert!(split_token("a.b").is_none());
        assert!(split_token("a.b.c.d").is_none());
        assert!(split_token(&format!("{token}.extra")).is_none());
        // Corrupt base64 in any segment is malformed, not a parse crash.
        assert!(split_token(&format!(
            "!!.{0}.{1}",
            b64url_encode(b"x"),
            b64url_encode(b"y")
        ))
        .is_none());
    }

    #[test]
    fn a_correct_identity_passes_every_check() {
        let c = claims();
        assert!(time_window_ok(&c, 1_799_999_500));
        assert_eq!(identity_ok(&c), Ok(()));
    }

    #[test]
    fn wrong_issuer_or_audience_is_wrong_party() {
        let mut c = claims();
        c.iss = "https://evil.example".into();
        assert_eq!(identity_ok(&c), Err(Rejection::WrongParty));
        let mut c = claims();
        c.aud = "some-other-service".into();
        assert_eq!(identity_ok(&c), Err(Rejection::WrongParty));
    }

    #[test]
    fn any_other_repo_ref_workflow_or_event_is_untrusted() {
        for fix in [
            |mut c: Claims| {
                c.repository = "attacker/trinity-proxy-catalog".into();
                c
            },
            |mut c: Claims| {
                c.r#ref = Some("refs/heads/dev".into());
                c
            },
            |mut c: Claims| {
                // Another workflow file in the same repo is still untrusted.
                c.workflow_ref =
                    Some("Osajjad0/trinity-proxy-catalog/.github/workflows/other.yml@refs/heads/main".into());
                c
            },
            |mut c: Claims| {
                c.event_name = Some("pull_request".into());
                c
            },
            |mut c: Claims| {
                c.event_name = None;
                c
            },
        ] {
            let c = fix(claims());
            assert_eq!(identity_ok(&c), Err(Rejection::Untrusted));
        }
    }

    #[test]
    fn expired_and_future_issued_tokens_are_rejected() {
        let c = claims();
        assert!(!time_window_ok(&c, c.exp + 120)); // past expiry beyond skew
        let mut c = claims();
        c.iat = Some(1_800_000_100); // issued in the future
        assert!(!time_window_ok(&c, 1_800_000_000 - 100));
    }

    #[test]
    fn skew_tolerates_a_late_checked_but_still_valid_token() {
        let c = claims();
        // 30s past exp: inside the 60s skew window.
        assert!(time_window_ok(&c, c.exp + 30));
        // 59s before exp: fine.
        assert!(time_window_ok(&c, c.exp - 59));
    }

    #[test]
    fn malformed_payloads_do_not_parse() {
        for bad in ["", "not json", r#"{"iss":1}"#, r#"[]"#] {
            assert_eq!(
                parse_claims(bad.as_bytes()),
                Err(Rejection::Malformed),
                "{bad}"
            );
        }
    }
}
