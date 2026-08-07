//! Panel authentication.
//!
//! The panel can read every credential the deployment serves and can rewrite
//! what its users import. It is the most valuable thing on the hostname, so it
//! gets a real session rather than a query-string password.
//!
//! # Shape of the session
//!
//! A token is `expiry.mac`, where `mac = BLAKE3::keyed_hash(secret, expiry)`
//! truncated. There is no server-side session table because there is nowhere
//! to put one: a Worker has no memory between requests, and a KV round trip on
//! every panel request to look up a session would be slower than recomputing
//! the MAC. Stateless tokens are the right shape here rather than a compromise.
//!
//! The key is derived from the operator's password, so a password change
//! invalidates every outstanding session for free.
//!
//! # What this does not attempt
//!
//! There is no revocation list, and no protection against an attacker who has
//! already read the secret binding. Both would be theatre: anyone who can read
//! the binding can mint tokens directly.
//!
//! Rate limiting is likewise not attempted here. It belongs at the edge, and
//! implementing a counter in KV would add a write to every failed attempt —
//! which is itself a denial-of-service amplifier. What is done instead is to
//! make each attempt cost a BLAKE3 derivation and to compare in constant time.

use crate::crypto::blake3;
use crate::protocol::ct_eq;

/// Cookie the session token travels in.
pub const COOKIE: &str = "tricore_session";

/// How long a session lasts.
///
/// Twelve hours: long enough that an operator configuring nodes is not logged
/// out mid-edit, short enough that a token copied off a shared machine expires
/// the same day.
pub const SESSION_SECS: u64 = 12 * 60 * 60;

/// Derivation context for the session key. Distinct from every other use of
/// the password so a token can never be replayed as anything else.
const SESSION_CONTEXT: &str = "tricore-panel 2026 session token";

/// Bytes of MAC carried in a token. Sixteen is far beyond forgeable and keeps
/// the cookie short.
const MAC_LEN: usize = 16;

/// Why a panel request was not authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No password is configured, so the panel is closed entirely.
    ///
    /// Deliberately not "allow everything": a deployment whose operator has
    /// not set a password must not expose an open admin panel.
    NotConfigured,
    /// No token presented.
    Missing,
    /// Token malformed, expired, or the MAC did not verify. One variant on
    /// purpose — telling a caller which would help them search the space.
    Invalid,
}

/// The session key for a password.
fn session_key(password: &str) -> [u8; 32] {
    blake3::derive_key(SESSION_CONTEXT, password.as_bytes())
}

/// Whether a submitted password matches, in constant time.
///
/// Compares derived keys rather than the passwords themselves so the
/// comparison is over a fixed 32 bytes regardless of input length — a
/// byte-wise compare of the raw strings leaks the length of the real password.
#[must_use]
pub fn password_matches(submitted: &str, configured: &str) -> bool {
    if configured.is_empty() {
        return false;
    }
    ct_eq(&session_key(submitted), &session_key(configured))
}

/// Mint a token valid until `now_secs + SESSION_SECS`.
#[must_use]
pub fn issue(password: &str, now_secs: u64) -> String {
    let expiry = now_secs.saturating_add(SESSION_SECS);
    let mac = mac_for(password, expiry);
    format!("{expiry}.{}", hex(&mac))
}

/// Verify a token.
///
/// # Errors
/// [`AuthError`] for every failure, without distinguishing which.
pub fn verify(token: &str, password: &str, now_secs: u64) -> Result<(), AuthError> {
    if password.is_empty() {
        return Err(AuthError::NotConfigured);
    }
    let (expiry_text, mac_text) = token.split_once('.').ok_or(AuthError::Invalid)?;
    let expiry: u64 = expiry_text.parse().map_err(|_| AuthError::Invalid)?;

    // Verify the MAC before the clock. Checking expiry first would answer
    // "is this a well-formed token for some other time?" without a valid MAC.
    let expected = mac_for(password, expiry);
    let presented = unhex(mac_text).ok_or(AuthError::Invalid)?;
    if !ct_eq(&presented, &expected) {
        return Err(AuthError::Invalid);
    }
    if expiry <= now_secs {
        return Err(AuthError::Invalid);
    }
    Ok(())
}

fn mac_for(password: &str, expiry: u64) -> [u8; MAC_LEN] {
    let full = blake3::keyed_hash(&session_key(password), expiry.to_string().as_bytes());
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

/// Extract our cookie from a `Cookie` header.
///
/// Written out rather than split naively: cookie values are separated by
/// `; `, other cookies share the header, and a prefix match would accept
/// `not_tricore_session`.
#[must_use]
pub fn token_from_cookies(header: &str) -> Option<&str> {
    header.split(';').map(str::trim).find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == COOKIE).then(|| value.trim())
    })
}

/// The `Set-Cookie` value for a freshly issued token.
///
/// `HttpOnly` keeps it out of any script on the page, `Secure` off a plaintext
/// hop, `SameSite=Strict` off a cross-site request, and `Path=/` because the
/// panel prefix is secret and putting it in a cookie attribute would write it
/// into every request the browser makes to this host.
#[must_use]
pub fn set_cookie(token: &str) -> String {
    format!("{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_SECS}")
}

/// The `Set-Cookie` value that clears the session.
#[must_use]
pub fn clear_cookie() -> String {
    format!("{COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

fn unhex(text: &str) -> Option<[u8; MAC_LEN]> {
    if text.len() != MAC_LEN * 2 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = [0u8; MAC_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        // Both digits are below 16, so the combination fits in a byte.
        #[allow(clippy::cast_possible_truncation)]
        {
            *slot = ((hi << 4) | lo) as u8;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery staple";
    const NOW: u64 = 1_785_100_000;

    #[test]
    fn a_freshly_issued_token_verifies() {
        let token = issue(PW, NOW);
        assert_eq!(verify(&token, PW, NOW), Ok(()));
    }

    #[test]
    fn a_token_expires() {
        let token = issue(PW, NOW);
        assert_eq!(verify(&token, PW, NOW + SESSION_SECS - 1), Ok(()));
        assert_eq!(verify(&token, PW, NOW + SESSION_SECS), Err(AuthError::Invalid));
        assert_eq!(verify(&token, PW, NOW + SESSION_SECS + 1), Err(AuthError::Invalid));
    }

    #[test]
    fn a_token_does_not_verify_under_a_different_password() {
        // Which is also what makes a password change revoke every session.
        let token = issue(PW, NOW);
        assert_eq!(verify(&token, "something else", NOW), Err(AuthError::Invalid));
    }

    #[test]
    fn an_extended_expiry_does_not_verify() {
        // The attack the MAC exists to stop: take a valid token and move its
        // deadline. The MAC covers the expiry, so the edit invalidates it.
        let token = issue(PW, NOW);
        let (_, mac) = token.split_once('.').expect("well formed");
        let forged = format!("{}.{mac}", NOW + 10 * SESSION_SECS);
        assert_eq!(verify(&forged, PW, NOW), Err(AuthError::Invalid));
    }

    #[test]
    fn malformed_tokens_are_refused_without_panicking() {
        for bad in ["", ".", "abc", "abc.def", "1785100000", "1785100000.", ".deadbeef", "x.y"] {
            assert!(verify(bad, PW, NOW).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_unconfigured_password_closes_the_panel_rather_than_opening_it() {
        // The failure mode that matters: a deployment with no password set
        // must not have an open admin panel.
        assert_eq!(verify(&issue("", NOW), "", NOW), Err(AuthError::NotConfigured));
        assert!(!password_matches("", ""));
        assert!(!password_matches("anything", ""));
    }

    #[test]
    fn password_comparison_accepts_only_the_configured_value() {
        assert!(password_matches(PW, PW));
        assert!(!password_matches("Correct horse battery staple", PW));
        assert!(!password_matches(&PW[..PW.len() - 1], PW));
        assert!(!password_matches(&format!("{PW}x"), PW));
    }

    #[test]
    fn the_cookie_is_found_among_others_and_not_by_prefix() {
        assert_eq!(token_from_cookies(&format!("{COOKIE}=abc")), Some("abc"));
        assert_eq!(token_from_cookies(&format!("other=1; {COOKIE}=abc; more=2")), Some("abc"));
        assert_eq!(token_from_cookies(&format!(" {COOKIE} = abc ")), Some("abc"));
        // A cookie whose name merely ends with ours must not be accepted.
        assert_eq!(token_from_cookies(&format!("not_{COOKIE}=abc")), None);
        assert_eq!(token_from_cookies("unrelated=1"), None);
        assert_eq!(token_from_cookies(""), None);
    }

    #[test]
    fn the_cookie_carries_the_attributes_that_protect_it() {
        let c = set_cookie("token");
        for attr in ["HttpOnly", "Secure", "SameSite=Strict"] {
            assert!(c.contains(attr), "missing {attr}");
        }
        // The panel prefix is secret; it must not be written into a cookie
        // attribute that the browser then attaches to requests.
        assert!(c.contains("Path=/;"));
        assert!(clear_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn verification_never_panics_on_arbitrary_tokens() {
        let mut seed = 0x2f81_aa31_0e77_1234u64;
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 60) as usize;
            let s: String = (0..len).map(|i| (seed >> (i % 56)) as u8 as char).collect();
            let _ = verify(&s, PW, NOW);
            let _ = token_from_cookies(&s);
        }
    }
}
