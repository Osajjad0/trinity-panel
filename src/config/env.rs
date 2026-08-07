//! Reading credentials out of environment bindings.
//!
//! Kept separate from the runtime so it can be tested on the host: parsing a
//! user list is exactly the kind of thing that silently does the wrong thing
//! with whitespace or a trailing comma, and a mistake here locks every user
//! out of a deployment or — worse — quietly accepts nobody while appearing
//! configured.

use crate::protocol::{shadowsocks, trojan, uuid, vmess, Credentials};

/// The raw binding values, one per protocol.
///
/// A struct rather than three `&str` parameters because "VLESS" and "VMess"
/// differ by one letter and take the same kind of value — a list of UUIDs.
/// Positionally, swapping them compiles, passes every type check, and produces
/// a deployment where each protocol authenticates the other's users. Named
/// fields make that mistake visible at the call site.
///
/// Generic over the string type so a caller reading from the environment can
/// hand over the `String`s it just built, rather than binding three temporaries
/// to borrow from — bindings that would themselves be one letter apart.
#[derive(Debug, Default, Clone, Copy)]
pub struct UserLists<S> {
    pub vless: S,
    pub trojan: S,
    pub vmess: S,
    /// Entries are `method:base64-key`, because Shadowsocks-2022 needs both and
    /// the key length is only valid against a particular method. Self-describing
    /// entries also mean adding a second binding is unnecessary.
    pub shadowsocks: S,
}

/// Build a credential set from binding values.
///
/// Malformed entries are skipped rather than poisoning the whole list. An
/// operator who pastes one bad UUID among five should lose that one user, not
/// all of them — and a hard failure here would take a working deployment down
/// on a typo.
///
/// An empty list for a protocol disables that protocol entirely, which is how
/// a protocol is turned off.
#[must_use]
pub fn credentials_from_env<S: AsRef<str>>(lists: &UserLists<S>) -> Credentials {
    Credentials {
        vless: split_list(lists.vless.as_ref()).filter_map(|s| uuid::parse(s).ok()).collect(),
        trojan: split_list(lists.trojan.as_ref()).map(trojan::key_for).collect(),
        // Derived once here rather than per request: the KDF behind
        // `credential_for` is a chain of HMACs, and doing it on the hot path
        // would put it in front of every unauthenticated byte that arrives.
        vmess: split_list(lists.vmess.as_ref())
            .filter_map(|s| uuid::parse(s).ok())
            .map(|u| vmess::credential_for(&u))
            .collect(),
        // A mismatched key length is rejected here rather than at connection
        // time, where it surfaces from inside a vendored library with a message
        // that points nowhere near the configuration that caused it.
        shadowsocks: split_list(lists.shadowsocks.as_ref())
            .filter_map(|entry| {
                let (method, key) = entry.split_once(':')?;
                shadowsocks::Credential::new(method, key)
            })
            .collect(),
    }
}

/// Split a binding value into non-empty, trimmed entries.
///
/// Accepts commas, newlines and semicolons, because a value pasted from a
/// panel textarea is as likely to be newline-separated as comma-separated and
/// there is nothing to gain from being strict about it.
fn split_list(raw: &str) -> impl Iterator<Item = &str> {
    raw.split([',', '\n', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const B: &str = "fedcba98-7654-3210-fedc-ba9876543210";

    #[test]
    fn parses_a_simple_list() {
        let both = format!("{A},{B}");
        let c =
            credentials_from_env(&UserLists { vless: both.as_str(), trojan: "pw1,pw2", vmess: A, shadowsocks: "" });
        assert_eq!(c.vless.len(), 2);
        assert_eq!(c.trojan.len(), 2);
        assert_eq!(c.vmess.len(), 1);
        assert!(!c.is_empty());
    }

    #[test]
    fn tolerates_whitespace_newlines_and_trailing_separators() {
        // What a panel textarea actually produces.
        let messy = format!("  {A} ,\n {B} ,\n");
        let c = credentials_from_env(&UserLists {
            vless: messy.as_str(),
            trojan: " pw1 ;\n pw2 \n",
            vmess: messy.as_str(),
            shadowsocks: "",
        });
        assert_eq!(c.vless.len(), 2);
        assert_eq!(c.trojan.len(), 2);
        assert_eq!(c.vmess.len(), 2);
    }

    #[test]
    fn one_bad_entry_does_not_lock_everyone_out() {
        let mixed = format!("{A},not-a-uuid,{B}");
        let c = credentials_from_env(&UserLists {
            vless: mixed.as_str(),
            trojan: "",
            vmess: mixed.as_str(),
            shadowsocks: "",
        });
        assert_eq!(c.vless.len(), 2, "the two valid UUIDs must survive");
        assert_eq!(c.vmess.len(), 2, "the same tolerance applies to VMess");
    }

    #[test]
    fn an_empty_binding_disables_that_protocol() {
        let c = credentials_from_env(&UserLists { vless: A, ..Default::default() });
        assert_eq!(c.vless.len(), 1);
        assert!(c.trojan.is_empty());
        assert!(c.vmess.is_empty());

        let none = credentials_from_env(&UserLists::<&str>::default());
        assert!(none.is_empty(), "a deployment with no credentials accepts nothing");
    }

    #[test]
    fn vmess_alone_is_enough_to_be_configured() {
        // `is_empty` gates whether the deployment serves anything at all, so
        // omitting a protocol from it would silently disable that protocol.
        let c = credentials_from_env(&UserLists { vmess: A, ..Default::default() });
        assert!(!c.is_empty());
        assert_eq!(c.vmess.len(), 1);
    }

    #[test]
    fn each_protocol_reads_only_its_own_binding() {
        // The mistake the struct exists to prevent: one UUID list must not
        // leak into a second protocol's credential table.
        let c = credentials_from_env(&UserLists { vless: A, trojan: "", vmess: B, shadowsocks: "" });
        assert_eq!(c.vless.len(), 1);
        assert_eq!(c.vmess.len(), 1);
        // Distinct UUIDs must yield distinct VMess key material.
        let other = credentials_from_env(&UserLists { vmess: A, ..Default::default() });
        assert_ne!(c.vmess[0], other.vmess[0]);
    }

    #[test]
    fn trojan_passwords_are_hashed_not_stored_raw() {
        let c = credentials_from_env(&UserLists { trojan: "hunter2", ..Default::default() });
        assert_eq!(c.trojan[0], trojan::key_for("hunter2"));
        // The wire key is the hex digest, never the password itself.
        assert_ne!(&c.trojan[0][..7], b"hunter2");
    }

    #[test]
    fn never_panics_on_hostile_binding_values() {
        for raw in ["", ",,,", "\n\n", ";", "\u{0}", "a".repeat(10_000).as_str(), "é,日本語"] {
            let _ = credentials_from_env(&UserLists { vless: raw, trojan: raw, vmess: raw, shadowsocks: raw });
        }
    }
}
