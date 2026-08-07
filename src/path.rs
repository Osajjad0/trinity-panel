//! Path prefix matching, in one place.
//!
//! This logic was previously written out three times — twice in the router and
//! once inside the XHTTP classifier — and only one of the three guarded the
//! empty-prefix case. That divergence was a real hole: with `XHTTP_PATH`
//! unset or set to `/`, the classifier's copy matched **every** path, so an
//! unconfigured deployment routed essentially every request to a Durable
//! Object instead of to the decoy page.
//!
//! Matching on a component boundary is the whole point. A prefix of `/api`
//! must match `/api` and `/api/x` but never `/apifoo`, or a route leaks onto
//! unrelated URLs.

/// Strip `prefix` from `path`, requiring a component boundary.
///
/// Returns the remainder with any leading slash removed, or `None` when the
/// prefix does not cover the path.
///
/// An empty prefix matches **nothing**. Treating it as matching everything is
/// the natural reading of `strip_prefix("")`, and it is exactly wrong here: an
/// operator who has not configured a route should expose no route at all,
/// rather than every route.
#[must_use]
pub fn strip<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return None;
    }
    let rest = path.strip_prefix(prefix)?;
    match rest.as_bytes().first() {
        None => Some(""),
        Some(b'/') => Some(&rest[1..]),
        // Matched as a substring, not as a path component.
        Some(_) => None,
    }
}

/// Whether `prefix` covers `path` on a component boundary.
#[must_use]
pub fn covers(prefix: &str, path: &str) -> bool {
    strip(path, prefix).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_on_component_boundaries_only() {
        assert_eq!(strip("/api", "/api"), Some(""));
        assert_eq!(strip("/api/x/y", "/api"), Some("x/y"));
        assert_eq!(strip("/api/", "/api"), Some(""));
        assert_eq!(strip("/apifoo", "/api"), None);
        assert_eq!(strip("/ap", "/api"), None);
        assert_eq!(strip("/other", "/api"), None);
    }

    #[test]
    fn tolerates_a_trailing_slash_on_the_configured_prefix() {
        assert_eq!(strip("/api/x", "/api/"), Some("x"));
        assert_eq!(strip("/api", "/api/"), Some(""));
    }

    #[test]
    fn an_empty_prefix_matches_nothing() {
        // The bug this module exists to prevent: an unconfigured deployment
        // must expose no route, not every route.
        for prefix in ["", "/", "//", "   ".trim_end_matches('/')] {
            for path in ["/", "/anything", "/a/b/c", ""] {
                assert_eq!(strip(path, prefix), None, "prefix {prefix:?} path {path:?}");
            }
        }
        assert!(!covers("", "/anything"));
        assert!(!covers("/", "/anything"));
    }

    #[test]
    fn covers_agrees_with_strip() {
        for (prefix, path) in [
            ("/api", "/api/x"),
            ("/api", "/apifoo"),
            ("", "/api"),
            ("/x", "/x"),
        ] {
            assert_eq!(covers(prefix, path), strip(path, prefix).is_some());
        }
    }

    #[test]
    fn never_panics() {
        let mut seed = 0x51ed_2701_u64;
        let alphabet = b"/api._%\0 ";
        for _ in 0..3000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mk = |n: usize| -> String {
                (0..n)
                    .map(|i| alphabet[((seed >> (i % 56)) as usize) % alphabet.len()] as char)
                    .collect()
            };
            let p = mk((seed % 12) as usize);
            let q = mk((seed % 7) as usize);
            let _ = strip(&p, &q);
            let _ = covers(&q, &p);
        }
    }
}
