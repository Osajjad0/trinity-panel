//! Encoding primitives for share links.
//!
//! Hand-written rather than pulled from crates, for three reasons: both are
//! small enough to read in one sitting, every kilobyte of WASM is paid on each
//! cold start, and this project already discovered that a dependency with a
//! C-building build script cannot link on the target toolchain. Fewer moving
//! parts is worth more here than reusing something familiar.
//!
//! Correctness is checked against published vectors (RFC 4648) rather than
//! against itself.

/// Standard base64 alphabet, with padding. Used by `vmess://`.
const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// URL-safe alphabet, no padding. Used by `ss://` under SIP002.
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_with(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for group in input.chunks(3) {
        // Assemble up to three bytes into a 24-bit accumulator, then peel off
        // four 6-bit indices. Missing bytes contribute zero bits, which is
        // exactly what the padding rules require.
        let b0 = u32::from(group[0]);
        let b1 = group.get(1).copied().map_or(0, u32::from);
        let b2 = group.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);

        if group.len() > 1 {
            out.push(alphabet[((n >> 6) & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }

        if group.len() > 2 {
            out.push(alphabet[(n & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// Standard base64 with padding.
#[must_use]
pub fn base64(input: &[u8]) -> String {
    encode_with(input, STD, true)
}

/// URL-safe base64 without padding, as SIP002 requires for `ss://` userinfo.
#[must_use]
pub fn base64_url_nopad(input: &[u8]) -> String {
    encode_with(input, URL_SAFE, false)
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
///
/// Deliberately conservative: it escapes `/`, `:` and `?` too. Those are legal
/// in some query positions and not others, and the cost of over-escaping is
/// nil — every client decodes it back — while under-escaping produces a link
/// that silently truncates at the first stray delimiter. A path containing a
/// `#` is the classic case: unescaped, everything after it becomes the
/// fragment and the node points somewhere else entirely.
#[must_use]
pub fn percent(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 0x0f)] as char);
        }
    }
    out
}

/// Encode a URI fragment (the part after `#`), used for the node label.
///
/// Spaces are common in node names and must not survive raw.
#[must_use]
pub fn fragment(input: &str) -> String {
    percent(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // Section 10 of RFC 4648, verbatim.
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want, "input {input:?}");
        }
    }

    #[test]
    fn url_safe_variant_uses_the_right_alphabet_and_omits_padding() {
        // 0xfb 0xff produces '+' and '/' under the standard alphabet, which is
        // exactly the pair that must become '-' and '_' here.
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
        assert_eq!(base64_url_nopad(&[0xfb, 0xff]), "-_8");
        assert!(!base64_url_nopad(b"f").contains('='), "SIP002 forbids padding");
    }

    #[test]
    fn base64_round_trips_through_a_reference_decoder() {
        // Decode with an independent implementation so a symmetric bug in the
        // encoder cannot hide.
        fn decode_std(s: &str) -> Vec<u8> {
            let mut acc: u32 = 0;
            let mut bits = 0u32;
            let mut out = Vec::new();
            for c in s.bytes().filter(|&c| c != b'=') {
                let v = STD.iter().position(|&x| x == c).unwrap_or(0) as u32;
                acc = (acc << 6) | v;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((acc >> bits) as u8);
                }
            }
            out
        }

        let mut seed = 0x1357_9bdf_2468_ace0u64;
        for _ in 0..500 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 64) as usize;
            let data: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            assert_eq!(decode_std(&base64(&data)), data, "round trip failed");
        }
    }

    #[test]
    fn percent_leaves_unreserved_characters_alone() {
        assert_eq!(percent("aZ09-._~"), "aZ09-._~");
    }

    #[test]
    fn percent_escapes_delimiters_that_would_truncate_a_link() {
        // A '#' in a path is the classic failure: unescaped, everything after
        // it becomes the fragment and the node silently points elsewhere.
        assert_eq!(percent("/a#b"), "%2Fa%23b");
        assert_eq!(percent("a b"), "a%20b");
        assert_eq!(percent("k=v&x=y"), "k%3Dv%26x%3Dy");
        assert_eq!(percent("?q"), "%3Fq");
        assert_eq!(percent("a:b"), "a%3Ab");
    }

    #[test]
    fn percent_handles_multibyte_utf8_bytewise() {
        // Node labels are frequently non-Latin; each UTF-8 byte is escaped.
        assert_eq!(percent("é"), "%C3%A9");
        assert_eq!(percent("日"), "%E6%97%A5");
    }

    #[test]
    fn encoders_never_panic() {
        let mut seed = 0xfeed_face_dead_beefu64;
        for _ in 0..2000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 48) as usize;
            let data: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            let _ = base64(&data);
            let _ = base64_url_nopad(&data);
            let s = String::from_utf8_lossy(&data);
            let _ = percent(&s);
        }
    }
}
