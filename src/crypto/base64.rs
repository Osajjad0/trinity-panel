//! Base64 decoding.
//!
//! Only decoding lives here. The share-link encoder is in
//! [`crate::subscription::encode`] because it needs the URL-safe, unpadded
//! variants that belong to that format; this is the plain RFC 4648 alphabet a
//! Shadowsocks-2022 pre-shared key is written in.
//!
//! Written out rather than taken from a crate for the same reason as BLAKE3:
//! this toolchain cannot link any dependency whose build script pulls in a C
//! compiler, and a base64 decoder is thirty lines.

/// Decode standard base64, with or without `=` padding.
///
/// Returns `None` for any input that is not valid base64 rather than decoding
/// as much as it can. A partially-decoded key would be a key of the wrong
/// length, which is far better rejected here than used.
///
/// Whitespace is skipped, because a value pasted from a panel or a config file
/// routinely carries a stray newline and failing on that helps nobody.
#[must_use]
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut chars = 0usize;
    let mut padded = false;

    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        // Padding contributes no bits and ends the data. Anything other than
        // more padding after it means the input is not a valid encoding, and
        // decoding the prefix anyway would silently yield a shorter key.
        if byte == b'=' {
            padded = true;
            continue;
        }
        if padded {
            return None;
        }
        chars += 1;
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Truncation is intended: the low 8 bits are the decoded byte.
            #[allow(clippy::cast_possible_truncation)]
            out.push((acc >> bits) as u8);
        }
    }

    // A well-formed encoding leaves fewer than 8 bits, and those must be zero.
    // Anything else means the input was truncated mid-character.
    if bits >= 8 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    // A final group of one character encodes nothing, and padding with no data
    // before it is not an encoding of the empty string.
    if chars % 4 == 1 || (padded && chars == 0) {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_rfc_4648_test_vectors() {
        // The published vectors, so this is checked against the standard rather
        // than against its own encoder.
        for (encoded, want) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(decode(encoded).as_deref(), Some(want.as_bytes()), "{encoded:?}");
        }
    }

    #[test]
    fn accepts_a_key_sized_value_at_both_lengths() {
        // The two lengths Shadowsocks-2022 uses.
        assert_eq!(decode("AAAAAAAAAAAAAAAAAAAAAA==").map(|v| v.len()), Some(16));
        assert_eq!(
            decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").map(|v| v.len()),
            Some(32)
        );
    }

    #[test]
    fn padding_is_optional() {
        assert_eq!(decode("Zg"), decode("Zg=="));
        assert_eq!(decode("Zm8"), decode("Zm8="));
    }

    #[test]
    fn whitespace_from_a_paste_is_tolerated() {
        assert_eq!(decode(" Zm9v YmFy \n").as_deref(), Some(&b"foobar"[..]));
    }

    #[test]
    fn rejects_rather_than_salvages_bad_input() {
        // A partial decode would produce a key of the wrong length, which is
        // exactly the failure this must not turn into.
        for bad in ["Zm9v!", "Z", "a b c #", "====", "Zg=x"] {
            assert_eq!(decode(bad), None, "{bad:?} must be rejected");
        }
    }

    #[test]
    fn rejects_non_zero_leftover_bits() {
        // "Zh" decodes 'f' with two bits left over that are not zero, so it is
        // not a valid encoding of anything.
        assert_eq!(decode("Zh"), None);
    }

    #[test]
    fn round_trips_against_the_independent_encoder() {
        // Cross-checks the two directions, which were written separately.
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let encoded = crate::subscription::encode::base64(&data);
            assert_eq!(decode(&encoded).as_deref(), Some(&data[..]), "len {len}");
        }
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut seed = 0x51ed_2701_abcd_1234u64;
        for _ in 0..4000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 60) as usize;
            let s: String = (0..len).map(|i| (seed >> (i % 56)) as u8 as char).collect();
            let _ = decode(&s);
        }
    }
}
