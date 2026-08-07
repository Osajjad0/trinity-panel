//! UUID parsing, shared by VLESS and VMess.
//!
//! This is a deliberate 40-line replacement for the `uuid` crate. That crate
//! pulls in formatting and error machinery for a job that is one hex decode,
//! and every kilobyte of WASM is paid on each cold start. Nothing here
//! allocates or panics.

use super::ProtocolError;

/// A parsed 128-bit user identifier.
pub type Uuid = [u8; 16];

/// Parse the canonical `8-4-4-4-12` hyphenated form, case-insensitively.
///
/// Also accepts the 32-character unhyphenated form, because several clients
/// emit it and rejecting them produces a failure that looks like bad
/// credentials rather than a formatting problem.
///
/// # Errors
/// Returns [`ProtocolError::MalformedAddress`] for any input that is not a
/// well-formed UUID. Config parsing is the only caller, so the error variant
/// matters less than the fact that it cannot panic on user input.
pub fn parse(s: &str) -> Result<Uuid, ProtocolError> {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let mut nibbles = 0usize;
    let mut hi: Option<u8> = None;

    for &c in b {
        if c == b'-' {
            continue;
        }
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return Err(ProtocolError::MalformedAddress),
        };
        match hi {
            None => hi = Some(v),
            Some(h) => {
                if nibbles >= 16 {
                    return Err(ProtocolError::MalformedAddress);
                }
                out[nibbles] = (h << 4) | v;
                nibbles += 1;
                hi = None;
            }
        }
    }

    if nibbles != 16 || hi.is_some() {
        return Err(ProtocolError::MalformedAddress);
    }
    Ok(out)
}

/// Render as the canonical lowercase hyphenated form.
///
/// Used when emitting subscriptions, never on the relay path.
#[must_use]
pub fn format(u: &Uuid) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(36);
    for (i, byte) in u.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(HEX[usize::from(byte >> 4)] as char);
        s.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANON: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const BYTES: Uuid = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];

    #[test]
    fn parses_canonical_form() {
        assert_eq!(parse(CANON), Ok(BYTES));
    }

    #[test]
    fn parse_is_case_insensitive_and_hyphen_optional() {
        assert_eq!(parse("0123456789ABCDEF0123456789ABCDEF"), Ok(BYTES));
        assert_eq!(parse(&CANON.to_uppercase()), Ok(BYTES));
    }

    #[test]
    fn round_trips() {
        assert_eq!(format(&BYTES), CANON);
        assert_eq!(parse(&format(&BYTES)), Ok(BYTES));
    }

    #[test]
    fn rejects_malformed_without_panicking() {
        for bad in [
            "",
            "not-a-uuid",
            "0123456789abcdef0123456789abcde",   // 31 nibbles
            "0123456789abcdef0123456789abcdef0", // 33 nibbles
            "0123456789abcdef0123456789abcdeg",  // bad hex digit
            "----------------------------------",
        ] {
            assert!(parse(bad).is_err(), "should reject {bad:?}");
        }
    }
}
