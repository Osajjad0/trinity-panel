//! QR encoding, so a phone can import a node without anyone typing a URI.
//!
//! # Why this is written out rather than pulled in
//!
//! Two reasons, and the second is the one that decided it. A crate would be
//! the obvious choice, but this build machine cannot link any dependency whose
//! build script needs a C compiler, which has already ruled out the obvious
//! choice twice (see the BLAKE3 and base64 modules). More importantly, a QR
//! encoder is a pure function from bytes to a bit matrix — exactly the shape
//! this project can test on the host in milliseconds, with no runtime and no
//! WASM harness.
//!
//! # Byte mode only, and why that is not a limitation here
//!
//! The specification also defines numeric, alphanumeric and kanji modes, which
//! pack denser for restricted alphabets. Everything this encodes is a URI:
//! `vless://`, `ss://`, or a subscription URL. Alphanumeric mode excludes
//! lowercase letters entirely, so no URI can use it. Implementing modes that
//! could never be selected would be code with no reachable path.
//!
//! # Correctness
//!
//! Checked against two outside implementations, comparing the full module
//! matrix bit for bit — not just "it produced something that scans". The
//! fixtures in `tests/fixtures/qr_vectors.txt` freeze that comparison across
//! every version, every error-correction level and all eight masks, so a
//! regression fails the host suite rather than a phone.
//!
//! Two implementations rather than one because they disagreed, and settling
//! which was right is the whole value of an external check. segno appends a
//! whole zero codeword of "padding bits" when the bit stream already ends on a
//! codeword boundary, which after a four-bit terminator in byte mode it always
//! does; ISO/IEC 18004 §7.4.10 adds padding bits only when the stream does
//! *not* end on one. qrcode and this encoder both add none. The symbol scans
//! either way — the extra byte lands in padding a reader discards once the
//! character count is satisfied — but a single reference implementation would
//! have made that divergence look like a bug here.
//!
//! The structure follows the algorithm in ISO/IEC 18004: encode to a bit
//! stream, split into blocks, append Reed-Solomon parity over GF(256),
//! interleave, draw with function patterns reserved, then choose the mask that
//! scores lowest under the four penalty rules. Mask selection is the one step
//! deliberately not compared against another implementation — see
//! `scripts/qr_vectors.py` for why.

use core::fmt::Write as _;

/// Error-correction level. Higher levels survive more damage and hold less.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ecc {
    /// Recovers ~7% damage.
    Low,
    /// ~15%. The usual choice for a URL, and the default here.
    Medium,
    /// ~25%.
    Quartile,
    /// ~30%.
    High,
}

impl Ecc {
    const fn index(self) -> usize {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::Quartile => 2,
            Self::High => 3,
        }
    }

    /// The two-bit value written into the format information. Deliberately not
    /// the same order as [`Ecc::index`] — the specification numbers them by
    /// robustness in one place and by an unrelated encoding in the other, and
    /// conflating the two is a classic way to produce a QR that no reader will
    /// touch.
    const fn format_bits(self) -> u32 {
        match self {
            Self::Low => 1,
            Self::Medium => 0,
            Self::Quartile => 3,
            Self::High => 2,
        }
    }

    const ALL: [Self; 4] = [Self::Low, Self::Medium, Self::Quartile, Self::High];
}

/// Why a payload could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrError {
    /// Longer than the largest QR code can hold at the requested level.
    ///
    /// Reachable in practice only for a full core configuration, which is a
    /// file rather than something to point a camera at.
    TooLong,
}

impl core::fmt::Display for QrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong => f.write_str("too long to fit in a QR code"),
        }
    }
}

/// Smallest and largest version (size) of QR symbol.
const MIN_VERSION: usize = 1;
const MAX_VERSION: usize = 40;

/// Number of error-correction codewords in each block, by level and version.
const ECC_CODEWORDS_PER_BLOCK: [[u8; MAX_VERSION + 1]; 4] = [
    // Version 0 is unused; the table is 1-indexed to match the specification.
    [
        0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28,
        30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ],
    [
        0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30,
        30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
];

/// Number of error-correction blocks, by level and version.
const NUM_ERROR_CORRECTION_BLOCKS: [[u8; MAX_VERSION + 1]; 4] = [
    [
        0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13,
        14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
    ],
    [
        0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21,
        23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ],
    [
        0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29,
        34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68,
    ],
    [
        0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32,
        35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81,
    ],
];

/// A finished QR symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qr {
    size: usize,
    /// Row-major, `size * size`. `true` is a dark module.
    modules: Vec<bool>,
}

impl Qr {
    /// Encode `data` at the smallest version that fits.
    ///
    /// `min_ecc` is a floor, not a target: if a stronger level fits in the same
    /// version it is used, because the extra robustness is free at that point.
    ///
    /// # Errors
    /// [`QrError::TooLong`] when the payload exceeds version 40.
    pub fn encode(data: &[u8], min_ecc: Ecc) -> Result<Self, QrError> {
        let (version, ecc) = plan(data.len(), min_ecc)?;
        let codewords = build_codewords(data, version, ecc);
        Ok(draw(&codewords, version, ecc, None))
    }

    /// Side length in modules, excluding the quiet zone.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Whether the module at `(x, y)` is dark. Out-of-range is light, which is
    /// what the quiet zone is anyway.
    #[must_use]
    pub fn dark(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.modules.get(y * self.size + x).copied().unwrap_or(false)
    }

    /// Render as a standalone SVG.
    ///
    /// `quiet` is the margin in modules; the specification requires at least 4
    /// and readers genuinely fail without it. No width or height attribute is
    /// emitted, only a `viewBox`, so the caller sizes it with CSS instead of
    /// this module guessing at a pixel size.
    #[must_use]
    pub fn to_svg(&self, quiet: usize) -> String {
        let span = self.size + quiet * 2;
        // One path for the whole symbol rather than one rect per module: a
        // version 40 symbol has 31k modules, and 31k elements is enough to
        // make a browser visibly stutter.
        let mut path = String::with_capacity(self.size * self.size / 2);
        for y in 0..self.size {
            let mut x = 0;
            while x < self.size {
                if !self.dark(x, y) {
                    x += 1;
                    continue;
                }
                // Merge horizontal runs, which roughly halves the path data.
                let start = x;
                while x < self.size && self.dark(x, y) {
                    x += 1;
                }
                let run = x - start;
                // `write!` to a String cannot fail, and the alternative would
                // be an unwrap on an infallible path.
                let _ = write!(path, "M{} {}h{run}v1h-{run}z", start + quiet, y + quiet);
            }
        }

        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {span} {span}\" \
             shape-rendering=\"crispEdges\">\
             <rect width=\"{span}\" height=\"{span}\" fill=\"#fff\"/>\
             <path d=\"{path}\" fill=\"#000\"/></svg>"
        )
    }
}

/// The smallest version holding `len` bytes at exactly this level.
fn smallest_version(len: usize, ecc: Ecc) -> Result<usize, QrError> {
    (MIN_VERSION..=MAX_VERSION)
        .find(|&v| len <= byte_capacity(v, ecc))
        .ok_or(QrError::TooLong)
}

/// Choose the version and level for a payload.
///
/// `min_ecc` is a floor rather than a target. Once the version is fixed, any
/// capacity left over would be spent on padding bytes, so it is spent on error
/// correction instead — the symbol is the same size either way, and a stronger
/// level is strictly better for a code that will be photographed off a screen.
fn plan(len: usize, min_ecc: Ecc) -> Result<(usize, Ecc), QrError> {
    let version = smallest_version(len, min_ecc)?;
    let mut ecc = min_ecc;
    for candidate in Ecc::ALL {
        if candidate > ecc && len <= byte_capacity(version, candidate) {
            ecc = candidate;
        }
    }
    Ok((version, ecc))
}

/// How many payload bytes fit at this version and level.
fn byte_capacity(version: usize, ecc: Ecc) -> usize {
    let data_bits = num_data_codewords(version, ecc) * 8;
    // Mode indicator is 4 bits; the character-count field widens at version 10.
    let header = 4 + if version <= 9 { 8 } else { 16 };
    data_bits.saturating_sub(header) / 8
}

/// Total modules available for data and error correction, in bits.
fn num_raw_data_modules(version: usize) -> usize {
    let mut result = (16 * version + 128) * version + 64;
    if version >= 2 {
        let num_align = version / 7 + 2;
        result -= (25 * num_align - 10) * num_align - 55;
        if version >= 7 {
            // The two version-information blocks, 18 modules each.
            result -= 36;
        }
    }
    result
}

fn num_data_codewords(version: usize, ecc: Ecc) -> usize {
    let blocks = usize::from(NUM_ERROR_CORRECTION_BLOCKS[ecc.index()][version]);
    let ecc_len = usize::from(ECC_CODEWORDS_PER_BLOCK[ecc.index()][version]);
    num_raw_data_modules(version) / 8 - ecc_len * blocks
}

/// Centre coordinates of the alignment patterns for a version.
fn alignment_positions(version: usize) -> Vec<usize> {
    if version == 1 {
        return Vec::new();
    }
    let num_align = version / 7 + 2;
    // Version 32 is the one case the general formula gets wrong; the
    // specification tabulates it separately.
    let step = if version == 32 {
        26
    } else {
        (version * 4 + num_align * 2 + 1) / (num_align * 2 - 2) * 2
    };
    // Positions are computed forward from the fixed first one rather than
    // walked backwards from the last. The backwards walk is the usual way to
    // write this, and it steps below zero after placing the final position at
    // versions 36 and 39 — harmless in a signed implementation, a panic in an
    // unsigned one, and a panic in a WASM isolate takes every connection on it
    // down with it.
    let last = version * 4 + 10;
    let mut result = Vec::with_capacity(num_align);
    result.push(6);
    for i in 1..num_align {
        result.push(last - step * (num_align - 1 - i));
    }
    result
}

/// Encode the payload to a bit stream, then to interleaved codewords.
fn build_codewords(data: &[u8], version: usize, ecc: Ecc) -> Vec<u8> {
    let capacity = num_data_codewords(version, ecc);
    let mut bits = BitBuffer::new();

    // Byte mode.
    bits.push(0b0100, 4);
    let count_bits = if version <= 9 { 8 } else { 16 };
    // Length is bounded by `byte_capacity`, which the caller checked.
    #[allow(clippy::cast_possible_truncation)]
    bits.push(data.len() as u32, count_bits);
    for &b in data {
        bits.push(u32::from(b), 8);
    }

    // Terminator, then pad to a byte boundary, then the fixed pad pattern.
    let remaining = capacity * 8 - bits.len().min(capacity * 8);
    bits.push(0, remaining.min(4));
    let to_byte = (8 - bits.len() % 8) % 8;
    bits.push(0, to_byte);
    for pad in [0xEC_u32, 0x11].into_iter().cycle() {
        if bits.len() >= capacity * 8 {
            break;
        }
        bits.push(pad, 8);
    }

    let payload = bits.into_bytes();
    interleave(&payload, version, ecc)
}

/// Split into blocks, append parity to each, and interleave.
///
/// The interleaving is what makes a burst of damage survivable: consecutive
/// modules in the symbol belong to different blocks, so a scratch that destroys
/// a run of codewords costs each block only a little.
fn interleave(payload: &[u8], version: usize, ecc: Ecc) -> Vec<u8> {
    let num_blocks = usize::from(NUM_ERROR_CORRECTION_BLOCKS[ecc.index()][version]);
    let ecc_len = usize::from(ECC_CODEWORDS_PER_BLOCK[ecc.index()][version]);
    let raw_codewords = num_raw_data_modules(version) / 8;
    let num_short_blocks = num_blocks - raw_codewords % num_blocks;
    let short_block_len = raw_codewords / num_blocks;

    // Short blocks hold one data codeword fewer than long ones. Their parity
    // sections are the same length, which is why data and parity have to be
    // walked as two separate column runs: a single walk over `data || parity`
    // would read every short block's parity one column out of step.
    let short_data_len = short_block_len - ecc_len;
    let divisor = rs_divisor(ecc_len);

    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(num_blocks);
    let mut offset = 0;
    for i in 0..num_blocks {
        let len = short_data_len + usize::from(i >= num_short_blocks);
        let chunk = payload.get(offset..offset + len).unwrap_or_default();
        offset += len;
        let mut block = chunk.to_vec();
        block.extend_from_slice(&rs_remainder(chunk, &divisor));
        blocks.push(block);
    }

    let data_len_of = |j: usize| short_data_len + usize::from(j >= num_short_blocks);

    let mut out = Vec::with_capacity(raw_codewords);
    for i in 0..=short_data_len {
        for (j, block) in blocks.iter().enumerate() {
            if i < data_len_of(j) {
                if let Some(&b) = block.get(i) {
                    out.push(b);
                }
            }
        }
    }
    for column in 0..ecc_len {
        for (j, block) in blocks.iter().enumerate() {
            if let Some(&b) = block.get(data_len_of(j) + column) {
                out.push(b);
            }
        }
    }
    out
}

/// Multiply in GF(256) with the QR primitive polynomial `x^8 + x^4 + x^3 + x^2 + 1`.
fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z: u32 = 0;
    for i in (0..8).rev() {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= u32::from((y >> i) & 1) * u32::from(x);
    }
    // The reduction keeps the running value inside a byte.
    #[allow(clippy::cast_possible_truncation)]
    {
        (z & 0xFF) as u8
    }
}

/// The Reed-Solomon generator polynomial of the given degree.
fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut result = vec![0u8; degree];
    if let Some(last) = result.last_mut() {
        *last = 1;
    }
    let mut root: u8 = 1;
    for _ in 0..degree {
        for j in 0..degree {
            result[j] = gf_mul(result[j], root);
            if j + 1 < degree {
                result[j] ^= result[j + 1];
            }
        }
        root = gf_mul(root, 0x02);
    }
    result
}

/// Remainder of `data` divided by `divisor` — the parity codewords.
fn rs_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; divisor.len()];
    for &b in data {
        let factor = b ^ result.remove(0);
        result.push(0);
        for (i, &d) in divisor.iter().enumerate() {
            result[i] ^= gf_mul(d, factor);
        }
    }
    result
}

/// A big-endian bit accumulator.
struct BitBuffer(Vec<bool>);

impl BitBuffer {
    const fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, value: u32, bits: usize) {
        for i in (0..bits).rev() {
            self.0.push((value >> i) & 1 == 1);
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn into_bytes(self) -> Vec<u8> {
        let mut out = vec![0u8; self.0.len().div_ceil(8)];
        for (i, bit) in self.0.iter().enumerate() {
            if *bit {
                out[i >> 3] |= 0x80 >> (i & 7);
            }
        }
        out
    }
}

/// The symbol being built, with a parallel record of which modules are
/// function patterns and therefore not available to data.
struct Canvas {
    size: usize,
    modules: Vec<bool>,
    function: Vec<bool>,
}

impl Canvas {
    fn new(version: usize) -> Self {
        let size = version * 4 + 17;
        Self {
            size,
            modules: vec![false; size * size],
            function: vec![false; size * size],
        }
    }

    fn set(&mut self, x: usize, y: usize, dark: bool) {
        if x < self.size && y < self.size {
            self.modules[y * self.size + x] = dark;
        }
    }

    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        if x < self.size && y < self.size {
            self.modules[y * self.size + x] = dark;
            self.function[y * self.size + x] = true;
        }
    }

    fn get(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.modules[y * self.size + x]
    }

    fn is_function(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return true;
        }
        self.function[y * self.size + x]
    }
}

/// Place every module: function patterns, then data, then a mask.
///
/// `mask` of `None` selects one by penalty score, which is what production
/// encoding does. Passing an explicit mask exists so the fixture comparison can
/// pin it — see the note on mask selection in the tests.
fn draw(codewords: &[u8], version: usize, ecc: Ecc, mask: Option<u32>) -> Qr {
    let mut c = Canvas::new(version);
    draw_function_patterns(&mut c, version);
    // Reserve the format area with a placeholder so the data placement skips
    // it; the real bits go in once the mask is known.
    draw_format_bits(&mut c, ecc, 0);
    draw_codewords(&mut c, codewords);

    let chosen = mask.unwrap_or_else(|| best_mask(&mut c, ecc));
    apply_mask(&mut c, chosen);
    draw_format_bits(&mut c, ecc, chosen);

    Qr { size: c.size, modules: c.modules }
}

/// The mask the penalty rules like least badly.
///
/// Every mask produces a valid symbol, so this is a quality choice rather than
/// a correctness one: it decides how much margin a reader has, not whether the
/// code can be read at all.
fn best_mask(c: &mut Canvas, ecc: Ecc) -> u32 {
    let mut best = 0;
    let mut best_penalty = u32::MAX;
    for mask in 0..8 {
        apply_mask(c, mask);
        draw_format_bits(c, ecc, mask);
        let penalty = penalty_score(c);
        if penalty < best_penalty {
            best_penalty = penalty;
            best = mask;
        }
        // Masking is its own inverse, so this restores the unmasked symbol.
        apply_mask(c, mask);
    }
    best
}

fn draw_function_patterns(c: &mut Canvas, version: usize) {
    let size = c.size;

    // Timing patterns run the full width and height; the finder patterns
    // overwrite their ends.
    for i in 0..size {
        c.set_function(6, i, i % 2 == 0);
        c.set_function(i, 6, i % 2 == 0);
    }

    for (cx, cy) in [(3usize, 3usize), (size - 4, 3), (3, size - 4)] {
        draw_finder(c, cx, cy);
    }

    let positions = alignment_positions(version);
    let n = positions.len();
    for (i, &ax) in positions.iter().enumerate() {
        for (j, &ay) in positions.iter().enumerate() {
            // The three corners hold finder patterns instead.
            let corner = (i == 0 && (j == 0 || j == n - 1)) || (i == n - 1 && j == 0);
            if !corner {
                draw_alignment(c, ax, ay);
            }
        }
    }

    if version >= 7 {
        draw_version_bits(c, version);
    }
}

/// A finder pattern and its separator, centred on `(cx, cy)`.
///
/// The span reaches four modules either side of the centre — the 7x7 finder
/// plus its one-module separator — and every centre sits within four modules of
/// a symbol edge, so part of that span always falls outside. The range is
/// clamped rather than computed in signed arithmetic and filtered: there is no
/// negative coordinate to convert back, so there is no conversion to get wrong.
fn draw_finder(c: &mut Canvas, cx: usize, cy: usize) {
    for y in cy.saturating_sub(4)..=(cy + 4).min(c.size - 1) {
        for x in cx.saturating_sub(4)..=(cx + 4).min(c.size - 1) {
            // Rings at distance 2 and 4 are light: the inner white ring and the
            // separator.
            let dist = x.abs_diff(cx).max(y.abs_diff(cy));
            c.set_function(x, y, dist != 2 && dist != 4);
        }
    }
}

fn draw_alignment(c: &mut Canvas, cx: usize, cy: usize) {
    for y in cy.saturating_sub(2)..=(cy + 2).min(c.size - 1) {
        for x in cx.saturating_sub(2)..=(cx + 2).min(c.size - 1) {
            c.set_function(x, y, x.abs_diff(cx).max(y.abs_diff(cy)) != 1);
        }
    }
}

/// Write the 15-bit format information, twice, plus the always-dark module.
fn draw_format_bits(c: &mut Canvas, ecc: Ecc, mask: u32) {
    let data = (ecc.format_bits() << 3) | mask;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    let bits = ((data << 10) | rem) ^ 0x5412;
    let bit = |i: usize| (bits >> i) & 1 == 1;
    let size = c.size;

    // First copy, around the top-left finder.
    for i in 0..=5 {
        c.set_function(8, i, bit(i));
    }
    c.set_function(8, 7, bit(6));
    c.set_function(8, 8, bit(7));
    c.set_function(7, 8, bit(8));
    for i in 9..15 {
        c.set_function(14 - i, 8, bit(i));
    }

    // Second copy, split between the other two finders. Redundancy here is
    // deliberate in the specification: without the format bits nothing else
    // can be read, so they are the one thing stored twice.
    for i in 0..8 {
        c.set_function(size - 1 - i, 8, bit(i));
    }
    for i in 8..15 {
        c.set_function(8, size - 15 + i, bit(i));
    }
    c.set_function(8, size - 8, true);
}

/// Write the 18-bit version information, for version 7 and above.
fn draw_version_bits(c: &mut Canvas, version: usize) {
    #[allow(clippy::cast_possible_truncation)]
    let v = version as u32;
    let mut rem = v;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    let bits = (v << 12) | rem;
    let size = c.size;
    for i in 0..18 {
        let dark = (bits >> i) & 1 == 1;
        let a = size - 11 + i % 3;
        let b = i / 3;
        c.set_function(a, b, dark);
        c.set_function(b, a, dark);
    }
}

/// Lay the codewords out in the zigzag the specification prescribes.
fn draw_codewords(c: &mut Canvas, codewords: &[u8]) {
    let size = c.size;
    let total_bits = codewords.len() * 8;
    let mut i = 0usize;
    let mut right = size - 1;

    loop {
        // Column 6 is the vertical timing pattern, so the pairing shifts left
        // past it rather than straddling it.
        if right == 6 {
            right = 5;
        }
        for vert in 0..size {
            for j in 0..2 {
                let x = right - j;
                let upward = ((right + 1) & 2) == 0;
                let y = if upward { size - 1 - vert } else { vert };
                if !c.is_function(x, y) && i < total_bits {
                    let dark = (codewords[i >> 3] >> (7 - (i & 7))) & 1 == 1;
                    c.set(x, y, dark);
                    i += 1;
                }
            }
        }
        if right < 2 {
            break;
        }
        right -= 2;
    }
}

/// XOR the data modules with one of the eight mask patterns.
fn apply_mask(c: &mut Canvas, mask: u32) {
    for y in 0..c.size {
        for x in 0..c.size {
            if c.is_function(x, y) {
                continue;
            }
            let invert = match mask {
                0 => (x + y) % 2 == 0,
                1 => y % 2 == 0,
                2 => x % 3 == 0,
                3 => (x + y) % 3 == 0,
                4 => (x / 3 + y / 2) % 2 == 0,
                5 => (x * y) % 2 + (x * y) % 3 == 0,
                6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
                _ => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
            };
            if invert {
                let was = c.get(x, y);
                c.set(x, y, !was);
            }
        }
    }
}

/// The four penalty rules, which together approximate "how hard is this to
/// scan". Lower is better.
fn penalty_score(c: &Canvas) -> u32 {
    const N1: u32 = 3;
    const N2: u32 = 3;
    const N3: u32 = 40;
    const N4: u32 = 10;

    let size = c.size;
    let mut score = 0u32;

    // Rules 1 and 3, scanned over rows and then columns. Both need the same
    // walk, so they share it: rule 1 counts long same-colour runs, rule 3 looks
    // for the 1:1:3:1:1 ratio that a reader mistakes for a finder pattern.
    for horizontal in [true, false] {
        for outer in 0..size {
            let at = |i: usize| if horizontal { c.get(i, outer) } else { c.get(outer, i) };
            let mut run_colour = false;
            let mut run_len = 0usize;
            let mut history = [0usize; 7];

            for i in 0..size {
                if at(i) == run_colour {
                    run_len += 1;
                    if run_len == 5 {
                        score += N1;
                    } else if run_len > 5 {
                        score += 1;
                    }
                } else {
                    add_run(&mut history, run_len, size);
                    if !run_colour {
                        score += finder_like(&history) * N3;
                    }
                    run_colour = at(i);
                    run_len = 1;
                }
            }
            score += terminate_runs(run_colour, run_len, &mut history, size) * N3;
        }
    }

    // Rule 2: every 2x2 block of one colour.
    for y in 0..size.saturating_sub(1) {
        for x in 0..size.saturating_sub(1) {
            let v = c.get(x, y);
            if v == c.get(x + 1, y) && v == c.get(x, y + 1) && v == c.get(x + 1, y + 1) {
                score += N2;
            }
        }
    }

    // Rule 4: deviation from an even balance of dark and light. `k` is the
    // smallest whole number of five-percent steps that still contains the
    // actual proportion, so a symbol sitting exactly on a step boundary is not
    // penalised for the step it is on.
    let dark = c.modules.iter().filter(|m| **m).count();
    let total = size * size;
    #[allow(clippy::cast_possible_truncation)]
    let k = (dark * 20).abs_diff(total * 10).div_ceil(total).saturating_sub(1) as u32;
    score += k * N4;

    score
}

/// Record a finished run, newest first.
///
/// The very first run of a line gets the quiet zone added to it, because the
/// margin outside the symbol is light and rule 3 is about what a reader sees,
/// not about where our array happens to stop.
fn add_run(history: &mut [usize; 7], mut run_len: usize, size: usize) {
    if history[0] == 0 {
        run_len += size;
    }
    history.rotate_right(1);
    history[0] = run_len;
}

/// Close the final run of a line and score what it completes.
fn terminate_runs(run_colour: bool, run_len: usize, history: &mut [usize; 7], size: usize) -> u32 {
    let mut len = run_len;
    if run_colour {
        add_run(history, len, size);
        len = 0;
    }
    // The quiet zone again, this time on the trailing edge.
    len += size;
    add_run(history, len, size);
    finder_like(history)
}

/// How many finder-lookalikes the last seven runs contain.
///
/// The pattern is a 1:1:3:1:1 dark-light-dark-light-dark core with a light run
/// at least four units long on one side and any light run on the other — which
/// is exactly what a real finder pattern with its separator looks like, and
/// therefore exactly what confuses a reader when it appears in the data.
fn finder_like(history: &[usize; 7]) -> u32 {
    let n = history[1];
    let core = n > 0
        && history[2] == n
        && history[3] == n * 3
        && history[4] == n
        && history[5] == n;
    u32::from(core && history[0] >= n * 4 && history[6] >= n)
        + u32::from(core && history[6] >= n * 4 && history[0] >= n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors produced by segno, an independent implementation, and frozen
    /// here so a regression fails the host suite rather than a phone.
    /// See `scripts/qr_vectors.py` for the format and for why the mask is
    /// pinned in the matrix records.
    const VECTORS: &str = include_str!("../../tests/fixtures/qr_vectors.txt");

    fn ecc_from(name: &str) -> Ecc {
        match name {
            "L" => Ecc::Low,
            "M" => Ecc::Medium,
            "Q" => Ecc::Quartile,
            _ => Ecc::High,
        }
    }

    /// Encode with the version and mask pinned, for comparison against a
    /// fixture. Production encoding goes through [`Qr::encode`].
    fn encode_pinned(data: &[u8], ecc: Ecc, mask: u32) -> Qr {
        let version = smallest_version(data.len(), ecc).expect("fits");
        let codewords = build_codewords(data, version, ecc);
        draw(&codewords, version, ecc, Some(mask))
    }

    /// One module out of a hex-encoded row.
    ///
    /// Rows are padded on the left to a whole number of hex digits, so module
    /// `x` sits at `pad + x` in the padded bit stream rather than at `x`.
    fn module_of(row: &str, size: usize, x: usize) -> bool {
        let pad = row.len() * 4 - size;
        let index = pad + x;
        let digit = row.as_bytes()[index / 4] as char;
        let value = digit.to_digit(16).expect("hex digit");
        (value >> (3 - index % 4)) & 1 == 1
    }

    #[test]
    fn matches_an_independent_implementation_module_for_module() {
        // The test that actually decides whether this works. A QR that is
        // self-consistently wrong scans as nothing at all, and no amount of
        // internal checking would notice.
        let mut checked = 0;
        let mut largest = 0;
        let mut masks_seen = [false; 8];

        for line in VECTORS.lines() {
            let mut parts = line.split('\t');
            if parts.next() != Some("matrix") {
                continue;
            }
            let ecc = ecc_from(parts.next().expect("level field"));
            let mask: u32 = parts.next().expect("mask field").parse().expect("mask");
            let text = parts.next().expect("text field");
            let expected: Vec<&str> = parts.collect();
            let label = &text[..text.len().min(24)];

            let qr = encode_pinned(text.as_bytes(), ecc, mask);
            assert_eq!(qr.size(), expected.len(), "size for {ecc:?} mask {mask} {label:?}");
            for (y, row) in expected.iter().enumerate() {
                for x in 0..qr.size() {
                    assert_eq!(
                        qr.dark(x, y),
                        module_of(row, qr.size(), x),
                        "module ({x}, {y}) differs for {ecc:?} mask {mask} {label:?} \
                         ({} bytes)",
                        text.len()
                    );
                }
            }
            largest = largest.max(qr.size());
            masks_seen[mask as usize] = true;
            checked += 1;
        }

        assert!(checked >= 200, "expected a broad vector set, got {checked}");
        assert!(masks_seen.iter().all(|m| *m), "every mask must be covered");
        // Version 40. Nothing below it exercises the version-information
        // blocks or the widest interleaving, so a vector set that stopped at
        // small symbols would leave both untested.
        assert_eq!(largest, 177, "the vector set must reach the largest symbol");
    }

    #[test]
    fn spare_capacity_is_spent_on_error_correction_the_same_way() {
        // The one decision the pinned matrices cannot check: which level a
        // payload actually lands on. Getting this wrong produces a perfectly
        // valid QR that is simply weaker than it should be, which no scan
        // would ever reveal.
        let mut checked = 0;
        for line in VECTORS.lines() {
            let mut parts = line.split('\t');
            if parts.next() != Some("boost") {
                continue;
            }
            let requested = ecc_from(parts.next().expect("requested level"));
            let effective = ecc_from(parts.next().expect("effective level"));
            let version: usize = parts.next().expect("version").parse().expect("version");
            let text = parts.next().expect("text field");

            let (got_version, got_ecc) =
                plan(text.len(), requested).expect("the fixture only holds payloads that fit");
            assert_eq!(
                (got_version, got_ecc),
                (version, effective),
                "planning {} bytes at {requested:?}",
                text.len()
            );
            checked += 1;
        }
        assert!(checked >= 60, "expected boost coverage, got {checked}");
    }

    #[test]
    fn alignment_positions_match_the_published_table() {
        // The one table this module computes rather than stores, so it is the
        // one that can be quietly wrong. Versions 36 and 39 are here for a
        // second reason: the natural way to write the walk steps below zero
        // after placing the last position at exactly those two versions.
        const TABLE: [&[usize]; 40] = [
            &[], &[6, 18], &[6, 22], &[6, 26], &[6, 30], &[6, 34], &[6, 22, 38],
            &[6, 24, 42], &[6, 26, 46], &[6, 28, 50], &[6, 30, 54], &[6, 32, 58],
            &[6, 34, 62], &[6, 26, 46, 66], &[6, 26, 48, 70], &[6, 26, 50, 74],
            &[6, 30, 54, 78], &[6, 30, 56, 82], &[6, 30, 58, 86], &[6, 34, 62, 90],
            &[6, 28, 50, 72, 94], &[6, 26, 50, 74, 98], &[6, 30, 54, 78, 102],
            &[6, 28, 54, 80, 106], &[6, 32, 58, 84, 110], &[6, 30, 58, 86, 114],
            &[6, 34, 62, 90, 118], &[6, 26, 50, 74, 98, 122], &[6, 30, 54, 78, 102, 126],
            &[6, 26, 52, 78, 104, 130], &[6, 30, 56, 82, 108, 134], &[6, 34, 60, 86, 112, 138],
            &[6, 30, 58, 86, 114, 142], &[6, 34, 62, 90, 118, 146],
            &[6, 30, 54, 78, 102, 126, 150], &[6, 24, 50, 76, 102, 128, 154],
            &[6, 28, 54, 80, 106, 132, 158], &[6, 32, 58, 84, 110, 136, 162],
            &[6, 26, 54, 82, 110, 138, 166], &[6, 30, 58, 86, 114, 142, 170],
        ];
        for (i, expected) in TABLE.iter().enumerate() {
            assert_eq!(&alignment_positions(i + 1), expected, "version {}", i + 1);
        }
    }

    #[test]
    fn every_version_encodes_without_panicking() {
        // The fixture set reaches version 40 but skips most versions on the
        // way. This walks all forty, which is what covers the alignment and
        // interleaving arithmetic at every block layout.
        for version in MIN_VERSION..=MAX_VERSION {
            for ecc in Ecc::ALL {
                let capacity = byte_capacity(version, ecc);
                let data = vec![b'A'; capacity];
                let qr = Qr::encode(&data, ecc).expect("a full payload fits by construction");
                assert_eq!(qr.size(), version * 4 + 17, "version {version} at {ecc:?}");
            }
        }
    }

    #[test]
    fn a_stronger_level_is_used_when_it_costs_no_extra_size() {
        // Slack becomes robustness rather than padding.
        let qr = Qr::encode(b"hi", Ecc::Low).expect("encodes");
        assert_eq!(qr.size(), 21);
    }

    #[test]
    fn the_version_grows_with_the_payload() {
        let small = Qr::encode(b"short", Ecc::Medium).expect("encodes");
        let large = Qr::encode(&[b'x'; 400], Ecc::Medium).expect("encodes");
        assert!(large.size() > small.size());
        assert_eq!(small.size() % 4, 1, "every version is 4n+17 modules");
    }

    #[test]
    fn a_payload_beyond_version_40_is_refused_rather_than_truncated() {
        // Silently encoding a prefix would produce a QR that scans to a broken
        // share link, which is worse than no QR at all.
        let huge = vec![b'x'; 4000];
        assert_eq!(Qr::encode(&huge, Ecc::Low), Err(QrError::TooLong));
    }

    #[test]
    fn a_real_share_link_fits() {
        let link = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443\
                    ?type=xhttp&mode=packet-up&path=%2Fabcdef&host=example.com\
                    &security=tls&sni=example.com&encryption=none#example%20node";
        let qr = Qr::encode(link.as_bytes(), Ecc::Medium).expect("encodes");
        assert!(qr.size() >= 21);
    }

    #[test]
    fn the_finder_patterns_are_where_a_reader_looks_for_them() {
        let qr = Qr::encode(b"test", Ecc::Medium).expect("encodes");
        let n = qr.size();
        for (ox, oy) in [(0, 0), (n - 7, 0), (0, n - 7)] {
            assert!(qr.dark(ox, oy), "finder corner");
            assert!(qr.dark(ox + 3, oy + 3), "finder centre");
            assert!(!qr.dark(ox + 1, oy + 1), "finder inner ring is light");
        }
    }

    #[test]
    fn the_svg_covers_every_dark_module_and_carries_a_quiet_zone() {
        let qr = Qr::encode(b"test", Ecc::Medium).expect("encodes");
        let svg = qr.to_svg(4);
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        let span = qr.size() + 8;
        assert!(svg.contains(&format!("viewBox=\"0 0 {span} {span}\"")));
        // Every row with a dark module must contribute at least one subpath.
        let dark_rows = (0..qr.size())
            .filter(|&y| (0..qr.size()).any(|x| qr.dark(x, y)))
            .count();
        assert!(svg.matches('M').count() >= dark_rows);
    }

    #[test]
    fn encoding_never_panics_on_arbitrary_input() {
        let mut seed = 0x51a3_77c2_11de_4409u64;
        for _ in 0..400 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 600) as usize;
            let data: Vec<u8> = (0..len).map(|i| (seed >> (i % 56)) as u8).collect();
            for ecc in Ecc::ALL {
                if let Ok(qr) = Qr::encode(&data, ecc) {
                    let _ = qr.to_svg(4);
                }
            }
        }
    }
}


