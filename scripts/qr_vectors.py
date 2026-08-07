#!/usr/bin/env python3
"""Regenerate the QR test vectors from independent implementations.

The QR encoder in ``src/subscription/qr.rs`` is checked against outside
implementations rather than against itself. A QR that is self-consistently
wrong scans as nothing at all, so agreeing with your own output proves nothing.

Both libraries are build-time tools. Neither is a dependency of the Worker,
neither is vendored, and nothing at runtime needs them::

    python -m pip install qrcode segno
    python scripts/qr_vectors.py > tests/fixtures/qr_vectors.txt

Two record types, tab separated, distinguished by the first field.

``matrix`` records come from ``qrcode`` and pin everything, so the comparison
is exact::

    matrix  <level>  <mask>  <text>  <hex row>  <hex row>  ...

The mask is pinned deliberately. Choosing a mask means scoring eight candidate
symbols against the four penalty rules in ISO/IEC 18004 Table 11, and the third
rule is written ambiguously enough that implementations disagree in good faith
-- segno matches the 1:1:3:1:1 pattern at a single module width, while the
reference algorithm matches it at any scale. Both produce valid, scannable
symbols. Comparing auto-selected masks would therefore test whose reading of
Table 11 is being used rather than whether the encoder works. Pinning the mask
compares the parts where a disagreement really is a bug -- segment encoding,
Reed-Solomon parity, block interleaving, module placement, and the format and
version information -- across all eight masks rather than only the winner.

``boost`` records come from ``segno`` and cover the one thing pinning hides:
which level a payload ends up at when there is spare capacity::

    boost  <requested level>  <effective level>  <version>  <text>

Why two libraries
-----------------

They disagree, and finding out which was right is the reason this file names
both. segno's ``write_padding_bits`` appends ``8 - (length % 8)`` zero bits,
which is a whole extra zero codeword when the bit stream already ends on a
codeword boundary -- and after a four-bit terminator in byte mode it always
does. ISO/IEC 18004 section 7.4.10 adds padding bits only "if the bit stream
length is such that it does not end at a codeword boundary". qrcode and this
encoder both add none; segno adds eight.

The symbol still scans either way, because the extra byte lands in the padding
region that a reader discards once the character count is satisfied. But it is
a real difference in the emitted bits, and it is exactly the sort of divergence
that makes a single reference implementation a weak check. Matrices therefore
come from qrcode, which follows the specification here, and segno is kept for
the level-boosting decision, which it does correctly and qrcode does not do at
all.
"""

from __future__ import annotations

import sys
from importlib.metadata import version

try:
    import qrcode
    from qrcode.util import MODE_8BIT_BYTE, QRData
except ImportError:  # pragma: no cover - a tooling problem, not a code path
    sys.exit("qrcode is not installed. Run: python -m pip install qrcode")

try:
    import segno
except ImportError:  # pragma: no cover
    sys.exit("segno is not installed. Run: python -m pip install segno")

# qrcode names its levels by the two-bit value that goes into the format
# information, which is not the order anyone would guess: M is 0 and L is 1.
QRCODE_LEVEL = {
    "L": qrcode.constants.ERROR_CORRECT_L,
    "M": qrcode.constants.ERROR_CORRECT_M,
    "Q": qrcode.constants.ERROR_CORRECT_Q,
    "H": qrcode.constants.ERROR_CORRECT_H,
}

# Payload lengths chosen to straddle the points where the encoding changes:
# the character-count field widens at version 10, the version-information
# blocks appear at version 7, and the block count changes at nearly every step.
SHORT_LENGTHS = [1, 3, 8, 14, 26, 40, 62]
LONG_LENGTHS = [90, 130, 180, 250, 330, 450, 620, 850, 1100, 1500, 1900, 2300]

LEVELS = ["L", "M", "Q", "H"]
MASKS = range(8)

# Text that is actually representative of what gets encoded, as opposed to
# filler that might accidentally avoid a whole class of byte values.
REAL = [
    (
        "M",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443"
        "?type=xhttp&mode=packet-up&path=%2Fabcdef&host=example.com"
        "&security=tls&sni=example.com&encryption=none#example%20node",
    ),
    ("M", "https://example.com/0123456789abcdef/v2rayn"),
    ("L", "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206QUFBQQ==@example.com:443#node"),
    ("H", "trojan://password@example.com:443?type=xhttp&path=%2Fx#node"),
]


def filler(length: int) -> str:
    """A repeatable string of the given length spanning the printable range.

    Deliberately not all one character: a run of identical bytes exercises the
    mask-penalty rules very differently from mixed content, and a QR encoder
    can pass on one while failing the other.
    """
    alphabet = "".join(chr(c) for c in range(0x21, 0x7F) if chr(c) not in "\t\\")
    return "".join(alphabet[i % len(alphabet)] for i in range(length))


def matrix_of(text: str, level: str, mask: int):
    """The module matrix qrcode produces, with no quiet zone.

    Byte mode is forced. Left to itself the library would pick numeric or
    alphanumeric mode for suitable content, which would compare against
    something the Rust encoder deliberately does not implement.
    """
    qr = qrcode.QRCode(error_correction=QRCODE_LEVEL[level], border=0, mask_pattern=mask)
    qr.add_data(QRData(text.encode("utf-8"), mode=MODE_8BIT_BYTE, check_data=False))
    qr.make(fit=True)
    return qr.modules


def rows_as_hex(matrix) -> list[str]:
    out = []
    for row in matrix:
        bits = 0
        for module in row:
            bits = (bits << 1) | (1 if module else 0)
        width = (len(row) + 3) // 4
        out.append(f"{bits:0{width}x}")
    return out


def matrix_record(level: str, mask: int, text: str) -> str:
    return "\t".join(["matrix", level, str(mask), text, *rows_as_hex(matrix_of(text, level, mask))])


def boost_record(requested: str, text: str) -> str:
    qr = segno.make_qr(text, error=requested, mode="byte", boost_error=True)
    return "\t".join(["boost", requested, qr.error, str(qr.version), text])


def strongest_that_fits(preferred: str, text: str) -> str:
    """The preferred level, or the strongest weaker one that holds the payload.

    Version 40 holds 2953 bytes at L but only 1273 at H, so the longest vectors
    cannot use every level. Weakening rather than dropping them keeps the
    largest versions in the vector set, which is where the version-information
    blocks and the widest interleaving live.
    """
    order = ["H", "Q", "M", "L"]
    for level in order[order.index(preferred):]:
        try:
            matrix_of(text, level, 0)
        except (qrcode.exceptions.DataOverflowError, ValueError):
            # qrcode reports "will not fit" two different ways: its own
            # overflow error when a fixed version is too small, and a bare
            # ValueError from the version check when best_fit runs past 40.
            continue
        return level
    raise ValueError(f"{len(text)} bytes will not fit at any level")


def main() -> int:
    print("# Generated by scripts/qr_vectors.py. Do not hand-edit.")
    print(f"# matrix records from qrcode {version('qrcode')}")
    print(f"# boost records from segno {segno.__version__}")
    print("# matrix\\t<level>\\t<mask>\\t<text>\\t<hex row>...")
    print("# boost\\t<requested level>\\t<effective level>\\t<version>\\t<text>")

    # Small symbols get every mask and every level, because that is where the
    # whole eight-way drawing path is cheap to cover exhaustively.
    for length in SHORT_LENGTHS:
        text = filler(length)
        for level in LEVELS:
            for mask in MASKS:
                print(matrix_record(level, mask, text))

    # Large symbols get one mask each, cycled, to keep the fixture a sensible
    # size while still reaching version 40.
    for i, length in enumerate(LONG_LENGTHS):
        text = filler(length)
        print(matrix_record(strongest_that_fits(LEVELS[i % len(LEVELS)], text), i % 8, text))

    for level, text in REAL:
        for mask in (0, 3, 7):
            print(matrix_record(level, mask, text))

    # The level a payload actually lands on, which pinning the mask hides.
    for length in SHORT_LENGTHS + LONG_LENGTHS:
        text = filler(length)
        for level in LEVELS:
            try:
                print(boost_record(level, text))
            except segno.DataOverflowError:
                continue
    for level, text in REAL:
        print(boost_record(level, text))

    return 0


if __name__ == "__main__":
    sys.exit(main())
