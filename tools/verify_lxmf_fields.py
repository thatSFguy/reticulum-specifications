"""
Verifier for SPEC.md §5.9 (LXMF field constants and helper specifiers).

Loads upstream `LXMF.LXMF` and confirms that the numeric allocations of
every `FIELD_*`, `AM_*`, `RENDERER_*`, `PN_META_*`, and `SF_*` constant
match the values listed in §5.9 byte-for-byte. If upstream renumbers a
constant or adds a new one, this verifier fails — and the spec section
needs an update.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import sys

import LXMF  # noqa: F401  — needed so `from LXMF import LXMF` resolves
from LXMF import LXMF as LXMF_consts


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


EXPECTED_FIELDS = {
    "FIELD_EMBEDDED_LXMS":    0x01,
    "FIELD_TELEMETRY":        0x02,
    "FIELD_TELEMETRY_STREAM": 0x03,
    "FIELD_ICON_APPEARANCE":  0x04,
    "FIELD_FILE_ATTACHMENTS": 0x05,
    "FIELD_IMAGE":            0x06,
    "FIELD_AUDIO":            0x07,
    "FIELD_THREAD":           0x08,
    "FIELD_COMMANDS":         0x09,
    "FIELD_RESULTS":          0x0A,
    "FIELD_GROUP":            0x0B,
    "FIELD_TICKET":           0x0C,
    "FIELD_EVENT":            0x0D,
    "FIELD_RNR_REFS":         0x0E,
    "FIELD_RENDERER":         0x0F,
    "FIELD_CUSTOM_TYPE":      0xFB,
    "FIELD_CUSTOM_DATA":      0xFC,
    "FIELD_CUSTOM_META":      0xFD,
    "FIELD_NON_SPECIFIC":     0xFE,
    "FIELD_DEBUG":            0xFF,
}

EXPECTED_AUDIO_MODES = {
    "AM_CODEC2_450PWB":  0x01,
    "AM_CODEC2_450":     0x02,
    "AM_CODEC2_700C":    0x03,
    "AM_CODEC2_1200":    0x04,
    "AM_CODEC2_1300":    0x05,
    "AM_CODEC2_1400":    0x06,
    "AM_CODEC2_1600":    0x07,
    "AM_CODEC2_2400":    0x08,
    "AM_CODEC2_3200":    0x09,
    "AM_OPUS_OGG":       0x10,
    "AM_OPUS_LBW":       0x11,
    "AM_OPUS_MBW":       0x12,
    "AM_OPUS_PTT":       0x13,
    "AM_OPUS_RT_HDX":    0x14,
    "AM_OPUS_RT_FDX":    0x15,
    "AM_OPUS_STANDARD":  0x16,
    "AM_OPUS_HQ":        0x17,
    "AM_OPUS_BROADCAST": 0x18,
    "AM_OPUS_LOSSLESS":  0x19,
    "AM_CUSTOM":         0xFF,
}

EXPECTED_RENDERERS = {
    "RENDERER_PLAIN":    0x00,
    "RENDERER_MICRON":   0x01,
    "RENDERER_MARKDOWN": 0x02,
    "RENDERER_BBCODE":   0x03,
}

EXPECTED_PN_META = {
    "PN_META_VERSION":       0x00,
    "PN_META_NAME":          0x01,
    "PN_META_SYNC_STRATUM":  0x02,
    "PN_META_SYNC_THROTTLE": 0x03,
    "PN_META_AUTH_BAND":     0x04,
    "PN_META_UTIL_PRESSURE": 0x05,
    "PN_META_CUSTOM":        0xFF,
}

EXPECTED_SF = {
    "SF_COMPRESSION": 0x00,
}


def verify_group(label: str, expected: dict[str, int]) -> None:
    print(f"== {label} ==")
    for name, want in expected.items():
        got = getattr(LXMF_consts, name, None)
        if got is None:
            fail(f"upstream LXMF.LXMF is missing constant `{name}` — spec §5.9 references it")
        if got != want:
            fail(
                f"upstream `LXMF.LXMF.{name}` = 0x{got:02x}, spec §5.9 says 0x{want:02x}. "
                "Either upstream renumbered (update the spec table AND this verifier) or "
                "the spec is wrong."
            )
        print(f"  {name:<24s} = 0x{got:02x}  (matches spec)")


def verify_no_unknown_field_constants() -> None:
    """Fail if upstream has added a FIELD_* / AM_* / RENDERER_* / PN_META_* /
    SF_* constant that isn't enumerated in §5.9. The spec needs to stay in
    sync with upstream as new field allocations land."""
    print("== unknown-constant audit ==")
    known = (
        set(EXPECTED_FIELDS) | set(EXPECTED_AUDIO_MODES) |
        set(EXPECTED_RENDERERS) | set(EXPECTED_PN_META) | set(EXPECTED_SF)
    )
    prefixes = ("FIELD_", "AM_", "RENDERER_", "PN_META_", "SF_")
    for attr in dir(LXMF_consts):
        if not any(attr.startswith(p) for p in prefixes):
            continue
        # Skip non-int attributes (function helpers, etc.)
        val = getattr(LXMF_consts, attr)
        if not isinstance(val, int):
            continue
        if attr not in known:
            fail(
                f"upstream `LXMF.LXMF.{attr}` = 0x{val:02x} is not enumerated in spec §5.9. "
                "Add it to the appropriate table and to this verifier."
            )
    print("  (no unknown FIELD_/AM_/RENDERER_/PN_META_/SF_ constants)")


def main() -> None:
    verify_group("FIELD_* (top-level fields dict keys)", EXPECTED_FIELDS)
    verify_group("AM_* (FIELD_AUDIO mode bytes)", EXPECTED_AUDIO_MODES)
    verify_group("RENDERER_* (FIELD_RENDERER values)", EXPECTED_RENDERERS)
    verify_group("PN_META_* (propagation-node metadata keys)", EXPECTED_PN_META)
    verify_group("SF_* (functionality signalling)", EXPECTED_SF)
    verify_no_unknown_field_constants()
    print()
    print("PASS")


if __name__ == "__main__":
    main()
