"""
Verifier for SPEC.md S4.6 (app_data is not always msgpack).

S4.3 documents the msgpack [name, stamp_cost, [flags]] array that LXMF
delivery destinations announce. That is LXMF's convention, not an RNS rule:
to RNS, app_data is opaque bytes (RNS/Destination.py:304 concatenates it
unexamined, RNS/Identity.py:532 slices it back out to the end of the packet).
Announces on other aspects carry whatever their own protocol specifies.

This locks in the consequence, which is that LXMF's parser cannot be used to
tell the two apart. LXMF/LXMF.py::display_name_from_app_data dispatches on the
FIRST BYTE only -- 0x90..0x9f or 0xdc takes the msgpack branch, anything else
is assumed to be a raw UTF-8 name -- so it is a heuristic, not a validation.
Fed a non-LXMF payload it does not report an error; it does one of three
things depending on that first byte, and none of them raises:

  * first byte outside both ranges, not valid UTF-8 -> None (through LXMF
    1.2.x this raised UnicodeDecodeError; LXMF 1.3 catches it)
  * first byte outside both ranges, valid UTF-8     -> returns a CORRUPTED
    name with the length/type header byte glued on as a character
  * first byte lands in 0x90..0x9f by coincidence   -> msgpack branch,
    returns None as though the announce carried no name

It also checks the S4.7 interaction: LXMF app_data followed by the 18-byte
RNS >= 1.6 announce-stamp trailer still parses, because umsgpack ignores
bytes after the first object.

The third case is reachable from CBOR without contrivance: CBOR encodes an
array of 16 items as 0x90, which is msgpack fixarray(0).

The lesson S4.6 draws from this -- key the parser on name_hash (S4.4), never
on the shape of app_data -- is what these cases are here to keep true.

CBOR test payloads are built by hand rather than with a cbor2 dependency:
they are three bytes of header each, and writing them out keeps the wire
form visible.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import sys

import RNS
import LXMF
from LXMF import LXMF as LXMF_helpers


# LXMF logs an error of its own when a msgpack branch yields a non-decodable
# name. That is the behaviour under test, not a problem; keep it off stdout.
RNS.loglevel = RNS.LOG_CRITICAL


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


# --- hand-built CBOR (RFC 8949) payloads -------------------------------------

# Major type 3 (text string), length 7: 0x60 | 7 = 0x67.
CBOR_TEXT_HUBNAME = bytes([0x67]) + b"hubname"

# Major type 5 (map), 3 entries: 0xa0 | 3 = 0xa3. Contents are irrelevant to
# the dispatch; only the leading byte is. This is the shape an RRC hub sends.
CBOR_MAP_3 = bytes([0xA3]) + b"\x65proto\x63rrc\x61v\x01\x63hub\x67hubname"

# Major type 4 (array), 16 items: 0x80 | 16 needs the 1-byte-length form, but
# 16 fits the immediate range for arrays as 0x90 exactly. Items 0..15 are
# major type 0 immediates 0x00..0x0f.
CBOR_ARRAY_16 = bytes([0x90]) + bytes(range(16))


def verify_cbor_map_returns_none():
    """0xa3 is outside both msgpack ranges -> raw-UTF-8 branch -> decode
    fails -> None since LXMF 1.3 (raised UnicodeDecodeError through 1.2.x)."""
    try:
        got = LXMF_helpers.display_name_from_app_data(CBOR_MAP_3)
    except Exception as e:
        fail(f"S4.6 CBOR map: expected None (LXMF >= 1.3 swallows the decode error), "
             f"got {type(e).__name__}: {e}")
    if got is not None:
        fail(f"S4.6 CBOR map: expected None, got {got!r}")
    print("PASS S4.6 CBOR map (0xa3) -> None from the raw-UTF-8 branch, no error raised")


def verify_cbor_text_corrupts_silently():
    """0x67 is valid UTF-8 ('g'), so the header byte becomes part of the name."""
    got = LXMF_helpers.display_name_from_app_data(CBOR_TEXT_HUBNAME)
    want = "ghubname"
    if got != want:
        fail(f"S4.6 CBOR text string: got {got!r} want {want!r}")
    if got == "hubname":
        fail("S4.6 CBOR text string: parser stripped the CBOR header; claim is stale")
    print(f"PASS S4.6 CBOR text string (0x67) -> silently corrupted name {got!r}, no error raised")


def verify_cbor_array_collides_with_fixarray():
    """0x90 is CBOR array(16) AND msgpack fixarray(0): the msgpack branch wins."""
    got = LXMF_helpers.display_name_from_app_data(CBOR_ARRAY_16)
    if got is not None:
        fail(f"S4.6 CBOR 16-array: expected None from the msgpack branch, got {got!r}")
    print("PASS S4.6 CBOR array-of-16 (0x90) -> msgpack branch taken, returns None, no error raised")


def verify_dispatch_is_first_byte_only():
    """The branch heads in display_name_from_app_data are 0x90..0x9f and 0xdc.

    Neither branch raises since LXMF 1.3, so the branch is observed by its
    result: a msgpack array holding bin "ab" decodes to "ab" only through the
    msgpack branch (the bytes are not valid UTF-8 as a whole)."""
    for n in range(1, 16):
        payload = bytes([0x90 | n]) + bytes([0xC4, 0x02]) + b"ab" + b"\xc0" * (n - 1)
        got = LXMF_helpers.display_name_from_app_data(payload)
        if got != "ab":
            fail(f"S4.6 dispatch: 0x{0x90 | n:02x} should take the msgpack branch, got {got!r}")
    got = LXMF_helpers.display_name_from_app_data(bytes([0xDC, 0x00, 0x01, 0xC4, 0x02]) + b"ab")
    if got != "ab":
        fail(f"S4.6 dispatch: 0xdc should take the msgpack branch, got {got!r}")
    # 0x81 is msgpack fixmap(1) and 0xdd array32: neither is a branch head,
    # so both go to the raw-UTF-8 branch, fail to decode and return None.
    for lead in (0x81, 0xDD):
        got = LXMF_helpers.display_name_from_app_data(bytes([lead]) + bytes([0xC4, 0x02]) + b"ab")
        if got is not None:
            fail(f"S4.6 dispatch: 0x{lead:02x} should take the raw-UTF-8 branch and give None, got {got!r}")
    print("PASS S4.6 dispatch is first-byte-only (0x90..0x9f, 0xdc msgpack; others raw-UTF-8)")


def verify_lxmf_shapes_still_parse():
    """Guard against over-reading the above: real LXMF app_data still works."""
    app_data = LXMF_helpers.display_name_from_app_data(
        RNS.vendor.umsgpack.packb([b"Reticulum5", None, [0x00]])
    )
    if app_data != "Reticulum5":
        fail(f"S4.6 control: genuine LXMF app_data parsed as {app_data!r}")
    print("PASS S4.6 control: genuine 3-element LXMF app_data still parses to 'Reticulum5'")


def verify_stamp_trailer_tolerated():
    """S4.7: LXMF app_data + the 18-byte RNS announce-stamp trailer.

    Upstream leaves the trailer on app_data when the stamp does not validate,
    and receivers that do not implement stamps never strip it. LXMF's readers
    still work because umsgpack.unpackb stops after the first object."""
    trailer = bytes([0xC1, 0x00]) + bytes(14) + bytes([0x80, 0x0C])
    app_data = RNS.vendor.umsgpack.packb([b"Reticulum5", 8, [0x00]]) + trailer
    name = LXMF_helpers.display_name_from_app_data(app_data)
    cost = LXMF_helpers.stamp_cost_from_app_data(app_data)
    if name != "Reticulum5" or cost != 8:
        fail(f"S4.7 trailer: LXMF parsed name {name!r} / stamp_cost {cost!r}, want 'Reticulum5' / 8")
    print("PASS S4.7 LXMF app_data followed by the 18-byte stamp trailer still parses (trailing bytes ignored)")


def main():
    print(f"verify_app_data_dispatch.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    verify_cbor_map_returns_none()
    verify_cbor_text_corrupts_silently()
    verify_cbor_array_collides_with_fixarray()
    verify_dispatch_is_first_byte_only()
    verify_lxmf_shapes_still_parse()
    verify_stamp_trailer_tolerated()
    print("ALL PASS")


if __name__ == "__main__":
    main()
