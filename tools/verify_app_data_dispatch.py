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
things depending on that first byte, and two of them look like success:

  * first byte outside both ranges, not valid UTF-8 -> UnicodeDecodeError
  * first byte outside both ranges, valid UTF-8     -> returns a CORRUPTED
    name with the length/type header byte glued on as a character
  * first byte lands in 0x90..0x9f by coincidence   -> msgpack branch,
    returns None as though the announce carried no name

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


def verify_cbor_map_raises():
    """0xa3 is outside both msgpack ranges -> raw-UTF-8 branch -> raises."""
    try:
        got = LXMF_helpers.display_name_from_app_data(CBOR_MAP_3)
    except UnicodeDecodeError:
        print("PASS S4.6 CBOR map (0xa3) -> UnicodeDecodeError from the raw-UTF-8 branch")
        return
    except Exception as e:
        fail(f"S4.6 CBOR map: expected UnicodeDecodeError, got {type(e).__name__}: {e}")
    fail(f"S4.6 CBOR map: expected UnicodeDecodeError, got a value: {got!r}")


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
    """The three branch heads in display_name_from_app_data are 0x90..0x9f and 0xdc."""
    msgpack_leaders = [b for b in range(0x90, 0xA0)] + [0xDC]
    for lead in msgpack_leaders:
        payload = bytes([lead]) + b"\x00" * 8
        try:
            LXMF_helpers.display_name_from_app_data(payload)
        except UnicodeDecodeError:
            fail(f"S4.6 dispatch: 0x{lead:02x} should take the msgpack branch, took raw-UTF-8")
        except Exception:
            pass  # malformed msgpack raising from inside the branch is still the msgpack branch
    # A byte just outside the range must take the raw-UTF-8 branch instead.
    try:
        LXMF_helpers.display_name_from_app_data(bytes([0x8F]) + b"\xff\xff")
    except UnicodeDecodeError:
        print("PASS S4.6 dispatch is first-byte-only (0x90..0x9f, 0xdc msgpack; 0x8f raw-UTF-8)")
        return
    fail("S4.6 dispatch: 0x8f should have taken the raw-UTF-8 branch and raised")


def verify_lxmf_shapes_still_parse():
    """Guard against over-reading the above: real LXMF app_data still works."""
    app_data = LXMF_helpers.display_name_from_app_data(
        RNS.vendor.umsgpack.packb([b"Reticulum5", None, [0x00]])
    )
    if app_data != "Reticulum5":
        fail(f"S4.6 control: genuine LXMF app_data parsed as {app_data!r}")
    print("PASS S4.6 control: genuine 3-element LXMF app_data still parses to 'Reticulum5'")


def main():
    print(f"verify_app_data_dispatch.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    verify_cbor_map_raises()
    verify_cbor_text_corrupts_silently()
    verify_cbor_array_collides_with_fixarray()
    verify_dispatch_is_first_byte_only()
    verify_lxmf_shapes_still_parse()
    print("ALL PASS")


if __name__ == "__main__":
    main()
