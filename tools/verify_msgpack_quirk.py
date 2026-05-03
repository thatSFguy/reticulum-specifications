"""
Verifier for SPEC.md S9.3 (RNS bundles `umsgpack` — encode display
names as bytes, not str).

The bundled `RNS.vendor.umsgpack` distinguishes between Python `str`
(encoded as msgpack `fixstr/str8/str16/str32` types `0xa0..0xbf`,
`0xd9`, `0xda`, `0xdb`) and Python `bytes` (encoded as `bin8/bin16/
bin32` types `0xc4`, `0xc5`, `0xc6`). The downstream LXMF parser at
`LXMF/LXMF.py:131` does `dn.decode("utf-8")` on the unpacked first
element — this only works when the producer used `bytes` (so umsgpack
unpacks as Python `bytes` which has `.decode`).

If a producer uses `str` instead, umsgpack unpacks back to a Python
`str` which has no `.decode("utf-8")` method, the LXMF parser raises
AttributeError, and the message's display name is silently lost.

This verifier confirms:

  1. umsgpack.packb on a `str` produces fixstr/str8/str16/str32 prefix
     bytes; on `bytes` produces bin8/bin16/bin32.
  2. umsgpack.unpackb round-trips a `bytes` value back to Python `bytes`,
     and a `str` value back to Python `str`.
  3. LXMF.display_name_from_app_data returns the decoded display name
     for a bytes-encoded producer and returns None (with no crash) for
     a str-encoded producer — i.e. the gotcha is real but contained.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import sys

import RNS
import RNS.vendor.umsgpack as umsgpack
import LXMF
from LXMF import LXMF as LXMF_helpers


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def verify_pack_str_uses_str_prefix():
    # 5-character str fits in fixstr (0xa0..0xbf with the length in the low 5 bits)
    blob = umsgpack.packb("hello")
    if blob[0] not in (0xa5, 0xd9, 0xda, 0xdb):
        # 0xa5 = fixstr length 5 (0xa0 | 5)
        fail(f"umsgpack.packb('hello') produced unexpected first byte 0x{blob[0]:02x}; "
             f"want fixstr 0xa5 or str8/16/32")
    if blob[0] != 0xa5:
        fail(f"umsgpack.packb('hello') did not use fixstr; got 0x{blob[0]:02x}")
    print(f"PASS S9.3 packb('hello') -> 0x{blob[0]:02x}: fixstr (str family)")


def verify_pack_bytes_uses_bin_prefix():
    # 5-byte bytes uses bin8 (0xc4 NN ...) — there's no fixbin
    blob = umsgpack.packb(b"hello")
    if blob[0] not in (0xc4, 0xc5, 0xc6):
        fail(f"umsgpack.packb(b'hello') produced unexpected first byte 0x{blob[0]:02x}; "
             f"want bin8/16/32")
    if blob[0] != 0xc4:
        fail(f"umsgpack.packb(b'hello') did not use bin8; got 0x{blob[0]:02x}")
    if blob[1] != 5:
        fail(f"bin8 length byte != 5: 0x{blob[1]:02x}")
    print(f"PASS S9.3 packb(b'hello') -> 0xc4 05: bin8 (bin family)")


def verify_unpack_round_trip_str_vs_bytes():
    # str round-trips to str
    s = umsgpack.unpackb(umsgpack.packb("hello"))
    if not isinstance(s, str):
        fail(f"umsgpack.unpackb(packb('hello')) returned {type(s).__name__}, want str")

    # bytes round-trips to bytes
    b = umsgpack.unpackb(umsgpack.packb(b"hello"))
    if not isinstance(b, bytes):
        fail(f"umsgpack.unpackb(packb(b'hello')) returned {type(b).__name__}, want bytes")

    print("PASS S9.3 round-trip preserves str/bytes distinction")


def verify_lxmf_display_name_parser_quirk():
    """LXMF.display_name_from_app_data only works when the producer used bytes."""
    # 1. Correct producer: bytes-encoded display name in a 2-element array
    correct_blob = umsgpack.packb([b"AliceTest", None])
    name = LXMF_helpers.display_name_from_app_data(correct_blob)
    if name != "AliceTest":
        fail(f"S9.3 correct (bytes-encoded) display name parsed wrong: {name!r}")
    print("PASS S9.3 correct producer: msgpack([bytes, None]) -> 'AliceTest'")

    # 2. Wrong producer: str-encoded display name. LXMF should NOT crash —
    # it should return None. (The except in display_name_from_app_data
    # at LXMF.py:133-135 logs the error and returns None.)
    wrong_blob = umsgpack.packb(["AliceTest", None])
    try:
        result = LXMF_helpers.display_name_from_app_data(wrong_blob)
    except Exception as e:
        fail(f"S9.3 LXMF parser crashed on str-encoded producer: {e}")

    if result is not None:
        fail(f"S9.3 LXMF parser silently accepted str-encoded producer "
             f"(returned {result!r}); spec says this should fail to None")
    print("PASS S9.3 wrong producer: msgpack([str, None]) -> None "
          "(LXMF.py:131 .decode raises AttributeError, parser returns None)")


def main():
    print(f"verify_msgpack_quirk.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    verify_pack_str_uses_str_prefix()
    verify_pack_bytes_uses_bin_prefix()
    verify_unpack_round_trip_str_vs_bytes()
    verify_lxmf_display_name_parser_quirk()
    print("ALL PASS")


if __name__ == "__main__":
    main()
