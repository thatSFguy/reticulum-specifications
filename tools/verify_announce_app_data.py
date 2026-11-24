"""
Verifier for SPEC.md S4.3 (announce app_data format for LXMF delivery
destinations).

Exercises:
  - Upstream LXMF.LXMRouter.get_announce_app_data, CALLED on a stub router
    (not grepped), emits the LXMF 1.3 4-element msgpack array
        [display_name_bytes, ceil(stamp_cost) | None, [SF_COMPRESSION], stamp_cost | None]
    where element [3] is the 1/256-quantized fractional cost as a float and
    element [1] is that cost rounded UP for LXMF <= 1.2 readers.
    (An earlier revision of this verifier looked for the 3-element producer
    line in the function source. After LXMF 1.3 that line survives only as
    a comment, so the check kept passing against a producer that no longer
    emitted the documented shape. Calling the producer closes that hole.)
  - The wire bytes for display_name="Reticulum5" with no stamp cost, and
    with stamp_cost=8.5, match the hex documented in SPEC.md S4.3.
  - The legacy 2-element (<= 0.9.x) and 3-element (1.0-1.2) forms still
    have the documented bytes.
  - The parsers in LXMF/LXMF.py tolerate raw UTF-8, and 1/2/3/4-element
    arrays; stamp_cost_from_app_data prefers a numeric element [3] and
    falls back to element [1] otherwise.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import sys
import types

import RNS
import LXMF
from LXMF import LXMF as LXMF_helpers
from LXMF.LXMRouter import LXMRouter
import RNS.vendor.umsgpack as umsgpack


NAME_HEX = "c40a" + "5265746963756c756d35"   # bin8(10) "Reticulum5"


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def produce(stamp_cost) -> bytes:
    """Run upstream's get_announce_app_data against a minimal stub router."""
    dest_hash = b"\x01" * 16
    dest = types.SimpleNamespace(display_name="Reticulum5", stamp_cost=stamp_cost)
    stub = types.SimpleNamespace(delivery_destinations={dest_hash: dest})
    out = LXMRouter.get_announce_app_data(stub, dest_hash)
    if not isinstance(out, bytes):
        fail(f"S4.3 get_announce_app_data returned {type(out).__name__}, expected bytes")
    return out


def verify_producer_wire_bytes():
    # No stamp cost: 94 <name> c0 91 00 c0
    expected = bytes.fromhex("94" + NAME_HEX + "c0" + "91" + "00" + "c0")
    actual = produce(None)
    if actual != expected:
        fail(f"S4.3 producer bytes (no stamp cost) mismatch:\n"
             f"  got:  {actual.hex()}\n  want: {expected.hex()}")
    print(f"PASS S4.3 LXMF {LXMF.__version__} producer emits the 4-element form, "
          f"no stamp cost: {actual.hex()}")

    # stamp_cost = 8.5: element [1] = ceil = 9 (fixint 09), element [3] = float64 8.5
    expected = bytes.fromhex("94" + NAME_HEX + "09" + "91" + "00" + "cb4021000000000000")
    actual = produce(8.5)
    if actual != expected:
        fail(f"S4.3 producer bytes (stamp_cost=8.5) mismatch:\n"
             f"  got:  {actual.hex()}\n  want: {expected.hex()}")
    print("PASS S4.3 stamp_cost=8.5 -> element [1] = 9 (rounded up), "
          "element [3] = float64 8.5")

    # Quantization: [3] is the 1/256 grid value, and [1] is never rounded down.
    for cost in (1, 8, 12.7, 33.3, 99.9):
        peer = umsgpack.unpackb(produce(cost))
        q = RNS.Stamps.quantize_cost(cost)
        if peer[3] != q or not isinstance(peer[3], float):
            fail(f"S4.3 element [3] for cost {cost!r} is {peer[3]!r}, want quantized float {q!r}")
        if not isinstance(peer[1], int) or peer[1] < peer[3] or peer[1] - peer[3] >= 1:
            fail(f"S4.3 element [1] for cost {cost!r} is {peer[1]!r}, want ceil({peer[3]!r})")
    print("PASS S4.3 element [3] is the 1/256-quantized float, element [1] its ceiling")

    # At or above STAMP_COST_CAP the producer announces no cost at all.
    cap = RNS.Transport.STAMP_COST_CAP
    peer = umsgpack.unpackb(produce(cap))
    if peer[1] is not None or peer[3] is not None:
        fail(f"S4.3 cost == STAMP_COST_CAP ({cap}) announced as {peer!r}; expected no cost")
    print(f"PASS S4.3 cost >= STAMP_COST_CAP ({cap}) is not announced")


def verify_legacy_wire_bytes():
    # Forms emitted by older producers, which receivers must still accept.
    three = bytes.fromhex("93" + NAME_HEX + "c0" + "91" + "00")
    if umsgpack.packb([b"Reticulum5", None, [LXMF_helpers.SF_COMPRESSION]]) != three:
        fail("S4.3 3-element (LXMF 1.0-1.2) wire bytes mismatch")
    two = bytes.fromhex("92" + NAME_HEX + "c0")
    if umsgpack.packb([b"Reticulum5", None]) != two:
        fail("S4.3 legacy 2-element wire bytes mismatch")
    print("PASS S4.3 legacy 3-element and 2-element wire bytes")


def verify_parser_tolerance():
    cases = [
        # (label, app_data bytes, expected display_name, expected stamp_cost,
        #  expected compression_support)
        ("raw UTF-8 (original format)",
         "Alice".encode("utf-8"),
         "Alice", None, True),
        ("1-element fixarray [name]",
         umsgpack.packb([b"Bob"]),
         "Bob", None, True),
        ("2-element fixarray [name, stamp_cost=int]",
         umsgpack.packb([b"Carol", 12]),
         "Carol", 12, True),
        ("2-element fixarray [name, nil]",
         umsgpack.packb([b"Dan", None]),
         "Dan", None, True),
        ("3-element fixarray [name, nil, [SF_COMPRESSION]]",
         umsgpack.packb([b"Eve", None, [LXMF_helpers.SF_COMPRESSION]]),
         "Eve", None, True),
        ("3-element fixarray [name, nil, []] (no SF flags set)",
         umsgpack.packb([b"Faye", None, []]),
         "Faye", None, False),
        ("4-element [name, 9, [SF], 8.5] -> element [3] wins",
         umsgpack.packb([b"Gus", 9, [LXMF_helpers.SF_COMPRESSION], 8.5]),
         "Gus", 8.5, True),
        ("4-element [name, nil, [SF], nil] -> no cost",
         umsgpack.packb([b"Hal", None, [LXMF_helpers.SF_COMPRESSION], None]),
         "Hal", None, True),
        ("4-element [name, 7, [SF], 'x'] -> non-numeric [3] falls back to [1]",
         umsgpack.packb([b"Ivy", 7, [LXMF_helpers.SF_COMPRESSION], "x"]),
         "Ivy", 7, True),
        ("5-element (future) [name, 7, [], 6.25, 'extra']",
         umsgpack.packb([b"Jo", 7, [], 6.25, "extra"]),
         "Jo", 6.25, False),
    ]
    for label, blob, want_name, want_cost, want_compress in cases:
        got_name = LXMF_helpers.display_name_from_app_data(blob)
        got_cost = LXMF_helpers.stamp_cost_from_app_data(blob)
        got_compress = LXMF_helpers.compression_support_from_app_data(blob)
        if got_name != want_name:
            fail(f"S4.3 parser ({label}): display_name got {got_name!r} want {want_name!r}")
        if got_cost != want_cost:
            fail(f"S4.3 parser ({label}): stamp_cost got {got_cost!r} want {want_cost!r}")
        if got_compress != want_compress:
            fail(f"S4.3 parser ({label}): compression got {got_compress!r} want {want_compress!r}")
    print("PASS S4.3 parser tolerance (raw UTF-8, 1/2/3/4/5-element msgpack array; "
          "numeric element [3] preferred over [1])")


def main():
    print(f"verify_announce_app_data.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    verify_producer_wire_bytes()
    verify_legacy_wire_bytes()
    verify_parser_tolerance()
    print("ALL PASS")


if __name__ == "__main__":
    main()
