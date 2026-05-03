"""
Verifier for SPEC.md S4.3 (announce app_data format for LXMF delivery
destinations).

Exercises:
  - Upstream LXMF.LXMRouter.get_announce_app_data emits a 2-element msgpack
    array [display_name_bytes, stamp_cost] in LXMF 0.9.6. The dead-code
    supported_functionality line at LXMF/LXMRouter.py:999 is computed but
    never appended.
  - The wire-byte form for display_name="Reticulum5", stamp_cost=None matches
    the hex documented in SPEC.md S4.3:
        92 c4 0a 52 65 74 69 63 75 6c 75 6d 35 c0
  - The parsers in LXMF/LXMF.py tolerate:
      * raw UTF-8 ("original announce format")
      * 1-element msgpack array
      * 2-element [name, stamp_cost]
      * 3-element [name, stamp_cost, [capability_flags]]
    and that the 3-element variant is what flips
    compression_support_from_app_data based on SF_COMPRESSION presence.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import sys

import RNS
import LXMF
from LXMF import LXMF as LXMF_helpers
import RNS.vendor.umsgpack as umsgpack


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def verify_two_element_wire_bytes():
    # SPEC.md S4.3 hex example: display_name="Reticulum5", stamp_cost=None.
    # Spec layout:
    #   92                              # fixarray, 2 elements
    #   c4 0a                           # bin8, length 10
    #   52 65 74 69 63 75 6c 75 6d 35   # "Reticulum5"
    #   c0                              # nil (stamp_cost)
    expected = bytes.fromhex("92" + "c40a" + "5265746963756c756d35" + "c0")

    name = b"Reticulum5"
    peer_data = [name, None]
    actual = umsgpack.packb(peer_data)
    if actual != expected:
        fail(f"S4.3 2-element wire bytes mismatch:\n"
             f"  got: {actual.hex()}\n"
             f"  want: {expected.hex()}")
    print("PASS S4.3 2-element wire bytes (umsgpack.packb([b'Reticulum5', None]))")


def verify_producer_is_two_element_in_this_lxmf():
    # Read the LXMRouter source and confirm it appends 2 elements (not 3) in
    # the LXMF 0.9.6 producer. We do this by inspecting the function source so
    # the verifier breaks loudly if upstream restores the 3-element variant.
    import inspect
    from LXMF.LXMRouter import LXMRouter

    src = inspect.getsource(LXMRouter.get_announce_app_data)
    if "peer_data = [display_name, stamp_cost]" not in src:
        fail(f"S4.3 producer line not found in LXMRouter.get_announce_app_data. "
             f"Upstream may have restored the 3-element variant. Source:\n{src}")
    if "peer_data.append(supported_functionality)" in src:
        # If upstream re-enables this, the spec needs the 3-element variant
        # marked as "current upstream" instead of "parser-tolerated only".
        fail("S4.3 producer NOW appends supported_functionality. "
             "Update SPEC.md S4.3 to describe the 3-element variant as live.")
    print(f"PASS S4.3 LXMF {LXMF.__version__} producer emits 2-element form only "
          "(supported_functionality is dead code at LXMF/LXMRouter.py:999)")


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
    print("PASS S4.3 parser tolerance (raw UTF-8, 1/2/3-element msgpack array)")


def main():
    print(f"verify_announce_app_data.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    verify_two_element_wire_bytes()
    verify_producer_is_two_element_in_this_lxmf()
    verify_parser_tolerance()
    print("ALL PASS")


if __name__ == "__main__":
    main()
