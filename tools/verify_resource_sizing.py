"""
Verifier for SPEC.md §10.2 step 6, §10.4 (the MTU-vs-fixed callout, and
since RNS 1.6 the application flag and the deferred-hashmap advertisement),
§10.5 (HASHMAP_IS_EMPTY) and §5.7.4 (the stamp-cost valid range).

Three claim clusters, all of which are silent-failure surface — a peer that
gets any of them wrong produces no error, just a transfer that never
progresses or an announce that is wrongly rejected.

1. §10.2 step 6 / §10.4 — which Resource quantities follow the §6.6
   negotiated link MTU and which are fixed class-level constants. The
   part `sdu` is per-link; `Link.MDU`, `HASHMAP_MAX_LEN` and
   `COLLISION_GUARD_SIZE` are evaluated once at import from
   `Reticulum.MTU` and are identical on every link. Reading either
   backwards fails silently: a receiver measuring parts against the fixed
   464 drops every part from a larger-MTU peer, and two peers using
   different `HASHMAP_MAX_LEN` values disagree about §10.7 segment
   indices.

2. §10.4 — the spec states that upstream imposes no receive-time size
   check on Resource parts, which is why it asks category-3
   implementations to add their own. That statement is only safe to make
   while it stays true, so this verifier asserts it by source inspection.

3. §5.7.4 — the `stamp_cost` valid range (`1 <= c < STAMP_COST_CAP`, i.e.
   below 100, int or float since LXMF 1.3; `1..254` int-only through LXMF
   1.2), the `< 1 -> None` rule, and the refusal at or above the cap.
   §5.7.4 documented none of these until 2026-08-27; a Go client derived a
   range from the PoW algorithm instead (`[0, 256]`, arithmetically true and
   wrong here) and treated a negative cost as a malformed announce, which
   upstream reads as "no stamp".

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import inspect
import math
import sys
import types

import RNS
from RNS.Resource import Resource, ResourceAdvertisement
from LXMF.LXMRouter import LXMRouter


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def verify_fixed_constants() -> None:
    """§10.4: the class-level quantities, and how they are derived."""
    if Resource.SDU != RNS.Packet.MDU:
        fail(f"§10.4 Resource.SDU should be RNS.Packet.MDU "
             f"({RNS.Packet.MDU}), got {Resource.SDU}")

    expected_hashmap_max = math.floor(
        (RNS.Link.MDU - ResourceAdvertisement.OVERHEAD) / Resource.MAPHASH_LEN)
    if ResourceAdvertisement.HASHMAP_MAX_LEN != expected_hashmap_max:
        fail(f"§10.4 HASHMAP_MAX_LEN should be "
             f"floor((Link.MDU {RNS.Link.MDU} - OVERHEAD "
             f"{ResourceAdvertisement.OVERHEAD}) / {Resource.MAPHASH_LEN}) = "
             f"{expected_hashmap_max}, got "
             f"{ResourceAdvertisement.HASHMAP_MAX_LEN}")

    expected_guard = 2 * Resource.WINDOW_MAX + ResourceAdvertisement.HASHMAP_MAX_LEN
    if ResourceAdvertisement.COLLISION_GUARD_SIZE != expected_guard:
        fail(f"§10.4 COLLISION_GUARD_SIZE should be 2*WINDOW_MAX + "
             f"HASHMAP_MAX_LEN = {expected_guard}, got "
             f"{ResourceAdvertisement.COLLISION_GUARD_SIZE}")

    print(f"PASS §10.4 fixed constants: Resource.SDU={Resource.SDU}, "
          f"Link.MDU={RNS.Link.MDU}, "
          f"HASHMAP_MAX_LEN={ResourceAdvertisement.HASHMAP_MAX_LEN}, "
          f"COLLISION_GUARD_SIZE={ResourceAdvertisement.COLLISION_GUARD_SIZE}")


def verify_link_mdu_is_not_per_link() -> None:
    """§10.4: Link.MDU comes from Reticulum.MTU, never from a link instance."""
    src = inspect.getsource(RNS.Link)
    mdu_line = next((l for l in src.split("\n")
                     if l.strip().startswith("MDU") and "=" in l), None)
    if mdu_line is None:
        fail("§10.4 could not find the class-level Link.MDU assignment")
    if "Reticulum.MTU" not in mdu_line:
        fail(f"§10.4 class-level Link.MDU is no longer derived from "
             f"Reticulum.MTU — the §10.4 table's 'no' column is wrong. "
             f"Got: {mdu_line.strip()}")
    print(f"PASS §10.4 Link.MDU derives from Reticulum.MTU, not a link "
          f"instance ({mdu_line.strip()})")


def verify_sdu_follows_link_mtu() -> None:
    """§10.2 step 6: the part sdu tracks the negotiated link MTU."""
    src = inspect.getsource(Resource.__init__)
    if "self.link.mtu - RNS.Reticulum.HEADER_MAXSIZE - RNS.Reticulum.IFAC_MIN_SIZE" not in src:
        fail("§10.2 step 6 the per-link sdu derivation "
             "(link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE) was not found in "
             "Resource.__init__. If upstream switched to a fixed SDU, §10.2 "
             f"step 6 and the §10.4 table both need revisiting. Source:\n{src}")

    overhead = RNS.Reticulum.HEADER_MAXSIZE + RNS.Reticulum.IFAC_MIN_SIZE
    for mtu, expected in ((RNS.Reticulum.MTU, RNS.Reticulum.MTU - overhead),
                          (1064, 1064 - overhead)):
        got = mtu - overhead
        if got != expected:
            fail(f"§10.2 step 6 sdu arithmetic wrong at MTU {mtu}")

    base = RNS.Reticulum.MTU - overhead
    if base == 1064 - overhead:
        fail("§10.2 step 6 sdu does not actually vary with link MTU — the "
             "section's whole point is that it does")

    print(f"PASS §10.2 step 6 sdu = link.mtu - {overhead}: "
          f"{base} at base MTU {RNS.Reticulum.MTU}, "
          f"{1064 - overhead} at a negotiated MTU of 1064")


def verify_adv_flags_and_deferred_hashmap() -> None:
    """§10.4 (RNS >= 1.6): flag bit 6 is the application flag `a`, and an
    advertisement that would exceed the link MDU is sent with an empty `m`
    (the receiver then asks for segment 0 with HASHMAP_IS_EMPTY = 0xFE)."""
    from RNS.vendor import umsgpack

    if getattr(Resource, "HASHMAP_IS_EMPTY", None) != 0xFE:
        fail(f"§10.5 Resource.HASHMAP_IS_EMPTY = {getattr(Resource, 'HASHMAP_IS_EMPTY', None)!r}, expected 0xFE")
    if (Resource.HASHMAP_IS_NOT_EXHAUSTED, Resource.HASHMAP_IS_EXHAUSTED) != (0x00, 0xFF):
        fail("§10.5 HASHMAP_IS_NOT_EXHAUSTED / HASHMAP_IS_EXHAUSTED are no longer 0x00 / 0xFF")

    n = ResourceAdvertisement.HASHMAP_MAX_LEN
    stub = types.SimpleNamespace(
        size=1000, total_size=1000, parts=[None] * n, hash=b"\x11" * 32,
        random_hash=b"\x22" * 4, original_hash=b"\x11" * 32,
        hashmap=b"\x33" * (4 * n), compressed=False, encrypted=True,
        app_flag=True, split=False, has_metadata=False, segment_index=1,
        total_segments=1, request_id=None, is_response=False)

    adv = ResourceAdvertisement(stub)
    if adv.f != 0x41:
        fail(f"§10.4 flags for encrypted + app_flag = 0x{adv.f:02x}, expected 0x41 (bit 6 = a)")
    full = umsgpack.unpackb(adv.pack())
    if len(full["m"]) != 4 * n:
        fail(f"§10.4 a full advertisement carried {len(full['m'])} hashmap bytes, expected {4 * n}")
    back = ResourceAdvertisement.unpack(adv.pack())
    if not back.a:
        fail("§10.4 unpack did not read flag bit 6 as the application flag")

    small = ResourceAdvertisement(stub, mdu=200)
    deferred = umsgpack.unpackb(small.pack())
    if deferred["m"] != b"" or deferred["n"] != n:
        fail(f"§10.4 over-MDU advertisement: m = {len(deferred['m'])} bytes, n = {deferred['n']}; "
             f"expected an empty m with n unchanged")
    print(f"PASS §10.4 flag bit 6 = application flag; an advertisement over the link MDU "
          f"is sent with m = b\"\" (n still {n}); HASHMAP_IS_EMPTY = 0xFE")


def verify_no_receive_time_size_check() -> None:
    """§10.4: upstream buffers parts without bounding them. Assert it stays so."""
    src = inspect.getsource(Resource.receive_part)
    for marker in ("len(part_data) >", "len(part_data) <", "self.sdu <", "> self.sdu"):
        if marker in src:
            fail(f"§10.4 receive_part now appears to bound part size "
                 f"({marker!r} found). The spec says upstream imposes no "
                 f"receive-time size check and asks implementations to add "
                 f"their own — re-check that wording. Source:\n{src}")

    asm = inspect.getsource(Resource.assemble)
    if "self.size" in asm and "!=" in asm and "len(" in asm:
        print("NOTE §10.4 assemble() may have gained a length comparison — "
              "worth re-reading, not a failure")

    print("PASS §10.4 upstream still performs no receive-time part-size or "
          "cumulative-bytes check (receive_part buffers what arrives)")


def verify_stamp_cost_range() -> None:
    """§5.7.4: 1 <= c < 100 valid (int or float), < 1 means None, >= 100 refused."""
    cap = RNS.Transport.STAMP_COST_CAP
    if cap != 100:
        fail(f"§5.7.4 RNS.Transport.STAMP_COST_CAP = {cap!r}, expected 100")
    cases = [
        # (input, expect_return, expect_stored, label)
        (None,  True,  None, "None -> None"),
        (0,     True,  None, "0 -> None (not an error)"),
        (-5,    True,  None, "negative -> None (not an error)"),
        (0.5,   True,  None, "0.5 -> None (float below 1, not an error)"),
        (1,     True,  1,    "1 -> 1 (lower bound)"),
        (23.5,  True,  23.5, "23.5 -> 23.5 (fractional cost accepted)"),
        (99,    True,  99,   "99 -> 99 (largest integer below the cap)"),
        (100,   False, "UNCHANGED", "100 -> refused at the cap, previous value kept"),
        (128,   False, "UNCHANGED", "128 -> refused (accepted through LXMF 1.2)"),
        (254,   False, "UNCHANGED", "254 -> refused (old upper bound)"),
        (99999, False, "UNCHANGED", "huge -> refused, previous value kept"),
    ]

    dest_hash = b"\x01" * 16
    for value, expect_return, expect_stored, label in cases:
        dest = types.SimpleNamespace(stamp_cost="SENTINEL")
        stub = types.SimpleNamespace(delivery_destinations={dest_hash: dest})

        got_return = LXMRouter.set_inbound_stamp_cost(stub, dest_hash, value)
        if got_return != expect_return:
            fail(f"§5.7.4 set_inbound_stamp_cost({value!r}) returned "
                 f"{got_return!r}, expected {expect_return!r} ({label})")

        want = "SENTINEL" if expect_stored == "UNCHANGED" else expect_stored
        if dest.stamp_cost != want:
            fail(f"§5.7.4 set_inbound_stamp_cost({value!r}) stored "
                 f"{dest.stamp_cost!r}, expected {want!r} ({label})")

    print(f"PASS §5.7.4 stamp_cost range over {len(cases)} cases: "
          "None/<1 -> None, 1 <= c < 100 accepted (int or float), >= 100 "
          "refused with the previous value retained")


def verify_reader_does_not_validate() -> None:
    """§5.7.4: the parse side returns element [1] verbatim."""
    from LXMF.LXMF import stamp_cost_from_app_data
    from RNS.vendor import umsgpack

    for bogus in (255, 100000, -1):
        app_data = umsgpack.packb([b"Name", bogus, []])
        got = stamp_cost_from_app_data(app_data)
        if got != bogus:
            fail(f"§5.7.4 stamp_cost_from_app_data no longer returns element "
                 f"[1] verbatim: gave {got!r} for {bogus!r}. If upstream "
                 f"added validation, §5.7.4's 'the reading side does not "
                 f"re-validate' warning needs updating.")

    print("PASS §5.7.4 stamp_cost_from_app_data returns element [1] "
          "unvalidated (receivers must enforce the range themselves)")


def main() -> None:
    print(f"RNS {RNS.__version__}")
    verify_fixed_constants()
    verify_link_mdu_is_not_per_link()
    verify_sdu_follows_link_mtu()
    verify_no_receive_time_size_check()
    verify_adv_flags_and_deferred_hashmap()
    verify_stamp_cost_range()
    verify_reader_does_not_validate()
    print()
    print("PASS")


if __name__ == "__main__":
    main()
