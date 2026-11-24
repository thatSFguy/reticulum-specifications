"""
Verifier for the LXMF 1.3 / RNS 1.6 stamp-cost changes in SPEC.md §5.7.2,
§5.7.4, §5.8.2 and §5.8.5.

LXMF 1.3 moved the proof-of-work primitives into RNS (RNS/Stamps.py) and made
stamp costs fractional. Each claim below is a silent-failure surface for a
clean-room implementation, so each is asserted against the running upstream
code rather than its source text:

1. §5.7.2 — a whole-number cost c has target exactly 1 << (256 - c), the
   LXMF <= 1.2 target, so integer-cost stamps are bit-compatible both ways.
   Fractional targets sit strictly between their integer neighbours.
2. §5.7.2 — stamp_value is now a float on the 1/256 grid, and its floor is
   the legacy integer leading-zero count (stamp_value_legacy).
3. §5.7.2 callout — LXMF 1.3 accepts a stamp computed over the NON-expanded
   workblock (the bare message_id / transient_id / peering_id) for message
   stamps, propagation stamps and peering keys, while generate_stamp still
   produces expanded-workblock stamps.
4. §5.8.5 — the propagation-node announce is 8 elements: [5] holds the
   three costs rounded up to ints, [7] the real floats. Readers require at
   least 7 elements, prefer [7], and reject a malformed [7].
5. §5.7.4 — stamp_cost_from_app_data returns a numeric element [3] verbatim,
   with no range check.
6. §5.8.1 / §5.8.2 — LXMF's link costs (3.25), PN_STAMP_THROTTLE (300 s),
   and the Resource app flag that marks client submissions to a
   propagation node and bypasses the from_static_only gate.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import inspect
import math
import os
import sys
import tempfile
import types

import RNS
import RNS.Stamps as Stamps
import LXMF
from LXMF import LXMF as H
from LXMF import LXStamper
from LXMF.LXMessage import LXMessage
from LXMF.LXMPeer import LXMPeer
from LXMF.LXMRouter import LXMRouter
import RNS.vendor.umsgpack as umsgpack


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-lxmf-stamp-costs-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def sha_int(data: bytes) -> int:
    return int.from_bytes(RNS.Identity.full_hash(data), "big")


# --- 1. targets -------------------------------------------------------------

def verify_integer_targets_are_legacy():
    cap = RNS.Transport.STAMP_COST_CAP
    for c in range(0, cap + 1):
        if Stamps.target_from_cost(c) != 1 << (256 - c):
            fail(f"§5.7.2 target_from_cost({c}) != 1 << {256 - c}; integer-cost stamps "
                 f"are no longer bit-compatible with LXMF <= 1.2")
    for c in (1.5, 8.25, 12.7, 33.3, 98.99):
        lo, hi = Stamps.target_from_cost(math.ceil(c)), Stamps.target_from_cost(math.floor(c))
        t = Stamps.target_from_cost(c)
        if not lo < t < hi:
            fail(f"§5.7.2 fractional target for {c} is not strictly between its integer neighbours")
    if Stamps.quantize_cost(12.7) != 3251 / 256:
        fail(f"§5.7.2 quantize_cost(12.7) = {Stamps.quantize_cost(12.7)!r}, expected 3251/256")
    if Stamps.quantize_cost(cap + 50) != float(cap):
        fail("§5.7.2 quantize_cost no longer clamps to STAMP_COST_CAP")
    print(f"PASS §5.7.2 integer cost c -> target 1 << (256 - c) for c in 0..{cap}; "
          "fractional targets lie strictly between; costs quantize to 1/256 and clamp to the cap")


# --- 2. stamp_value ---------------------------------------------------------

def verify_stamp_value_floor_is_legacy():
    wb = os.urandom(64)
    for _ in range(4000):
        s = os.urandom(32)
        v, legacy = Stamps.stamp_value(wb, s), Stamps.stamp_value_legacy(wb, s)
        if not isinstance(v, float):
            fail(f"§5.7.2 stamp_value returned {type(v).__name__}, expected float")
        if math.floor(v) != legacy:
            fail(f"§5.7.2 floor(stamp_value) = {math.floor(v)} != stamp_value_legacy = {legacy}")
        if abs(v * 256 - round(v * 256)) > 1e-9:
            fail(f"§5.7.2 stamp_value {v!r} is not on the 1/256 grid")
    print("PASS §5.7.2 stamp_value is a float on the 1/256 grid whose floor is the "
          "legacy leading-zero count (4000 random stamps)")


# --- 3. non-expanded workblock acceptance -----------------------------------

def find_ne_only_stamp(material: bytes, cost: int, expand_rounds: int, size: int) -> bytes:
    """A stamp valid against the bare material but NOT against its expansion."""
    expanded = LXStamper.stamp_workblock(material, expand_rounds=expand_rounds)
    target = Stamps.target_from_cost(cost)
    for _ in range(200000):
        s = os.urandom(size)
        if sha_int(material + s) <= target and sha_int(expanded + s) > target:
            return s
    fail(f"could not find a non-expanded-only stamp at cost {cost}")


def verify_non_expanded_acceptance():
    cost = 6

    # Message stamp (LXMessage.validate_stamp)
    message_id = os.urandom(32)
    stamp = find_ne_only_stamp(message_id, cost, LXStamper.WORKBLOCK_EXPAND_ROUNDS, LXStamper.STAMP_SIZE)
    lxm = types.SimpleNamespace(message_id=message_id, stamp=stamp, stamp_value=None)
    if not LXMessage.validate_stamp(lxm, cost):
        fail("§5.7.2 validate_stamp rejected a stamp valid against the non-expanded workblock")
    print(f"PASS §5.7.2 LXMessage.validate_stamp accepts a non-expanded-workblock stamp "
          f"(value {lxm.stamp_value}) that the expanded workblock rejects")

    # Propagation stamp (LXStamper.validate_pn_stamp)
    lxm_data = os.urandom(LXMessage.LXMF_OVERHEAD + 64)
    transient_id = RNS.Identity.full_hash(lxm_data)
    pn_stamp = find_ne_only_stamp(transient_id, cost, LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN, LXStamper.STAMP_SIZE)
    tid, data, value, st = LXStamper.validate_pn_stamp(lxm_data + pn_stamp, cost)
    if tid != transient_id or data != lxm_data or st != pn_stamp:
        fail("§5.7.2 validate_pn_stamp rejected a non-expanded-workblock propagation stamp")
    print("PASS §5.7.2 validate_pn_stamp accepts a non-expanded-workblock propagation stamp")

    # Peering key (LXStamper.validate_peering_key)
    peering_id = os.urandom(32)
    key = find_ne_only_stamp(peering_id, cost, LXStamper.WORKBLOCK_EXPAND_ROUNDS_PEERING, LXStamper.STAMP_SIZE)
    if not LXStamper.validate_peering_key(peering_id, key, cost):
        fail("§5.8.4 validate_peering_key rejected a non-expanded-workblock peering key")
    print("PASS §5.8.4 validate_peering_key accepts a non-expanded-workblock peering key")

    # Generation still uses the expanded workblock.
    gen_id = os.urandom(32)
    gen_cost = 4
    stamp, value = LXStamper.generate_stamp(gen_id, gen_cost)
    if stamp is None or len(stamp) != LXStamper.STAMP_SIZE:
        fail(f"§5.7.2 generate_stamp returned {stamp!r}")
    if not Stamps.stamp_valid(stamp, gen_cost, LXStamper.stamp_workblock(gen_id)):
        fail("§5.7.2 generate_stamp output is not valid against the expanded workblock; "
             "LXMF <= 1.2 receivers would reject it")
    print(f"PASS §5.7.2 generate_stamp still emits expanded-workblock stamps "
          f"(cost {gen_cost}, value {value})")


# --- 4. propagation-node announce --------------------------------------------

def pn_app_data(cost, flex, peering):
    stub = types.SimpleNamespace(
        get_propagation_node_announce_metadata=lambda: {},
        propagation_node=True, from_static_only=False,
        propagation_stamp_cost=cost, propagation_stamp_cost_flexibility=flex,
        peering_cost=peering, propagation_per_transfer_limit=256,
        propagation_per_sync_limit=10240)
    return LXMRouter.get_propagation_node_app_data(stub)


def verify_pn_announce_shape():
    blob = pn_app_data(16.5, 2.5, 18.0)
    data = umsgpack.unpackb(blob)
    if len(data) != 8:
        fail(f"§5.8.5 PN announce has {len(data)} elements, expected 8")
    if data[5] != [17, 3, 18] or not all(isinstance(x, int) for x in data[5]):
        fail(f"§5.8.5 element [5] = {data[5]!r}, expected rounded-up ints [17, 3, 18]")
    if data[7] != [16.5, 2.5, 18.0] or not all(isinstance(x, float) for x in data[7]):
        fail(f"§5.8.5 element [7] = {data[7]!r}, expected floats [16.5, 2.5, 18.0]")
    print(f"PASS §5.8.5 LXMF {LXMF.__version__} PN announce is 8 elements; "
          f"[5] = {data[5]} (ceil), [7] = {data[7]}")

    if not H.pn_announce_data_is_valid(blob):
        fail("§5.8.5 pn_announce_data_is_valid rejected upstream's own 8-element announce")
    if H.pn_stamp_cost_from_app_data(blob) != 16.5:
        fail("§5.8.5 pn_stamp_cost_from_app_data does not prefer element [7]")
    seven = umsgpack.packb(data[:7])
    if not H.pn_announce_data_is_valid(seven) or H.pn_stamp_cost_from_app_data(seven) != 17:
        fail("§5.8.5 a 7-element (LXMF <= 1.2) announce is no longer accepted, or [5] is not the fallback")
    if H.pn_announce_data_is_valid(umsgpack.packb(data[:6])):
        fail("§5.8.5 a 6-element announce was accepted; the minimum is 7")
    bad7 = umsgpack.packb(data[:7] + ["not a list"])
    if H.pn_announce_data_is_valid(bad7):
        fail("§5.8.5 a non-list element [7] was accepted")
    print("PASS §5.8.5 readers need >= 7 elements, prefer [7], fall back to [5], "
          "and reject a malformed [7]")


# --- 5. delivery announce reader ---------------------------------------------

def verify_reader_does_not_validate_element_3():
    for bogus in (1e9, 255, -3.5):
        got = H.stamp_cost_from_app_data(umsgpack.packb([b"N", 1, [], bogus]))
        if got != bogus:
            fail(f"§5.7.4 stamp_cost_from_app_data gave {got!r} for element [3] = {bogus!r}; "
                 f"if upstream now validates, update §5.7.4's warning")
    print("PASS §5.7.4 stamp_cost_from_app_data returns a numeric element [3] unvalidated")


# --- 6. constants and the Resource app flag ----------------------------------

def verify_router_constants_and_app_flag():
    if (LXMRouter.DELIVERY_LINK_COST, LXMRouter.PROPAGATION_LINK_COST) != (3.25, 3.25):
        fail(f"§5.8.1 link costs = {(LXMRouter.DELIVERY_LINK_COST, LXMRouter.PROPAGATION_LINK_COST)}, "
             f"expected (3.25, 3.25)")
    if LXMRouter.PN_STAMP_THROTTLE != 300:
        fail(f"§5.8.2 PN_STAMP_THROTTLE = {LXMRouter.PN_STAMP_THROTTLE}, expected 300")
    if LXMPeer.ERROR_THROTTLED != 0xF6:
        fail("§5.8.2 ERROR_THROTTLED is no longer 0xf6")

    as_resource = inspect.getsource(LXMessage._LXMessage__as_resource)
    if "self.propagation_packed" not in as_resource or "app_flag=True" not in as_resource:
        fail("§5.8.2 the propagation upload Resource no longer sets app_flag=True")
    gate = inspect.getsource(LXMRouter.propagation_resource_advertised)
    if "if self.from_static_only and not resource.app_flag_set():" not in gate:
        fail("§5.8.2 propagation_resource_advertised no longer exempts app-flagged "
             "Resources from the from_static_only check")
    print("PASS §5.8.1/§5.8.2 link costs 3.25/3.25, PN_STAMP_THROTTLE = 300, propagation "
          "uploads set the Resource app flag, and the flag bypasses from_static_only")


def main():
    print(f"verify_lxmf_stamp_costs.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    init_minimal_rns()
    verify_integer_targets_are_legacy()
    verify_stamp_value_floor_is_legacy()
    verify_non_expanded_acceptance()
    verify_pn_announce_shape()
    verify_reader_does_not_validate_element_3()
    verify_router_constants_and_app_flag()
    print("ALL PASS")


if __name__ == "__main__":
    main()
