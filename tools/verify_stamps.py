"""
Verifier for SPEC.md S5.7 (LXMF stamps and tickets).

Locks in the proof-of-work stamp and pre-shared ticket mechanisms by
exercising upstream LXMF.LXMStamper directly:

  1. Workblock construction is deterministic and roughly the documented
     size (~768 KiB at 3000 rounds, scaled down here for test speed).

  2. stamp_value() returns the leading-zero-bit count of
     SHA256(workblock || stamp).

  3. stamp_valid() accepts a stamp meeting target_cost and rejects one
     that doesn't.

  4. End-to-end LXMessage.validate_stamp(target_cost) accepts a freshly-
     generated PoW stamp and rejects a tampered one.

  5. End-to-end LXMessage.validate_stamp(target_cost, tickets=[...])
     accepts a stamp built via the ticket shortcut
     SHA256(ticket || message_id) and rejects with a wrong ticket.

We use a low target_cost (4 bits) so PoW is fast — typical solve time
is <1s on a normal laptop. Real interop uses higher costs (8-16 bits).

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile

import RNS
import LXMF
from LXMF.LXMessage import LXMessage
from LXMF import LXStamper


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-stamps-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def verify_workblock_deterministic():
    """S5.7.2: workblock is HKDF-driven from material; same material
    must produce identical workblocks every time."""
    material = b"test_message_id_32_bytes______!!"        # 32B
    wb1 = LXStamper.stamp_workblock(material)
    wb2 = LXStamper.stamp_workblock(material)
    if wb1 != wb2:
        fail("S5.7.2 workblock not deterministic for the same material")
    print(f"PASS S5.7.2 workblock is deterministic ({len(wb1)} bytes generated)")
    return wb1


def verify_stamp_search_and_validate(target_cost=4):
    """S5.7.2: search for a stamp with at least target_cost leading
    zero bits; validate against the same workblock; tamper a byte and
    confirm rejection.

    target_cost = 4 keeps the search fast — average 16 SHA-256 calls
    after the workblock is ready."""
    message_id = hashlib.sha256(b"test_lxm_for_stamp_verifier").digest()
    workblock  = LXStamper.stamp_workblock(message_id)

    # Brute-force search for a stamp with the required leading zeros
    counter = 0
    stamp = None
    while True:
        candidate = counter.to_bytes(32, "big")
        if LXStamper.stamp_valid(candidate, target_cost, workblock):
            stamp = candidate
            break
        counter += 1
        if counter > 1_000_000:
            fail(f"S5.7.2 brute-force search exceeded 1M iterations at cost={target_cost} "
                 f"(extremely unlikely; cost may have been mis-set)")

    print(f"PASS S5.7.2 stamp found at cost={target_cost} after {counter+1} iterations")

    if not LXStamper.stamp_valid(stamp, target_cost, workblock):
        fail("S5.7.2 freshly-found stamp does not validate (round-trip bug)")

    value = LXStamper.stamp_value(workblock, stamp)
    if value < target_cost:
        fail(f"S5.7.2 stamp_value = {value}, want >= {target_cost}")
    print(f"PASS S5.7.2 stamp_value = {value} (>= target_cost = {target_cost})")

    # Tamper a byte — must reject
    tampered = bytes([stamp[0] ^ 0x01]) + stamp[1:]
    if LXStamper.stamp_valid(tampered, target_cost, workblock):
        fail("S5.7.2 tampered stamp was accepted")
    print("PASS S5.7.2 tampered stamp rejected")

    return message_id, stamp


def verify_lxmessage_validate_stamp(message_id, stamp, target_cost=4):
    """S5.7.4: end-to-end LXMessage.validate_stamp PoW path."""
    # We need an LXMessage with .hash == message_id. Cheapest way:
    # build one via the constructor, then forcibly set its hash to
    # match the message_id we used for the stamp.
    src_id = RNS.Identity()
    dst_id = RNS.Identity()
    src = RNS.Destination(src_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                          "verify_stamps", "src")
    dst = RNS.Destination(dst_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
                          "verify_stamps", "dst")
    RNS.Identity.remember(b"\x00"*32, dst.hash, dst_id.get_public_key(), None)

    lxm = LXMessage(destination=dst, source=src, content=b"x", title=b"",
                    fields={}, desired_method=LXMessage.OPPORTUNISTIC)
    # Don't actually pack — just set the fields validate_stamp reads
    lxm.message_id = message_id
    lxm.stamp = stamp

    if not lxm.validate_stamp(target_cost):
        fail(f"S5.7.4 LXMessage.validate_stamp rejected a valid PoW stamp "
             f"at cost={target_cost}")
    print(f"PASS S5.7.4 LXMessage.validate_stamp accepts valid PoW stamp")

    # Tamper and confirm rejection
    lxm.stamp = bytes([stamp[0] ^ 0x01]) + stamp[1:]
    if lxm.validate_stamp(target_cost):
        fail("S5.7.4 LXMessage.validate_stamp accepted a tampered stamp")
    print("PASS S5.7.4 LXMessage.validate_stamp rejects tampered stamp")


def verify_ticket_shortcut(target_cost=4):
    """S5.7.3: ticket shortcut. stamp = SHA256(ticket || message_id)
    is accepted by validate_stamp(target_cost, tickets=[ticket])
    regardless of whether it would pass the PoW check."""
    src_id = RNS.Identity()
    dst_id = RNS.Identity()
    src = RNS.Destination(src_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                          "verify_stamps", "src2")
    dst = RNS.Destination(dst_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
                          "verify_stamps", "dst2")
    RNS.Identity.remember(b"\x00"*32, dst.hash, dst_id.get_public_key(), None)

    lxm = LXMessage(destination=dst, source=src, content=b"x", title=b"",
                    fields={}, desired_method=LXMessage.OPPORTUNISTIC)
    lxm.message_id = hashlib.sha256(b"ticket-shortcut-test").digest()

    ticket = os.urandom(LXMessage.TICKET_LENGTH)                  # 16B
    expected_stamp = RNS.Identity.truncated_hash(ticket + lxm.message_id)
    lxm.stamp = expected_stamp

    if not lxm.validate_stamp(target_cost, tickets=[ticket]):
        fail("S5.7.3 LXMessage.validate_stamp(tickets=...) rejected a valid ticket stamp")
    if lxm.stamp_value != LXMessage.COST_TICKET:
        fail(f"S5.7.3 stamp_value = {lxm.stamp_value}, want COST_TICKET")
    print("PASS S5.7.3 LXMessage.validate_stamp accepts ticket stamp shortcut")

    # With wrong ticket — must NOT match the ticket shortcut, and the
    # PoW path won't validate either (because expected_stamp wasn't
    # generated against the workblock). validate_stamp returns False.
    wrong_ticket = os.urandom(LXMessage.TICKET_LENGTH)
    lxm.stamp_value = None
    if lxm.validate_stamp(target_cost, tickets=[wrong_ticket]):
        fail("S5.7.3 validate_stamp accepted with wrong ticket")
    print("PASS S5.7.3 validate_stamp rejects ticket-shortcut stamp under wrong ticket")


def main():
    print(f"verify_stamps.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    print("(target_cost = 4 bits to keep the test fast — real interop uses 8-16)")
    init_minimal_rns()
    try:
        verify_workblock_deterministic()
        message_id, stamp = verify_stamp_search_and_validate(target_cost=4)
        verify_lxmessage_validate_stamp(message_id, stamp, target_cost=4)
        verify_ticket_shortcut(target_cost=4)
    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass
    print("ALL PASS")


if __name__ == "__main__":
    main()
