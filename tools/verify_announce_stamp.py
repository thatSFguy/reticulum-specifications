"""
Verifier for SPEC.md S4.7 (announce stamps, RNS >= 1.6).

Since RNS 1.6 an upstream announce ends its app_data with an 18-byte
extension payload carrying a proof-of-work stamp and the destination's
link-request stamp cost. This exercises upstream directly:

  1. Constants: EXTPAYLOADMARKER = 0xC1, EXTHEADERLENGTH = 2,
     STAMPLENGTH = 14, LRCOSTLENGTH = 2, EXTPAYLOADLENGTH = 18.

  2. Emit side (Destination._announce): app_data on the wire is
     app_data || 0xC1 || flags(0x00) || stamp(14) || frac || int,
     i.e. the 16-bit fixed-point lr_cost is written fraction byte FIRST.

  3. The stamp is over material = dest_hash || public_key || name_hash
     with NO workblock expansion: SHA-256(material || stamp) meets the
     target, and stamp_value(material, stamp) >= the emitted value.

  4. The trailer is inside the signed data.

  5. Receive side (Identity.validate_announce), stamps enabled but not
     enforced (the defaults):
       - valid stamp       -> trailer stripped from recalled app_data,
                              lr_cost recalled
       - insufficient stamp-> announce still accepted, app_data kept
                              VERBATIM with the trailer, lr_cost None
       - reserved bit 7 of the last byte set -> not a stamp, kept verbatim

  6. Enforced: insufficient -> "invalid_stamp", unstamped -> "no_stamp"
     (with signal_stamp=True).

Low costs (6) keep generation instant; real defaults are
DESTINATION_VALUE = 25.0 to emit, DESTINATION_COST = 23.5 to accept.

Exit code 0 on PASS, non-zero on FAIL. Fails at RNS 1.5.7, which has no
announce stamps.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile

import RNS


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-announce-stamp-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def fresh(raw):
    """A newly-received copy of the packet, with validation caches cleared."""
    RNS.Identity._reset_validation_caches()
    p = RNS.Packet(None, raw)
    p.unpack()
    return p


def forget(dest_hash):
    RNS.Identity.known_destinations.pop(dest_hash, None)


def verify_constants():
    I = RNS.Identity
    got = (I.EXTPAYLOADMARKER, I.EXTHEADERLENGTH, I.STAMPLENGTH, I.LRCOSTLENGTH, I.EXTPAYLOADLENGTH)
    if got != (0xC1, 2, 14, 2, 18):
        fail(f"S4.7 constants (marker, header, stamp, lrcost, total) = {got}, want (0xC1, 2, 14, 2, 18)")
    print("PASS S4.7 EXTPAYLOADMARKER 0xC1, 2+14+2 = 18-byte trailer")


def verify_emit(T):
    idn = RNS.Identity()
    dst = RNS.Destination(idn, RNS.Destination.IN, RNS.Destination.SINGLE, "verify_announce_stamp", "a")
    dst.set_link_cost(12.5)
    app = b"hello"
    pkt = dst.announce(app_data=app, send=False)
    pkt.pack()

    # context_flag 0 here (no ratchets enabled), so app_data starts at 148
    if pkt.context_flag != RNS.Packet.FLAG_UNSET:
        fail("S4.7 test destination unexpectedly emitted a ratchet")
    wire_app = pkt.data[148:]
    if len(wire_app) != len(app) + 18 or wire_app[:len(app)] != app:
        fail(f"S4.7 wire app_data is {wire_app.hex()}, want {app.hex()} + 18-byte trailer")
    ext = wire_app[-18:]
    if ext[0] != 0xC1 or ext[1] != 0x00:
        fail(f"S4.7 trailer header {ext[:2].hex()}, want c100")
    if ext[-2:] != bytes([0x80, 0x0C]):
        fail(f"S4.7 lr_cost 12.5 encoded as {ext[-2:].hex()}, want 800c (fraction byte first)")
    print(f"PASS S4.7 emitted trailer c1 00 <stamp:14> 80 0c for lr_cost 12.5")

    stamp = ext[2:16]
    material = dst.hash + idn.get_public_key() + dst.name_hash
    digest = hashlib.sha256(material + stamp).digest()
    lz = 256 - int.from_bytes(digest, "big").bit_length()
    if lz < int(T.DESTINATION_VALUE):
        fail(f"S4.7 SHA-256(dest_hash||public_key||name_hash||stamp) has {lz} leading zeros, want >= {T.DESTINATION_VALUE}")
    if not RNS.Stamps.stamp_valid(stamp, T.DESTINATION_VALUE, material):
        fail("S4.7 stamp does not validate against the unexpanded material")
    if RNS.Stamps.stamp_workblock(material, expand_rounds=0) != material:
        fail("S4.7 an unexpanded workblock is not the material itself")
    print(f"PASS S4.7 stamp is over dest_hash||public_key||name_hash, unexpanded ({lz} leading zero bits)")

    signed = dst.hash + idn.get_public_key() + dst.name_hash + pkt.data[74:84] + wire_app
    signature = pkt.data[84:148]
    if not idn.validate(signature, signed):
        fail("S4.7 signature does not cover the trailer")
    print("PASS S4.7 signature covers app_data including the trailer")

    # A second encoding check, fraction != 0.5
    dst.set_link_cost(3.25)
    p2 = dst.announce(app_data=app, send=False); p2.pack()
    if p2.data[-2:] != bytes([0x40, 0x03]):
        fail(f"S4.7 lr_cost 3.25 encoded as {p2.data[-2:].hex()}, want 4003")
    print("PASS S4.7 lr_cost 3.25 encoded as 40 03")

    dst.set_link_cost(12.5)
    pkt = dst.announce(app_data=app, send=False); pkt.pack()
    return dst, app, pkt.raw, stamp


def verify_receive(T, dst, app, raw, stamp):
    forget(dst.hash)
    if RNS.Identity.validate_announce(fresh(raw)) is not True:
        fail("S4.7 valid stamped announce rejected")
    if RNS.Identity.recall_app_data(dst.hash) != app:
        fail(f"S4.7 valid stamp: recalled app_data {RNS.Identity.recall_app_data(dst.hash)!r}, want trailer stripped {app!r}")
    if RNS.Identity.recall_link_cost(dst.hash) != 12.5:
        fail(f"S4.7 recalled lr_cost {RNS.Identity.recall_link_cost(dst.hash)!r}, want 12.5")
    print("PASS S4.7 valid stamp: trailer stripped, lr_cost 12.5 recalled")

    saved = T.DESTINATION_COST
    T.DESTINATION_COST = 60.0
    forget(dst.hash)
    if RNS.Identity.validate_announce(fresh(raw)) is not True:
        fail("S4.7 insufficient stamp rejected although enforcement is off")
    got = RNS.Identity.recall_app_data(dst.hash)
    if got is None or len(got) != len(app) + 18 or got[-18] != 0xC1:
        fail(f"S4.7 insufficient stamp: recalled app_data {got!r}, want app_data WITH trailer")
    if RNS.Identity.recall_link_cost(dst.hash) is not None:
        fail("S4.7 insufficient stamp: lr_cost recalled, want None")
    print("PASS S4.7 insufficient stamp, not enforced: accepted, app_data keeps the 18-byte trailer")

    T.STAMPS_ENFORCED = True
    forget(dst.hash)
    r = RNS.Identity.validate_announce(fresh(raw), signal_stamp=True)
    if r != "invalid_stamp":
        fail(f"S4.7 enforced insufficient stamp returned {r!r}, want 'invalid_stamp'")
    T.DESTINATION_COST = saved
    forget(dst.hash)
    if RNS.Identity.validate_announce(fresh(raw), signal_stamp=True) is not True:
        fail("S4.7 enforced: sufficient stamp rejected")
    print("PASS S4.7 enforced: insufficient -> 'invalid_stamp', sufficient -> True")

    # Unstamped announce, and a trailer with the reserved bit set.
    T.STAMP_DESTINATIONS = False
    try:
        d2 = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, "verify_announce_stamp", "b")
        q = d2.announce(app_data=b"x", send=False); q.pack()
        forget(d2.hash)
        r = RNS.Identity.validate_announce(fresh(q.raw), signal_stamp=True)
        if r != "no_stamp":
            fail(f"S4.7 enforced unstamped announce returned {r!r}, want 'no_stamp'")

        T.STAMPS_ENFORCED = False
        bad = b"hi" + bytes([0xC1, 0x00]) + stamp + bytes([0x80, 0x0C | 0x80])
        q = d2.announce(app_data=bad, send=False); q.pack()
        forget(d2.hash)
        if RNS.Identity.validate_announce(fresh(q.raw)) is not True:
            fail("S4.7 reserved-bit trailer: announce rejected")
        if RNS.Identity.recall_app_data(d2.hash) != bad or RNS.Identity.recall_link_cost(d2.hash) is not None:
            fail("S4.7 reserved bit 7 set: trailer was treated as a stamp")
    finally:
        T.STAMP_DESTINATIONS = True
        T.STAMPS_ENFORCED = False
    print("PASS S4.7 enforced unstamped -> 'no_stamp'; reserved bit 7 set -> not a stamp, kept verbatim")


def main():
    print(f"verify_announce_stamp.py against RNS {RNS.__version__}")
    init_minimal_rns()
    T = RNS.Transport
    if not hasattr(T, "STAMPS_ENABLED") or not hasattr(RNS.Identity, "EXTPAYLOADMARKER"):
        fail("S4.7 this RNS has no announce stamps (added in RNS 1.6)")
    try:
        if (T.STAMPS_ENABLED, T.STAMPS_ENFORCED, T.STAMP_DESTINATIONS) != (True, False, True):
            fail(f"S4.7 defaults (STAMPS_ENABLED, STAMPS_ENFORCED, STAMP_DESTINATIONS) = "
                 f"{(T.STAMPS_ENABLED, T.STAMPS_ENFORCED, T.STAMP_DESTINATIONS)}, want (True, False, True)")
        if (T.DESTINATION_VALUE, T.DESTINATION_COST, T.LR_COST, T.STAMP_COST_CAP) != (25.0, 23.5, 12.5, 100):
            fail("S4.7 default (DESTINATION_VALUE, DESTINATION_COST, LR_COST, STAMP_COST_CAP) changed: "
                 f"{(T.DESTINATION_VALUE, T.DESTINATION_COST, T.LR_COST, T.STAMP_COST_CAP)}")
        print("PASS S4.7 defaults: stamping on, enforcement off; value 25.0, cost 23.5, lr_cost 12.5, cap 100")
        verify_constants()
        T.DESTINATION_VALUE = 6.0
        T.DESTINATION_COST = 6.0
        dst, app, raw, stamp = verify_emit(T)
        verify_receive(T, dst, app, raw, stamp)
    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass
    print("ALL PASS")


if __name__ == "__main__":
    main()
