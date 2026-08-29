"""
Verifier for SPEC.md §2.2 and §4.5 — receive-side ingress bounds added in RNS 1.5.2.

Verifies:
  - §2.2: `Packet.unpack` rejects a frame whose data field is empty, for both
          HEADER_1 (19 bytes) and HEADER_2 (35 bytes), and accepts the same
          frame with a single data byte. New in RNS 1.5.2; 1.4.2 and 1.5.0
          both parsed a zero-data frame successfully. The HEADER_2 case is the
          one framing never caught: at 35 bytes it clears TCPInterface's
          `frame_len <= HEADER_MINSIZE` (19) bound.
  - §4.5: the emit half — `Packet.pack` refuses to build an announce whose
          frame exceeds `Reticulum.MTU` (500). Long-standing, not new.
  - §4.5: the receive half — `Transport.inbound` drops an ANNOUNCE whose raw
          frame exceeds `Reticulum.MTU` and counts it as a protocol violation
          against the receiving interface, before `validate_announce` runs. An
          announce of exactly MTU bytes is accepted. New in RNS 1.5.2. The
          interface stub carries a deliberately large HW_MTU so that the
          general frame-size bound cannot fire first — this isolates the
          announce-specific rule, and mirrors the real gap it closes: an
          interface's own HW_MTU reaches 512 KiB on a 1 Gbps link, so before
          1.5.2 an oversized announce got a full signature validation.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

import RNS
from RNS import Transport


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-ingress-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


class StubInterface:
    """Minimal interface standing in for the receiving interface.

    HW_MTU is set far above Reticulum.MTU on purpose: the general frame-size
    bound in preprocess_inbound would otherwise fire before the announce
    bound, and the test would pass for the wrong reason.
    """

    def __init__(self):
        self.ifac_identity = None
        self.ifac_size = 0
        self.HW_MTU = 65535
        self.reports_phy_stats = False
        self.violations = []
        self.announces_received = 0

    def protocol_violation(self, description=None):
        self.violations.append(description)
        return None

    def ifac_violation(self, description=None):
        self.violations.append(f"IFAC: {description}")
        return None

    def packet_filter_hit(self):
        return None

    def received_announce(self, size=None):
        self.announces_received += 1

    def __str__(self):
        return "StubInterface"


def verify_zero_length_data():
    """§2.2: a frame with an empty data field is rejected at unpack time."""
    dest_hash = b"\xaa" * 16
    transport_id = b"\xbb" * 16

    # flags: header_type in bit 6, destination_type SINGLE (0b00) at bits 3-2,
    # packet_type DATA (0b00) at bits 1-0. Byte 1 is hops.
    header1_empty = bytes([0x00, 0x00]) + dest_hash + bytes([0x00])
    header2_empty = bytes([0x40, 0x00]) + transport_id + dest_hash + bytes([0x00])

    if len(header1_empty) != 19:
        fail(f"HEADER_1 zero-data frame is {len(header1_empty)} bytes, expected 19")
    if len(header2_empty) != 35:
        fail(f"HEADER_2 zero-data frame is {len(header2_empty)} bytes, expected 35")

    for name, raw in (("HEADER_1", header1_empty), ("HEADER_2", header2_empty)):
        if RNS.Packet(None, raw).unpack():
            fail(f"Packet.unpack accepted a zero-data {name} frame "
                 f"({len(raw)} bytes); RNS 1.5.2 must reject it")

        # The same frame with one byte of data must parse, so the rejection is
        # attributable to the empty data field and not to the header itself.
        if not RNS.Packet(None, raw + b"\x01").unpack():
            fail(f"Packet.unpack rejected a {name} frame carrying 1 data byte")

    print("PASS §2.2 Packet.unpack rejects a zero-length data field "
          "(HEADER_1 and HEADER_2), accepts 1 data byte")


def build_announce_of_size(dest, target_size):
    """Build an announce whose packed frame is exactly target_size bytes.

    Past Reticulum.MTU this has to raise the packet's own MTU attribute first,
    because Packet.pack enforces the emit-side bound (see
    verify_announce_emit_bound). A non-conformant sender is exactly what the
    receive-side rule exists to reject, so the test has to synthesise one.
    """
    probe = dest.announce(app_data=b"", send=False)
    probe.pack()
    overhead = len(probe.raw)
    if target_size < overhead:
        fail(f"cannot build a {target_size}-byte announce; the empty-app_data "
             f"announce is already {overhead} bytes")

    pkt = dest.announce(app_data=b"\x00" * (target_size - overhead), send=False)
    if target_size > pkt.MTU:
        pkt.MTU = target_size
    pkt.pack()
    if len(pkt.raw) != target_size:
        fail(f"announce packed to {len(pkt.raw)} bytes, wanted {target_size}")
    return pkt


def verify_announce_emit_bound(dest):
    """§4.5: Packet.pack refuses to emit an announce over Reticulum.MTU."""
    mtu = RNS.Reticulum.MTU
    probe = dest.announce(app_data=b"", send=False)
    probe.pack()
    overhead = len(probe.raw)

    pkt = dest.announce(app_data=b"\x00" * (mtu + 1 - overhead), send=False)
    if pkt.MTU != mtu:
        fail(f"announce packet MTU is {pkt.MTU}, expected Reticulum.MTU {mtu}")
    try:
        pkt.pack()
    except OSError:
        print(f"PASS §4.5 Packet.pack refuses to emit an announce over the "
              f"{mtu}-byte MTU")
        return
    fail(f"Packet.pack emitted a {len(pkt.raw)}-byte announce, over the "
         f"{mtu}-byte MTU")


def verify_announce_ingress_bound(dest):
    """§4.5: an announce over Reticulum.MTU is refused before validation."""
    mtu = RNS.Reticulum.MTU

    at_limit = build_announce_of_size(dest, mtu)
    over_limit = build_announce_of_size(dest, mtu + 1)

    iface = StubInterface()
    Transport.inbound(over_limit.raw, iface)
    time.sleep(0.1)
    if not iface.violations:
        fail(f"a {mtu + 1}-byte announce raised no protocol violation; "
             f"RNS 1.5.2 must refuse it")
    if not any("announce" in (v or "").lower() for v in iface.violations):
        fail(f"the {mtu + 1}-byte announce was refused, but not by the "
             f"announce bound: {iface.violations}")
    if iface.announces_received:
        fail(f"the {mtu + 1}-byte announce reached received_announce; it must "
             f"be dropped before validate_announce")

    iface = StubInterface()
    Transport.inbound(at_limit.raw, iface)
    time.sleep(0.1)
    if iface.violations:
        fail(f"an announce of exactly {mtu} bytes was refused: {iface.violations}")
    if not iface.announces_received:
        fail(f"an announce of exactly {mtu} bytes did not reach "
             f"received_announce; it should be accepted")

    print(f"PASS §4.5 Transport.inbound refuses an announce over the "
          f"{mtu}-byte MTU as a protocol violation, accepts one at exactly {mtu}")


def main():
    reticulum = init_minimal_rns()
    print(f"Running against RNS {RNS.__version__}")

    verify_zero_length_data()

    identity = RNS.Identity()
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                           "verify_ingress", "test")
    verify_announce_emit_bound(dest)
    verify_announce_ingress_bound(dest)

    print("PASS: all §2.2 / §4.5 ingress-bound checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
