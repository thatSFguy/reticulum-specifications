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
          Since RNS 1.6 it also refuses a HEADER_1 announce that would exceed
          the MTU once a relay inserts a 16-byte transport_id, so the largest
          emittable HEADER_1 announce is 484 bytes. 485 packed through 1.5.7.
  - §4.5: the receive half — `Transport.inbound` drops an ANNOUNCE whose raw
          frame exceeds `Reticulum.MTU` and counts it as a protocol violation
          against the receiving interface, before `validate_announce` runs. An
          announce of exactly MTU bytes is accepted. New in RNS 1.5.2. The
          interface stub carries a deliberately large HW_MTU so that the
          general frame-size bound cannot fire first — this isolates the
          announce-specific rule, and mirrors the real gap it closes: an
          interface's own HW_MTU reaches 512 KiB on a 1 Gbps link, so before
          1.5.2 an oversized announce got a full signature validation.
  - §4.5: since RNS 1.6 the receive half also refuses a HEADER_1 announce
          with fewer than 16 bytes of headroom under the MTU ("Excessive
          announce payload"), while a 500-byte HEADER_2 announce is still
          accepted. A 485-byte HEADER_1 announce was accepted through 1.5.7.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

import RNS
from RNS import Transport

# The exact violation texts preprocess_inbound records for the
# announce-specific bounds (RNS/Transport.py::preprocess_inbound).
EXCESSIVE_ANNOUNCE = "Excessive announce packet frame size"
EXCESSIVE_PAYLOAD = "Excessive announce payload"  # RNS >= 1.6
INSUFFICIENT_PAYLOAD = "Insufficient announce payload"  # RNS >= 1.6
ANNOUNCE_MIN_DATA = 64 + 10 + 10   # public_key || name_hash || random_hash
HEADER_1_LEN = 2 + 16 + 1          # flags, hops, dest_hash, context

TRANSPORT_ID_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
H1_ANNOUNCE_MAX = RNS.Reticulum.MTU - TRANSPORT_ID_LEN  # 484


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def wait_for(predicate, timeout: float = 5.0, interval: float = 0.01) -> bool:
    """Poll until `predicate()` holds. Transport.inbound hands the packet to
    the inbound_job thread, so the assertions below read state written by
    another thread; a fixed sleep is not a synchronisation point."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


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
        self.online = True
        self.violations = []
        self.announces_received = 0
        self.held_announces = 0
        # RNS >= 1.6 reads a per-interface hop limiter (None disables it)
        # and accounts accepted/filtered bytes on the interface.
        self.hop_limiter = None
        self.parent_interface = None
        self.rxb = 0
        self.frxb = 0
        # RNS >= 1.6: validate_announce reads the interface's required
        # announce stamp value. Stamps are not enforced by default, so the
        # value only matters to the (unenforced) stamp check.
        self.destination_cost = getattr(Transport, "DESTINATION_COST", None)

    def should_ingress_limit(self):
        # False, so preprocess_inbound carries the announce through to the
        # dispatch path. Without this method the call raises AttributeError,
        # Transport.inbound's bare except swallows it, and the "accepted at
        # exactly MTU" case silently verifies nothing.
        return False

    def hold_announce(self, packet=None):
        self.held_announces += 1
        return None

    def filtered_announce(self):
        return None

    def protocol_violation(self, description=None, level=None):
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
    if target_size > H1_ANNOUNCE_MAX:
        # Lift the packet's own MTU past both emit-side checks (the general
        # one and, since RNS 1.6, the transport_id headroom one).
        pkt.MTU = target_size + TRANSPORT_ID_LEN
    pkt.pack()
    if len(pkt.raw) != target_size:
        fail(f"announce packed to {len(pkt.raw)} bytes, wanted {target_size}")
    return pkt


def _try_pack(dest, size, overhead):
    pkt = dest.announce(app_data=b"\x00" * (size - overhead), send=False)
    if pkt.MTU != RNS.Reticulum.MTU:
        fail(f"announce packet MTU is {pkt.MTU}, expected Reticulum.MTU "
             f"{RNS.Reticulum.MTU}")
    try:
        pkt.pack()
    except OSError as e:
        return None, str(e)
    return pkt, None


def verify_announce_emit_bound(dest):
    """§4.5: Packet.pack refuses to emit an announce over Reticulum.MTU, and
    (RNS >= 1.6) a HEADER_1 announce without room for a transport_id."""
    mtu = RNS.Reticulum.MTU
    probe = dest.announce(app_data=b"", send=False)
    probe.pack()
    overhead = len(probe.raw)

    pkt, err = _try_pack(dest, mtu + 1, overhead)
    if pkt is not None:
        fail(f"Packet.pack emitted a {len(pkt.raw)}-byte announce, over the "
             f"{mtu}-byte MTU")
    print(f"PASS §4.5 Packet.pack refuses to emit an announce over the "
          f"{mtu}-byte MTU")

    pkt, err = _try_pack(dest, H1_ANNOUNCE_MAX + 1, overhead)
    if pkt is not None:
        fail(f"Packet.pack emitted a {len(pkt.raw)}-byte HEADER_1 announce; "
             f"since RNS 1.6 the limit is {H1_ANNOUNCE_MAX} so a relay can "
             f"insert a transport_id")
    if "Transport-inserted" not in err:
        fail(f"the {H1_ANNOUNCE_MAX + 1}-byte HEADER_1 announce was refused, "
             f"but not by the transport_id headroom check: {err}")
    pkt, err = _try_pack(dest, H1_ANNOUNCE_MAX, overhead)
    if pkt is None:
        fail(f"Packet.pack refused a {H1_ANNOUNCE_MAX}-byte HEADER_1 announce: "
             f"{err}")
    print(f"PASS §4.5 Packet.pack emits a HEADER_1 announce of at most "
          f"{H1_ANNOUNCE_MAX} bytes (MTU minus a {TRANSPORT_ID_LEN}-byte "
          f"transport_id)")


def as_header2(raw: bytes, transport_id: bytes) -> bytes:
    """Rewrite a HEADER_1 frame as the HEADER_2 frame a relay would emit:
    header_type bit 6 and transport_type TRANSPORT (bit 4) set, transport_id
    inserted after the hops byte (§2.2)."""
    return bytes([raw[0] | 0x40 | 0x10, raw[1]]) + transport_id + raw[2:]


def verify_announce_ingress_bound(dest):
    """§4.5: an announce over Reticulum.MTU is refused before validation."""
    mtu = RNS.Reticulum.MTU

    at_limit = build_announce_of_size(dest, H1_ANNOUNCE_MAX)
    over_limit = build_announce_of_size(dest, mtu + 1)

    iface = StubInterface()
    Transport.inbound(over_limit.raw, iface)
    if not wait_for(lambda: bool(iface.violations)):
        fail(f"a {mtu + 1}-byte announce raised no protocol violation; "
             f"RNS >= 1.5.2 must refuse it")
    # Match the specific bound, not merely the word "announce": an
    # "Invalid announce signature" violation would otherwise satisfy this
    # assertion and hide the removal of the size check.
    if not any(EXCESSIVE_ANNOUNCE in (v or "") for v in iface.violations):
        fail(f"the {mtu + 1}-byte announce was refused, but not by the "
             f"announce bound ({EXCESSIVE_ANNOUNCE!r}): {iface.violations}")
    if iface.announces_received:
        fail(f"the {mtu + 1}-byte announce reached received_announce; it must "
             f"be dropped before validate_announce")

    print(f"PASS §4.5 Transport.inbound refuses an announce over the "
          f"{mtu}-byte MTU as a protocol violation")

    # RNS >= 1.6: a HEADER_1 announce must leave room for a transport_id.
    h1_over = build_announce_of_size(dest, H1_ANNOUNCE_MAX + 1)
    iface = StubInterface()
    Transport.inbound(h1_over.raw, iface)
    if not wait_for(lambda: bool(iface.violations) or iface.announces_received > 0):
        fail(f"a {H1_ANNOUNCE_MAX + 1}-byte HEADER_1 announce produced neither "
             f"a violation nor an accept within the timeout")
    if not any(EXCESSIVE_PAYLOAD in (v or "") for v in iface.violations):
        fail(f"a {H1_ANNOUNCE_MAX + 1}-byte HEADER_1 announce was not refused "
             f"by the transport_id headroom bound ({EXCESSIVE_PAYLOAD!r}); "
             f"violations: {iface.violations}, accepted: {iface.announces_received}")
    if iface.announces_received:
        fail(f"the {H1_ANNOUNCE_MAX + 1}-byte HEADER_1 announce reached "
             f"received_announce")
    print(f"PASS §4.5 Transport.inbound refuses a HEADER_1 announce over "
          f"{H1_ANNOUNCE_MAX} bytes (RNS >= 1.6)")

    # RNS >= 1.6: the data field must hold at least
    # public_key(64) || name_hash(10) || random_hash(10) = 84 bytes.
    hdr = at_limit.raw[:HEADER_1_LEN]
    for n, refused in ((ANNOUNCE_MIN_DATA - 1, True), (ANNOUNCE_MIN_DATA, False)):
        iface = StubInterface()
        Transport.inbound(hdr + at_limit.raw[HEADER_1_LEN:HEADER_1_LEN + n], iface)
        wait_for(lambda: bool(iface.violations))
        hit = any(INSUFFICIENT_PAYLOAD in (v or "") for v in iface.violations)
        if hit != refused:
            fail(f"a HEADER_1 announce with {n} data bytes was "
                 f"{'not ' if refused else ''}refused by the minimum-payload "
                 f"bound ({INSUFFICIENT_PAYLOAD!r}); violations: {iface.violations}")
        if iface.announces_received:
            fail(f"a HEADER_1 announce with {n} data bytes reached received_announce")
    print(f"PASS §4.5 Transport.inbound refuses announce data shorter than "
          f"{ANNOUNCE_MIN_DATA} bytes (RNS >= 1.6)")

    for name, raw in (
        (f"{H1_ANNOUNCE_MAX}-byte HEADER_1", at_limit.raw),
        (f"{mtu}-byte HEADER_2", as_header2(at_limit.raw, b"\xcc" * TRANSPORT_ID_LEN)),
    ):
        if len(raw) not in (H1_ANNOUNCE_MAX, mtu):
            fail(f"{name} test frame is {len(raw)} bytes")
        iface = StubInterface()
        Transport.inbound(raw, iface)
        if not wait_for(lambda: iface.announces_received > 0):
            fail(f"a {name} announce did not reach received_announce within the "
                 f"timeout; it should be accepted (violations: {iface.violations}, "
                 f"held: {iface.held_announces})")
        if iface.violations:
            fail(f"a {name} announce was refused: {iface.violations}")
        if iface.held_announces:
            fail(f"a {name} announce was held by ingress limiting; the stub must "
                 f"not trigger that path")
    print(f"PASS §4.5 Transport.inbound accepts a {H1_ANNOUNCE_MAX}-byte HEADER_1 "
          f"announce and a {mtu}-byte HEADER_2 one")


def main():
    reticulum = init_minimal_rns()
    # RNS >= 1.6 attaches a proof-of-work stamp to every emitted announce by
    # default (cost 25, tens of seconds of CPU). The bounds under test are
    # about frame size, and the stamp is part of app_data either way, so turn
    # stamping off to keep this verifier fast.
    if hasattr(Transport, "STAMP_DESTINATIONS"):
        Transport.STAMP_DESTINATIONS = False
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
