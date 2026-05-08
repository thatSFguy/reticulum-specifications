"""
Verifier for SPEC.md S6.5 (regular PROOF packet wire form).

Three scenarios against upstream RNS 1.2.4:

  1. Implicit-mode opportunistic DATA proof: when Reticulum is
     configured with use_implicit_proof = True (the upstream default
     per Reticulum.py:256), Identity.prove emits a 64-byte body
     containing only the Ed25519 signature over packet.packet_hash.

  2. Explicit-mode opportunistic DATA proof: when use_implicit_proof
     = False, Identity.prove emits a 96-byte body of
     packet_hash(32) || signature(64).

  3. Receiver-side length dispatch in PacketReceipt.validate_proof:
     accepts both 64- and 96-byte forms; rejects bodies of any other
     length.

Reticulum doesn't support reinitialisation in one process; we toggle
use_implicit_proof via the name-mangled class variable
RNS.Reticulum._Reticulum__use_implicit_proof rather than running
two separate Reticulum instances. The toggle is read by
should_use_implicit_proof(), which is what Identity.prove dispatches on.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import os
import sys
import tempfile

import RNS
from RNS.Packet import PacketReceipt


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-proof-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def set_implicit_proof(value: bool) -> None:
    RNS.Reticulum._Reticulum__use_implicit_proof = value
    if RNS.Reticulum.should_use_implicit_proof() != value:
        fail(f"Failed to toggle use_implicit_proof to {value}")


def build_packet_to_prove(identity, name_aspect):
    """Build a regular DATA packet that we can then prove. name_aspect lets
    each call create a unique destination so we don't trip the
    'already registered' check."""
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                           "verify_proof", name_aspect)
    pkt = RNS.Packet(dest, b"some payload bytes", create_receipt=False)
    pkt.pack()
    pkt.update_hash()
    pkt.fromPacked = True
    pkt.destination = dest
    return dest, pkt


def capture_proof_body(identity, target_packet):
    """Run identity.prove() against target_packet and capture the proof
    packet's body via Packet.send monkey-patch."""
    captured = {}
    real_packet_class = RNS.Packet

    class CapturePacket(real_packet_class):
        def send(self, *a, **kw):
            captured["data"] = self.data
            captured["context"] = self.context
            captured["packet_type"] = self.packet_type
            captured["dest_hash"] = self.destination.hash
            return None

    RNS.Packet = CapturePacket
    try:
        identity.prove(target_packet)
    finally:
        RNS.Packet = real_packet_class

    return captured


def verify_implicit_form(identity):
    set_implicit_proof(True)
    dest, pkt = build_packet_to_prove(identity, "implicit_test")
    captured = capture_proof_body(identity, pkt)

    body = captured["data"]
    if len(body) != PacketReceipt.IMPL_LENGTH:
        fail(f"S6.5 implicit proof body is {len(body)} bytes, want IMPL_LENGTH = "
             f"{PacketReceipt.IMPL_LENGTH} (= 64)")

    if not identity.validate(body, pkt.packet_hash):
        fail("S6.5 implicit proof body did not validate as signature(packet_hash)")

    if captured["dest_hash"] != pkt.packet_hash[:16]:
        fail(f"S6.5 implicit proof dest_hash != packet_hash[:16]")

    if captured["packet_type"] != RNS.Packet.PROOF:
        fail(f"S6.5 implicit proof packet_type = {captured['packet_type']}, want PROOF (3)")

    print("PASS S6.5.1 implicit proof form: 64B = Ed25519_sign(packet_hash) only")


def verify_explicit_form(identity):
    set_implicit_proof(False)
    dest, pkt = build_packet_to_prove(identity, "explicit_test")
    captured = capture_proof_body(identity, pkt)

    body = captured["data"]
    if len(body) != PacketReceipt.EXPL_LENGTH:
        fail(f"S6.5 explicit proof body is {len(body)} bytes, want EXPL_LENGTH = "
             f"{PacketReceipt.EXPL_LENGTH} (= 96)")

    if body[:32] != pkt.packet_hash:
        fail(f"S6.5 explicit proof body[:32] != packet_hash")

    if not identity.validate(body[32:], pkt.packet_hash):
        fail("S6.5 explicit proof body[32:] did not validate as signature(packet_hash)")

    print("PASS S6.5.1 explicit proof form: 96B = packet_hash(32) || Ed25519_sign(packet_hash)")


def verify_validator_length_dispatch(identity):
    """S6.5.5: validate_proof must accept both 64- and 96-byte bodies and
    reject anything else."""
    dest, pkt = build_packet_to_prove(identity, "validator_test")
    pkt.create_receipt = True
    pkt.receipt = PacketReceipt(pkt)
    receipt = pkt.receipt

    sig = identity.sign(pkt.packet_hash)
    implicit_proof = sig                                # 64 bytes
    explicit_proof = pkt.packet_hash + sig              # 96 bytes

    # Implicit
    if not receipt.validate_proof(implicit_proof):
        fail("S6.5.5 receiver rejected a valid implicit-form proof")

    # Reset and try explicit
    receipt.proved = False
    receipt.status = PacketReceipt.SENT
    if not receipt.validate_proof(explicit_proof):
        fail("S6.5.5 receiver rejected a valid explicit-form proof")

    # Bogus length
    receipt.proved = False
    receipt.status = PacketReceipt.SENT
    if receipt.validate_proof(b"\x00" * 80):
        fail("S6.5.5 receiver accepted an 80-byte body (must reject any non-{64,96})")

    print("PASS S6.5.5 receiver length-dispatch: accepts 64B and 96B, rejects 80B")


def main():
    print(f"verify_proof_packet.py against RNS {RNS.__version__}")
    init_minimal_rns()
    try:
        identity = RNS.Identity()
        verify_implicit_form(identity)
        verify_explicit_form(identity)
        verify_validator_length_dispatch(identity)
    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass

    print("ALL PASS")


if __name__ == "__main__":
    main()
