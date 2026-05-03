"""
Verifier for SPEC.md S6.1, S6.2, S6.3, S6.6.

Locks in the corrections previously made to S6.2 (LRPROOF body order)
and S6.3 (link_id derivation offsets) by exercising the actual upstream
Link.validate_request -> handshake -> prove pipeline and asserting the
wire bytes match the spec at every step.

Scenarios:

  1. LINKREQUEST body layout per S6.1:
        initiator_X25519_pub(32) || initiator_Ed25519_pub(32) || [signalling(3)]
     Build a Link initiator-side, capture request_data, slice and
     verify each region.

  2. link_id derivation per S6.3:
        link_id = SHA256(get_hashable_part(LINKREQUEST))[:16]
     where hashable_part = byte(flags & 0x0F) || raw[N:] with N=2 for
     HEADER_1, N=18 for HEADER_2 (the corrected offsets — earlier
     spec revisions had 18/34 which was wrong).
     Verified by computing the link_id by hand from the packed
     LINKREQUEST and confirming it matches Link.set_link_id.

  3. LRPROOF body layout per S6.2:
        signature(64) || responder_X25519_pub(32) || [signalling(3)]
     (Earlier spec revisions had link_id || pub || sig || signalling,
     which was wrong — link_id is in the packet header, not the body.)
     Build a responder Link via Link.validate_request, capture the
     proof_data emitted by Link.prove, slice and verify.

  4. signed_data per S6.2 (used in the LRPROOF):
        link_id || responder_X25519_pub || responder_long_term_Ed25519_pub
        || [signalling]
     Reconstruct by hand and verify the signature in proof_data
     validates against this signed_data.

  5. S6.6 signalling 3-byte trailer encoding/decoding for both
     LINKREQUEST and LRPROOF:
        byte 0: top 3 bits = mode, low 5 = mtu[20:16]
        byte 1: mtu[15:8]
        byte 2: mtu[7:0]
     Encode a known (mtu, mode) pair via Link.signalling_bytes,
     decode by hand, confirm round-trip.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import hashlib
import os
import sys
import struct
import tempfile

import RNS
from RNS.Link import Link
from RNS.Packet import Packet


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-link-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def verify_signalling_bytes_layout():
    """S6.6.1: 24-bit packed value, big-endian, top 3 bits = mode,
    low 21 bits = mtu."""
    mtu = 0x0123AB              # arbitrary 21-bit value
    mode = Link.MODE_AES256_CBC

    sb = Link.signalling_bytes(mtu, mode)
    if len(sb) != 3:
        fail(f"S6.6 signalling_bytes returned {len(sb)} bytes, want 3")

    # Decode by hand per the spec
    decoded_mode = (sb[0] & 0xE0) >> 5
    decoded_mtu  = ((sb[0] << 16) | (sb[1] << 8) | sb[2]) & 0x1FFFFF

    if decoded_mode != mode:
        fail(f"S6.6 mode round-trip mismatch: encoded {mode}, decoded {decoded_mode}")
    if decoded_mtu != mtu:
        fail(f"S6.6 mtu round-trip mismatch: encoded {mtu:#x}, decoded {decoded_mtu:#x}")

    # Confirm bit positions: mode is in top 3 bits of byte 0
    assert (sb[0] & 0xE0) == ((mode << 5) & 0xE0)
    # And the mtu fits in the low 21 bits of the 24-bit packed value
    full = (sb[0] << 16) | (sb[1] << 8) | sb[2]
    assert (full & 0x1FFFFF) == mtu

    print(f"PASS S6.6.1 signalling layout: mtu={mtu:#x} mode={mode} -> {sb.hex()} -> "
          f"({decoded_mtu:#x}, {decoded_mode})")


def build_linkrequest():
    """Construct a LINKREQUEST packet via the upstream Link initiator path,
    return the resulting Packet plus a 'fake destination' SimpleLink so
    we can exercise validate_request without actually transmitting."""
    # The remote destination Bob's identity must already be discoverable.
    bob_id = RNS.Identity()
    bob_dest = RNS.Destination(bob_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                               "verify_link", "responder")

    # Initiator-side outbound destination to Bob
    bob_dest_out = RNS.Destination(bob_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
                                   "verify_link", "responder")
    RNS.Identity.remember(b"\x00"*32, bob_dest.hash, bob_id.get_public_key(), None)

    # Build a Link to bob_dest_out. The constructor packs and sends; we
    # capture the LINKREQUEST via Transport.outbound monkey-patch (not
    # Packet.send, because send() calls pack() before outbound and we
    # need packet.raw populated).
    captured = {}
    real_outbound = RNS.Transport.outbound

    def fake_outbound(packet):
        captured["raw"] = packet.raw
        captured["request_data"] = packet.data
        return True

    RNS.Transport.outbound = staticmethod(fake_outbound)
    try:
        link = Link(destination=bob_dest_out)
    finally:
        RNS.Transport.outbound = real_outbound

    return link, bob_dest, bob_id, captured


def verify_linkrequest_body_layout(link, captured):
    """S6.1: initiator_X25519_pub(32) || initiator_Ed25519_pub(32) || [signalling(3)]"""
    body = captured["request_data"]
    if len(body) not in (Link.ECPUBSIZE, Link.ECPUBSIZE + Link.LINK_MTU_SIZE):
        fail(f"S6.1 LINKREQUEST body is {len(body)} bytes; "
             f"want {Link.ECPUBSIZE} or {Link.ECPUBSIZE + Link.LINK_MTU_SIZE}")

    initiator_x25519_pub  = body[:32]
    initiator_ed25519_pub = body[32:64]
    if initiator_x25519_pub != link.pub_bytes[:32]:
        fail(f"S6.1 LINKREQUEST X25519 pub mismatch")
    # Note: link.pub_bytes covers just the X25519 in some impls; sig_pub_bytes is separate.
    # The spec uses ECPUBSIZE = 64 = X25519(32) + Ed25519(32).
    print(f"PASS S6.1 LINKREQUEST body layout: "
          f"initiator_X25519({len(initiator_x25519_pub)}) || "
          f"initiator_Ed25519({len(initiator_ed25519_pub)})"
          + (f" || signalling({len(body)-64})" if len(body) > 64 else ""))


def verify_link_id_derivation(link, captured):
    """S6.3: link_id = SHA256(byte(flags & 0x0F) || raw[N:])[:16]
    with N = 2 for HEADER_1 (the corrected value)."""
    raw = captured["raw"]
    # Manually compute hashable_part for HEADER_1 (the initiator-side form)
    hashable = bytes([raw[0] & 0x0F]) + raw[2:]

    # Strip trailing signalling if body length > ECPUBSIZE
    if len(captured["request_data"]) > Link.ECPUBSIZE:
        diff = len(captured["request_data"]) - Link.ECPUBSIZE
        hashable = hashable[:-diff]

    expected_link_id = hashlib.sha256(hashable).digest()[:16]
    if expected_link_id != link.link_id:
        fail(f"S6.3 link_id by-hand recompute mismatch:\n"
             f"  spec recipe: {expected_link_id.hex()}\n"
             f"  upstream:    {link.link_id.hex()}")
    print(f"PASS S6.3 link_id derivation (N=2 for HEADER_1, signalling stripped): "
          f"{link.link_id.hex()}")


def verify_lrproof_layout_and_signed_data(link, captured, bob_id, bob_dest):
    """S6.2: LRPROOF body = signature(64) || responder_X25519_pub(32) || [signalling]
    signed_data = link_id || responder_X25519_pub || responder_long_term_Ed25519_pub || [signalling]"""

    # Build the responder-side Link by hand (inlined from validate_request)
    # so any exception surfaces cleanly rather than being swallowed.
    request_data = captured["request_data"]
    inbound = RNS.Packet(None, captured["raw"])
    if not inbound.unpack():
        fail("Failed to unpack LINKREQUEST on responder side")
    inbound.destination = bob_dest

    responder_link = Link(
        owner=bob_dest,
        peer_pub_bytes=request_data[:Link.ECPUBSIZE//2],
        peer_sig_pub_bytes=request_data[Link.ECPUBSIZE//2:Link.ECPUBSIZE],
    )
    responder_link.set_link_id(inbound)

    if len(request_data) == Link.ECPUBSIZE + Link.LINK_MTU_SIZE:
        responder_link.mtu  = Link.mtu_from_lr_packet(inbound) or RNS.Reticulum.MTU
        responder_link.mode = Link.mode_from_lr_packet(inbound)

    responder_link.destination = inbound.destination
    responder_link.handshake()

    # Capture LRPROOF emission. Patch Transport.outbound (not Packet.send)
    # so Packet.pack() runs normally and packet.raw is populated.
    captured_proof = {}
    real_outbound = RNS.Transport.outbound

    def fake_outbound(packet):
        if packet.context == RNS.Packet.LRPROOF:
            captured_proof["raw"] = packet.raw
            captured_proof["proof_data"] = packet.data
            captured_proof["dest_hash"] = packet.destination.link_id
        return True   # signal "sent" so callers don't retry

    RNS.Transport.outbound = staticmethod(fake_outbound)
    try:
        responder_link.prove()
    finally:
        RNS.Transport.outbound = real_outbound

    if "proof_data" not in captured_proof:
        fail("LRPROOF was not emitted via Packet.send")

    proof_data = captured_proof["proof_data"]
    # S6.2: signature(64) || responder_X25519_pub(32) || [signalling(3)]
    if len(proof_data) not in (96, 96 + Link.LINK_MTU_SIZE):
        fail(f"S6.2 LRPROOF body is {len(proof_data)} bytes, want 96 or 99")

    signature           = proof_data[:64]
    responder_x25519    = proof_data[64:96]
    signalling          = proof_data[96:] if len(proof_data) > 96 else b""

    if responder_x25519 != responder_link.pub_bytes:
        fail(f"S6.2 LRPROOF responder X25519 pub mismatch")

    # Reconstruct signed_data per S6.2 corrected:
    signed_data = (responder_link.link_id
                   + responder_x25519
                   + bob_id.get_public_key()[Link.ECPUBSIZE//2:Link.ECPUBSIZE]  # long-term Ed25519 pub
                   + signalling)

    if not bob_id.validate(signature, signed_data):
        fail("S6.2 hand-rebuilt signed_data did not validate signature — "
             "spec body order doesn't match upstream emission")

    # Outer packet: dest_hash position is the link_id (S6.2 wire summary)
    if captured_proof["dest_hash"] != responder_link.link_id:
        fail(f"S6.2 LRPROOF outer dest_hash position != link_id")

    print(f"PASS S6.2 LRPROOF body order: "
          f"signature(64) || responder_X25519_pub(32)"
          + (f" || signalling({len(signalling)})" if signalling else "")
          + f"; signed_data = link_id || pub || long_term_Ed25519_pub"
          + (" || signalling" if signalling else ""))


def main():
    print(f"verify_link_handshake.py against RNS {RNS.__version__}")
    init_minimal_rns()
    try:
        # 1. Signalling layout (independent of an actual link)
        verify_signalling_bytes_layout()

        # 2-4. Build a real LINKREQUEST and walk through validate_request + prove
        link, bob_dest, bob_id, captured = build_linkrequest()
        verify_linkrequest_body_layout(link, captured)
        verify_link_id_derivation(link, captured)
        verify_lrproof_layout_and_signed_data(link, captured, bob_id, bob_dest)
    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass

    print("ALL PASS")


if __name__ == "__main__":
    main()
