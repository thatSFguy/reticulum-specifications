"""
Verifier for SPEC.md S5 (LXMF wire format) — opportunistic delivery path.

Full end-to-end round-trip:

  1. Build two identities (Alice, Bob) and their `lxmf.delivery`
     destinations.
  2. Make Bob's identity discoverable to Alice by simulating an
     announce reception (RNS.Identity.remember).
  3. Construct an LXMF message from Alice to Bob with method =
     OPPORTUNISTIC.
  4. Pack the LXMF body per S5.1: dest_hash || src_hash ||
     signature(64) || msgpack_payload, then strip the leading
     dest_hash for opportunistic wire form.
  5. Confirm the wire body length and structure match S5.1.
  6. Encrypt to Bob via Token (S3.1 opportunistic form).
  7. Decrypt as Bob and confirm the plaintext matches the
     pre-encryption packed bytes.
  8. Re-prepend Bob's dest_hash to obtain the canonical Link-form
     LXMF body (S5.2), then parse via LXMessage.unpack_from_bytes.
  9. Confirm the parsed message has signature_validated == True,
     correct source_hash and destination_hash, and that
     content / title / fields round-trip.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import os
import sys
import tempfile

import RNS
import LXMF
from LXMF.LXMessage import LXMessage


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-lxmf-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def main():
    print(f"verify_lxmf_opportunistic.py against RNS {RNS.__version__} / "
          f"LXMF {LXMF.__version__}")
    init_minimal_rns()
    try:
        # --- 1, 2: identities, destinations, mutual discovery
        alice_id = RNS.Identity()
        bob_id   = RNS.Identity()

        alice_dest = RNS.Destination(alice_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                     "lxmf", "delivery")
        bob_dest   = RNS.Destination(bob_id,   RNS.Destination.IN, RNS.Destination.SINGLE,
                                     "lxmf", "delivery")

        # Make Bob's identity recallable to Alice
        RNS.Identity.remember(b"\x00"*32, bob_dest.hash, bob_id.get_public_key(), None)

        # Alice's outbound destination to Bob (this is what LXMessage uses
        # for encryption; it must hold Bob's public key).
        bob_dest_out = RNS.Destination(bob_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
                                       "lxmf", "delivery")

        # --- 3: construct LXMessage
        title    = "test title"
        content  = "hello reticulum from alice"
        fields   = {0xFF: "diag-marker"}
        lxm = LXMessage(
            destination    = bob_dest_out,
            source         = alice_dest,
            content        = content.encode("utf-8"),
            title          = title.encode("utf-8"),
            fields         = fields,
            desired_method = LXMessage.OPPORTUNISTIC,
        )

        # --- 4: pack
        lxm.pack()

        # S5.5 message_id = SHA256(dest_hash || src_hash || msgpack_payload)
        # which lxm.hash already exposes.
        if lxm.hash is None or len(lxm.hash) != 32:
            fail(f"S5.5 message_id missing or wrong length: {len(lxm.hash) if lxm.hash else None}")

        # S5.1/5.2: lxm.packed = dest(16) || src(16) || sig(64) || msgpack
        packed = lxm.packed
        if packed[:16] != bob_dest.hash:
            fail(f"S5.2 dest_hash slot mismatch:\n  got:  {packed[:16].hex()}\n"
                 f"  want: {bob_dest.hash.hex()}")
        if packed[16:32] != alice_dest.hash:
            fail(f"S5.2 src_hash slot mismatch:\n  got:  {packed[16:32].hex()}\n"
                 f"  want: {alice_dest.hash.hex()}")
        if len(packed[32:96]) != 64:
            fail(f"S5.2 signature slot is {len(packed[32:96])} bytes, want 64")

        print("PASS S5.1/5.2 LXMF body layout: dest(16) || src(16) || sig(64) || msgpack")

        # --- 5: opportunistic wire form strips the leading dest_hash
        # See S5.1 and LXMessage.__as_packet line 631:
        #   RNS.Packet(dest, self.packed[16:])  for OPPORTUNISTIC
        opp_wire_plaintext = packed[16:]   # what gets fed to Token encrypt
        if opp_wire_plaintext[:16] != alice_dest.hash:
            fail("S5.1 opportunistic-stripped form must start with src_hash")

        # --- 6: encrypt to Bob via Token (this is what Packet.pack does)
        ciphertext = bob_dest_out.encrypt(opp_wire_plaintext)
        # Wire-layout sanity: ephemeral_pub(32) || iv(16) || aes(...) || hmac(32)
        if len(ciphertext) < 32 + 16 + 16 + 32:
            fail(f"opportunistic ciphertext too short: {len(ciphertext)} bytes")
        if (len(ciphertext) - 32 - 16 - 32) % 16 != 0:
            fail("opportunistic ciphertext AES body not block-aligned")

        # --- 7: decrypt as Bob
        # bob_dest is the IN-direction destination for Bob; it can decrypt.
        decrypted = bob_dest.decrypt(ciphertext)
        if decrypted != opp_wire_plaintext:
            fail("S3 round-trip mismatch on opportunistic LXMF body")
        print("PASS S3 + S5.1 opportunistic encrypt/decrypt round-trip")

        # --- 8: re-prepend dest_hash to feed unpack_from_bytes
        full_lxmf = bob_dest.hash + decrypted

        # --- 9: parse and validate
        # Make Alice's identity recallable to Bob too so signature
        # validation can find her public key.
        RNS.Identity.remember(b"\x00"*32, alice_dest.hash, alice_id.get_public_key(), None)

        parsed = LXMessage.unpack_from_bytes(full_lxmf)
        if not parsed.signature_validated:
            fail(f"S5.5/5.6 unpack_from_bytes did not validate signature: "
                 f"unverified_reason={getattr(parsed, 'unverified_reason', None)}")
        if parsed.destination_hash != bob_dest.hash:
            fail(f"parsed dest_hash mismatch: {parsed.destination_hash.hex()} vs {bob_dest.hash.hex()}")
        if parsed.source_hash != alice_dest.hash:
            fail(f"parsed src_hash mismatch: {parsed.source_hash.hex()} vs {alice_dest.hash.hex()}")
        if parsed.title_as_string() != title:
            fail(f"parsed title mismatch: {parsed.title_as_string()!r} vs {title!r}")
        if parsed.content_as_string() != content:
            fail(f"parsed content mismatch: {parsed.content_as_string()!r} vs {content!r}")
        if parsed.fields != fields:
            fail(f"parsed fields mismatch: {parsed.fields!r} vs {fields!r}")

        print(f"PASS S5.5/5.6 unpack_from_bytes round-trip: title/content/fields preserved, "
              f"signature_validated=True")

    finally:
        try:
            RNS.Reticulum.exit_handler()
        except Exception:
            pass

    print("ALL PASS")


if __name__ == "__main__":
    main()
