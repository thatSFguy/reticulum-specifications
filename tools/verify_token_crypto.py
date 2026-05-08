"""
Verifier for SPEC.md S3 (Token cryptography).

Exercises the modified-Fernet Token construction in two directions
against upstream RNS 1.2.4:

  1. Identity-style encrypt (with ephemeral X25519 prefix) per S3.1
     opportunistic form. Round-trips a known plaintext through
     RNS.Identity.encrypt -> RNS.Identity.decrypt.

  2. Symmetric Token encrypt/decrypt (no ephemeral prefix) per S3.1
     link-derived form. Builds a fresh symmetric key, encrypts a
     known plaintext, validates the wire layout against the spec,
     and round-trips back through Token.decrypt.

  3. HMAC-then-AES order check (S3.3): a tampered HMAC byte is
     detected before AES decryption is attempted, so the function
     raises on HMAC failure rather than returning a malformed
     plaintext.

  4. HKDF salt = identity_hash check (S3.2): re-derive the
     encryption key by hand using HKDF over the ECDH shared secret
     with salt = recipient identity_hash, and confirm the resulting
     key matches the one upstream uses to encrypt.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import sys

import RNS
from RNS.Cryptography.Token import Token
from RNS.Cryptography.HKDF import hkdf


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def verify_opportunistic_encrypt_decrypt():
    """S3.2 / S3.3: identity-style encrypt with ephemeral pub prefix,
    HKDF derived from ECDH(ephemeral, recipient.X25519_pub) with
    salt = recipient.identity_hash."""
    recipient = RNS.Identity()
    plaintext = b"hello, reticulum"

    # Encrypt to recipient's identity. This builds an ephemeral X25519
    # keypair internally, does ECDH, derives the Token key, and emits
    #   ephemeral_pub(32) || iv(16) || aes_ciphertext(...) || hmac(32)
    ciphertext = recipient.encrypt(plaintext)

    # Wire-layout sanity:
    if len(ciphertext) < 32 + 16 + 16 + 32:
        fail(f"opportunistic ciphertext too short: {len(ciphertext)} bytes")
    eph_pub_bytes = ciphertext[:32]
    iv             = ciphertext[32:48]
    hmac           = ciphertext[-32:]
    aes_body       = ciphertext[48:-32]
    if len(aes_body) % 16 != 0:
        fail(f"AES body not block-aligned: {len(aes_body)} bytes (must be multiple of 16)")
    if len(iv) != 16:
        fail(f"IV is {len(iv)} bytes, want 16")
    if len(hmac) != 32:
        fail(f"HMAC is {len(hmac)} bytes, want 32")

    # Round-trip through decrypt — uses recipient's long-term X25519
    # private key (no ratchets configured on this fresh identity).
    decrypted = recipient.decrypt(ciphertext)
    if decrypted != plaintext:
        fail(f"opportunistic round-trip mismatch:\n"
             f"  plaintext: {plaintext!r}\n"
             f"  decrypted: {decrypted!r}")

    print("PASS S3.1/3.2/3.3 opportunistic Token encrypt/decrypt round-trip")
    return recipient, eph_pub_bytes, iv, hmac, aes_body


def verify_hkdf_salt_is_identity_hash(recipient, eph_pub_bytes, iv, hmac_bytes, aes_body):
    """S3.2: confirm HKDF salt is the recipient's 16-byte identity_hash,
    not the dest_hash or ratchet_pub or anything else."""
    # We can't observe the exact ephemeral private key (it was generated
    # inside RNS.Identity.encrypt). But we CAN take the recipient's
    # private key and the captured ephemeral_pub, perform ECDH from the
    # recipient's side, derive the Token key under salt = identity_hash,
    # and confirm decrypt succeeds — equivalent to asserting the salt.
    # Use the RNS-level X25519 dispatcher so the resulting public-key
    # object matches whichever provider (proxy vs fallback) the recipient's
    # private key uses — exchange() requires both sides be the same kind.
    from RNS.Cryptography import X25519PublicKey

    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared  = recipient.prv.exchange(eph_pub)

    derived = hkdf(
        length=64,
        derive_from=shared,
        salt=recipient.hash,            # <-- the 16-byte identity_hash
        context=None,
    )

    # Reconstruct the Token from the derived key and verify HMAC + decrypt
    token = Token(derived)
    body = iv + aes_body + hmac_bytes
    plaintext = token.decrypt(body)
    if plaintext != b"hello, reticulum":
        fail(f"HKDF-salt-by-hand decrypt mismatch: {plaintext!r}")

    print("PASS S3.2 HKDF salt is recipient.identity_hash (decrypt succeeds with hand-derived key)")


def verify_symmetric_token_form(plaintext=b"link DATA payload"):
    """S3.1 link-derived form: no ephemeral prefix, just iv || ciphertext || hmac."""
    key = Token.generate_key()                       # 64 bytes for AES-256-CBC
    if len(key) != 64:
        fail(f"Token.generate_key returned {len(key)} bytes, want 64")

    token = Token(key)
    wire = token.encrypt(plaintext)

    # Layout: iv(16) || ciphertext(N*16) || hmac(32)
    if len(wire) < 16 + 16 + 32:
        fail(f"link-derived ciphertext too short: {len(wire)}")
    iv         = wire[:16]
    ciphertext = wire[16:-32]
    hmac_bytes = wire[-32:]
    if len(ciphertext) % 16 != 0:
        fail(f"link-derived ciphertext body not block-aligned: {len(ciphertext)}")

    decrypted = token.decrypt(wire)
    if decrypted != plaintext:
        fail(f"link-derived round-trip mismatch:\n  in:  {plaintext!r}\n  out: {decrypted!r}")

    print("PASS S3.1 link-derived Token form (no ephemeral prefix, iv||ct||hmac)")
    return key, wire


def verify_hmac_before_aes(key, wire):
    """S3.3: HMAC verification MUST run before AES decryption.
    A tampered HMAC byte should raise rather than produce malformed plaintext."""
    token = Token(key)

    # Flip a single bit in the HMAC region — the last 32 bytes
    tampered = wire[:-1] + bytes([wire[-1] ^ 0x01])

    try:
        token.decrypt(tampered)
        fail("S3.3 tampered HMAC was accepted — encrypt-then-MAC verification missing")
    except ValueError as e:
        if "HMAC" not in str(e):
            fail(f"S3.3 decrypt raised but with wrong error: {e}")
        # Good: HMAC mismatch raised before AES decrypt could run

    # Also flip a byte in the ciphertext (HMAC stays intact in shape but
    # the HMAC wouldn't match the corrupted body). Same expected outcome.
    if len(wire) > 64:
        tampered2 = wire[:32] + bytes([wire[32] ^ 0x01]) + wire[33:]
        try:
            token.decrypt(tampered2)
            fail("S3.3 tampered ciphertext was accepted — HMAC-then-AES order broken")
        except ValueError:
            pass

    print("PASS S3.3 HMAC-then-AES order (tampered ciphertext rejected at HMAC stage)")


def verify_pkcs7_padding_handled():
    """S3.2 step 6: AES-CBC PKCS#7 padding is applied automatically by the
    Token; clients must NOT pad manually (would produce double padding)."""
    # 1-byte plaintext: PKCS#7 will pad with 15 bytes of 0x0F
    one_byte = b"x"
    key = Token.generate_key()
    token = Token(key)
    wire = token.encrypt(one_byte)
    out = token.decrypt(wire)
    if out != one_byte:
        fail(f"S3.2 step 6 PKCS#7 round-trip on 1B plaintext failed: {out!r}")

    # 16-byte plaintext (one full block): PKCS#7 adds a full block of 0x10
    sixteen = b"sixteen ABCDEFGH"
    assert len(sixteen) == 16
    wire = Token(key).encrypt(sixteen)
    if (len(wire) - 16 - 32) != 32:
        fail(f"S3.2 step 6 16B plaintext should produce 32B AES body (one + full pad block), "
             f"got {len(wire) - 16 - 32}")
    out = Token(key).decrypt(wire)
    if out != sixteen:
        fail(f"S3.2 step 6 PKCS#7 round-trip on 16B plaintext failed: {out!r}")

    print("PASS S3.2 step 6 PKCS#7 padding (1B and 16B boundaries)")


def main():
    print(f"verify_token_crypto.py against RNS {RNS.__version__}")
    recipient, eph_pub_bytes, iv, hmac_bytes, aes_body = verify_opportunistic_encrypt_decrypt()
    verify_hkdf_salt_is_identity_hash(recipient, eph_pub_bytes, iv, hmac_bytes, aes_body)
    key, wire = verify_symmetric_token_form()
    verify_hmac_before_aes(key, wire)
    verify_pkcs7_padding_handled()
    print("ALL PASS")


if __name__ == "__main__":
    main()
