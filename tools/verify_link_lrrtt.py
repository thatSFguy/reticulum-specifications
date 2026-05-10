"""
Verifier for SPEC.md S6.4.2 — LRRTT, the initiator's link-activation packet.

Consumes `test-vectors/links.json`. Asserts that the recorded LRRTT
vector decomposes as documented in SPEC.md S6.4.2:

  - Wire header is HEADER_1 with no transport_id (per S6.4.3).
  - packet_type = DATA (0x00).
  - destination_type = LINK (0x03), dest_hash = link_id.
  - context = LRRTT (0xfe).
  - Body is link-form Token encryption (S3.1, no eph_pub prefix):
        IV(16) || AES256_CBC(plaintext, key, iv) || HMAC(32)
    keyed off the link's derived_key.
  - Plaintext decodes via umsgpack as a single float64 matching
    the recorded rtt_seconds.

Run from repo root:

    python tools/verify_link_lrrtt.py

Prints PASS lines and exits 0 if every assertion holds.
"""

from __future__ import annotations

import json
import os
import sys

import RNS
from RNS.Cryptography.Token import Token
from RNS.vendor import umsgpack


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC_PATH  = os.path.join(REPO_ROOT, "test-vectors", "links.json")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main() -> int:
    with open(VEC_PATH, "r", encoding="utf-8") as f:
        vectors = json.load(f)["vectors"]

    for v in vectors:
        label    = v["label"]
        expected = v["expected"]
        if "lrrtt" not in expected:
            print(f"SKIP {label}: no lrrtt field")
            continue

        lrrtt        = expected["lrrtt"]
        link_id      = bytes.fromhex(expected["link_id_hex"])
        derived_key  = bytes.fromhex(expected["derived_key_hex"])
        rtt_seconds  = lrrtt["rtt_seconds"]
        iv           = bytes.fromhex(lrrtt["iv_hex"])
        plaintext    = bytes.fromhex(lrrtt["plaintext_hex"])
        raw          = bytes.fromhex(lrrtt["raw_hex"])
        body         = bytes.fromhex(lrrtt["body_hex"])

        # 1. Header decomposition (S2.1 + S6.4.2 + S6.4.3).
        if len(raw) < 19:
            fail(f"{label}: raw is shorter than the 19-byte HEADER_1 frame")

        flags        = raw[0]
        hops         = raw[1]
        dest_hash    = raw[2:18]
        context      = raw[18]
        ciphertext   = raw[19:]

        header_type     = (flags & 0b01000000) >> 6
        context_flag    = (flags & 0b00100000) >> 5
        transport_type  = (flags & 0b00010000) >> 4
        destination_type = (flags & 0b00001100) >> 2
        packet_type     = (flags & 0b00000011)

        if header_type != 0:
            fail(f"{label}: header_type = {header_type}, expected HEADER_1 (0) per S6.4.3")
        if packet_type != 0:
            fail(f"{label}: packet_type = {packet_type}, expected DATA (0) per S6.4.2")
        if destination_type != 3:
            fail(f"{label}: destination_type = {destination_type}, expected LINK (3) per S6.4.2")
        if context != 0xfe:
            fail(f"{label}: context = 0x{context:02x}, expected LRRTT (0xfe) per S6.4.2")
        if dest_hash != link_id:
            fail(f"{label}: dest_hash = {dest_hash.hex()}, expected link_id = {link_id.hex()}")
        if hops != 0:
            fail(f"{label}: hops = {hops}, originator emits 0")

        print(f"PASS {label} S6.4.2 LRRTT header: HEADER_1 + DATA + LINK + ctx=0xfe + dest_hash=link_id")
        print(f"     (context_flag={context_flag}, transport_type={transport_type})")

        # 2. Body length and IV match the link-form Token layout (S3.1).
        if ciphertext != body:
            fail(f"{label}: raw[19:] != body — vector self-inconsistency")
        if ciphertext[:16] != iv:
            fail(f"{label}: body IV {ciphertext[:16].hex()} != recorded iv_hex {iv.hex()}")

        print(f"PASS {label} S3.1 link-form Token: 16B IV || ciphertext || 32B HMAC, no eph_pub prefix")

        # 3. Token decrypt round-trip using the link's derived_key.
        recovered = Token(derived_key).decrypt(body)
        if recovered != plaintext:
            fail(f"{label}: Token decrypt did not recover plaintext\n"
                 f"  got: {recovered.hex() if recovered else None}\n"
                 f"  exp: {plaintext.hex()}")
        print(f"PASS {label} S6.4.2 body decrypts under derived_key to recorded plaintext")

        # 4. Plaintext is umsgpack(float) matching rtt_seconds.
        decoded = umsgpack.unpackb(plaintext)
        if not isinstance(decoded, float):
            fail(f"{label}: plaintext umsgpack-decoded to {type(decoded).__name__}, expected float")
        if decoded != rtt_seconds:
            fail(f"{label}: decoded float {decoded!r} != recorded rtt_seconds {rtt_seconds!r}")
        # msgpack float64 tag is 0xcb plus 8 IEEE 754 bytes — total 9 bytes.
        if len(plaintext) != 9 or plaintext[0] != 0xcb:
            fail(f"{label}: plaintext is not a 9-byte msgpack float64 (tag 0xcb)")
        print(f"PASS {label} S6.4.2 plaintext = umsgpack(float64) rtt_seconds={rtt_seconds!r} (9B, tag 0xcb)")

    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
