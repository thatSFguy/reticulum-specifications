"""
Verifier for SPEC.md S1.1 (identity composition) and S1.2 (destination hash).

Reads test-vectors/identities.json and, for each vector:
  - Loads the private-key bytes via RNS.Identity.from_bytes (the upstream API
    for the on-bytes form X25519_priv || Ed25519_priv).
  - Confirms identity.get_public_key() matches expected.public_key_hex
    (X25519_pub || Ed25519_pub).
  - Confirms identity.hash matches expected.identity_hash_hex
    (= SHA256(public_key)[:16]).
  - Confirms SHA256(SHA256(name)[:10] || identity_hash)[:16] equals
    expected.destination_hash_hex.
  - Cross-checks RNS.Destination.hash(identity_hash, *name.split(".")) ==
    expected.destination_hash_hex (i.e. upstream agrees with the by-hand recipe).

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import RNS


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC_PATH  = os.path.join(REPO_ROOT, "test-vectors", "identities.json")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def verify_vector(v: dict) -> None:
    label   = v["label"]
    inputs  = v["inputs"]
    expect  = v["expected"]
    full    = v["destination_full_name"]

    prv = bytes.fromhex(inputs["private_key_hex"])
    if prv.hex() != inputs["x25519_priv_hex"] + inputs["ed25519_priv_hex"]:
        fail(f"{label}: private_key_hex != x25519_priv_hex||ed25519_priv_hex")

    identity = RNS.Identity.from_bytes(prv)
    if identity is None:
        fail(f"{label}: RNS.Identity.from_bytes returned None")

    if identity.get_public_key().hex() != expect["public_key_hex"]:
        fail(f"{label}: public_key mismatch\n"
             f"  got: {identity.get_public_key().hex()}\n"
             f"  want: {expect['public_key_hex']}")

    expected_idhash = hashlib.sha256(identity.get_public_key()).digest()[:16]
    if expected_idhash.hex() != expect["identity_hash_hex"]:
        fail(f"{label}: SHA256(public_key)[:16] != identity_hash")
    if identity.hash.hex() != expect["identity_hash_hex"]:
        fail(f"{label}: identity.hash != expected (RNS disagrees with manual)")

    name_hash_calc = hashlib.sha256(full.encode("utf-8")).digest()[:10]
    if name_hash_calc.hex() != expect["name_hash_hex"]:
        fail(f"{label}: name_hash for {full!r}: got {name_hash_calc.hex()} "
             f"want {expect['name_hash_hex']}")

    dest_calc = hashlib.sha256(name_hash_calc + identity.hash).digest()[:16]
    if dest_calc.hex() != expect["destination_hash_hex"]:
        fail(f"{label}: dest_hash recipe mismatch\n"
             f"  got:  {dest_calc.hex()}\n"
             f"  want: {expect['destination_hash_hex']}")

    rns_dest_hash = RNS.Destination.hash(identity.hash, *full.split("."))
    if rns_dest_hash.hex() != expect["destination_hash_hex"]:
        fail(f"{label}: RNS.Destination.hash != expected\n"
             f"  RNS.Destination.hash: {rns_dest_hash.hex()}\n"
             f"  want:                 {expect['destination_hash_hex']}")

    print(f"PASS {label}: identity, identity_hash, dest_hash for {full!r}")


def main():
    print(f"verify_destination_hash.py against RNS {RNS.__version__}")
    if not os.path.isfile(VEC_PATH):
        fail(f"Missing test-vectors file: {VEC_PATH}")

    with open(VEC_PATH, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if "vectors" not in payload:
        fail(f"Bad test-vectors file: missing 'vectors' key")

    for vec in payload["vectors"]:
        verify_vector(vec)

    print(f"ALL PASS ({len(payload['vectors'])} identity vectors)")


if __name__ == "__main__":
    main()
