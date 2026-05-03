"""
Regenerator for test-vectors/identities.json.

Takes a list of fixed (X25519_priv || Ed25519_priv) inputs and emits the
expected `public_key`, `identity_hash`, and `destination_hash` (for
`lxmf.delivery`) that upstream RNS derives. Verifies the round-trip:
load -> derive -> reload-from-output and confirms outputs match.

Run from the repo root:

    python tools/regen_identities.py

Updates `test-vectors/identities.json` in place. Exit 0 on success.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import RNS


REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH   = os.path.join(REPO_ROOT, "test-vectors", "identities.json")


# Fixed test-vector inputs. The X25519 and Ed25519 private bytes are 32
# arbitrary but stable bytes; we use SHA-256 of a label so the values are
# reproducible in any environment without a private blob in the repo.
def vector_inputs():
    def derive(label: str, suffix: str) -> bytes:
        return hashlib.sha256(f"{label}.{suffix}".encode("utf-8")).digest()

    return [
        {
            "label":  "alice",
            "x25519_priv_hex":  derive("alice", "x25519").hex(),
            "ed25519_priv_hex": derive("alice", "ed25519").hex(),
            "destination_full_name": "lxmf.delivery",
        },
        {
            "label":  "bob",
            "x25519_priv_hex":  derive("bob",   "x25519").hex(),
            "ed25519_priv_hex": derive("bob",   "ed25519").hex(),
            "destination_full_name": "lxmf.delivery",
        },
    ]


def derive_with_upstream(spec: dict) -> dict:
    prv_bytes = bytes.fromhex(spec["x25519_priv_hex"]) + bytes.fromhex(spec["ed25519_priv_hex"])
    if len(prv_bytes) != 64:
        raise ValueError(f"prv_bytes for {spec['label']} must be 64 B, got {len(prv_bytes)}")

    identity = RNS.Identity.from_bytes(prv_bytes)
    if identity is None:
        raise RuntimeError(f"Identity.from_bytes returned None for {spec['label']}")

    public_key       = identity.get_public_key()              # 64 B: X25519_pub || Ed25519_pub
    identity_hash    = identity.hash                          # 16 B
    full_name        = spec["destination_full_name"]
    name_hash        = hashlib.sha256(full_name.encode("utf-8")).digest()[:10]
    destination_hash = hashlib.sha256(name_hash + identity_hash).digest()[:16]

    # Cross-check: RNS.Destination.hash with bytes-style identity argument
    # (no Identity instance — just the raw identity_hash) must agree.
    rns_dest_hash = RNS.Destination.hash(identity_hash, *full_name.split("."))
    if rns_dest_hash != destination_hash:
        raise RuntimeError(
            f"destination_hash mismatch for {spec['label']!r}: "
            f"hand-computed {destination_hash.hex()} vs RNS.Destination.hash "
            f"{rns_dest_hash.hex()}"
        )

    # Round-trip: rebuild identity from its private-key bytes again.
    rebuilt = RNS.Identity.from_bytes(identity.get_private_key())
    if rebuilt.hash != identity_hash:
        raise RuntimeError(
            f"private-key round-trip mismatch for {spec['label']!r}"
        )

    return {
        "label":            spec["label"],
        "destination_full_name": full_name,
        "inputs": {
            "x25519_priv_hex":  spec["x25519_priv_hex"],
            "ed25519_priv_hex": spec["ed25519_priv_hex"],
            "private_key_hex":  identity.get_private_key().hex(),  # X25519 || Ed25519
        },
        "expected": {
            "public_key_hex":       public_key.hex(),               # X25519_pub || Ed25519_pub
            "identity_hash_hex":    identity_hash.hex(),
            "name_hash_hex":        name_hash.hex(),
            "destination_hash_hex": destination_hash.hex(),
        },
        "rns_version_at_generation":  RNS.__version__,
        "generator_script":           "tools/regen_identities.py",
        "verifies_spec_sections":     ["1.1", "1.2"],
    }


def main():
    print(f"regen_identities.py against RNS {RNS.__version__}")
    vectors = [derive_with_upstream(v) for v in vector_inputs()]
    payload = {
        "_about": (
            "Identity test vectors. Load via RNS.Identity.from_bytes("
            "bytes.fromhex(inputs.private_key_hex)) and confirm the four "
            "expected.* fields match. Regenerate by running this script "
            "against the upstream RNS shown in rns_version_at_generation."
        ),
        "vectors": vectors,
    }
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"Wrote {OUT_PATH} with {len(vectors)} vectors")
    print("ALL PASS")


if __name__ == "__main__":
    main()
