"""
Regenerator for test-vectors/lxmf.json.

Builds two deterministic opportunistic-LXMF wire-byte vectors using
Alice and Bob from `identities.json`:

  1. `alice_to_bob_simple`     — title b"hello", content b"hi bob",
                                  no fields
  2. `alice_to_bob_with_fields` — content + title + a small msgpack-
                                  serialisable fields dict

For each vector we record:

  - `lxmf_packed_hex`   — the post-`LXMessage.pack()` plaintext body
                          (`dest(16) || src(16) || sig(64) || msgpack`)
                          per S5.1 / S5.2.
  - `opportunistic_plaintext_hex` — the same body with the leading 16
                          dest_hash stripped (S5.1 opportunistic form
                          fed to Token).
  - `token_ciphertext_hex` — the Token-encrypted ciphertext that goes
                          on the wire as the opportunistic packet body
                          per S3.

Determinism inputs:

  - Alice + Bob private keys (from identities.json). Ed25519 sign is
    deterministic so the LXMF signature is reproducible.
  - `LXMessage.timestamp` pre-set to a fixed value (overrides the
    `time.time()` default at `LXMF/LXMessage.py:354`).
  - The Token ephemeral X25519 priv (patched X25519PrivateKey.generate
    in RNS.Identity).
  - The Token CBC IV (patched os.urandom in RNS.Cryptography.Token).

After generation we decrypt with Bob's identity, re-prepend Bob's
dest_hash, parse via `LXMessage.unpack_from_bytes`, and assert
signature_validated + title/content/fields round-trip.

Run from repo root:

    python tools/regen_lxmf.py

Updates `test-vectors/lxmf.json` in place. Exit 0 on success.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

import RNS
import LXMF
from LXMF.LXMessage import LXMessage
from RNS.vendor import umsgpack


REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH   = os.path.join(REPO_ROOT, "test-vectors", "lxmf.json")
IDS_PATH   = os.path.join(REPO_ROOT, "test-vectors", "identities.json")


FIXED_LXMF_TIMESTAMP   = 1700000000.0
FIXED_EPH_X25519_PRIV  = bytes.fromhex("d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0")
FIXED_TOKEN_IV         = bytes.fromhex("11223344556677889900aabbccddeeff")  # 16 B for AES-CBC


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-regen-lxmf-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def load_identities():
    with open(IDS_PATH, "r", encoding="utf-8") as f:
        ids = json.load(f)
    alice = next(v for v in ids["vectors"] if v["label"] == "alice")
    bob   = next(v for v in ids["vectors"] if v["label"] == "bob")
    alice_id = RNS.Identity.from_bytes(bytes.fromhex(alice["inputs"]["private_key_hex"]))
    bob_id   = RNS.Identity.from_bytes(bytes.fromhex(bob  ["inputs"]["private_key_hex"]))
    if alice_id is None or bob_id is None:
        fail("Identity.from_bytes returned None for one of alice/bob")
    return alice_id, bob_id


class _StaticX25519Priv:
    """Drop-in replacement for X25519PrivateKey whose .generate()
    classmethod returns a private key seeded with FIXED_EPH_X25519_PRIV."""
    _real = None
    @classmethod
    def generate(cls):
        # cls._real is the original RNS dispatcher; from_private_bytes
        # builds an X25519 priv with the same interface as generate().
        return cls._real.from_private_bytes(FIXED_EPH_X25519_PRIV)


def build_vector(alice_dest, bob_dest_in, bob_dest_out, label, title, content, fields):
    import sys as _sys
    id_mod    = _sys.modules["RNS.Identity"]
    token_mod = _sys.modules["RNS.Cryptography.Token"]

    lxm = LXMessage(
        destination    = bob_dest_out,
        source         = alice_dest,
        content        = content,
        title          = title,
        fields         = fields,
        desired_method = LXMessage.OPPORTUNISTIC,
    )
    # Fix the timestamp before pack() so the msgpack payload is stable
    lxm.timestamp = FIXED_LXMF_TIMESTAMP
    lxm.pack()

    packed = lxm.packed
    if packed[:16] != bob_dest_out.hash:
        fail(f"S5.2 dest_hash slot mismatch ({label})")
    if packed[16:32] != alice_dest.hash:
        fail(f"S5.2 src_hash slot mismatch ({label})")

    opp_plaintext = packed[16:]   # opportunistic-form input to Token

    # --- Patch ephemeral X25519 generate + Token IV for deterministic CT
    real_X25519 = id_mod.X25519PrivateKey
    _StaticX25519Priv._real = real_X25519
    id_mod.X25519PrivateKey = _StaticX25519Priv

    real_urandom = token_mod.os.urandom
    def patched_urandom(n):
        if n == 16: return FIXED_TOKEN_IV
        return real_urandom(n)
    token_mod.os.urandom = patched_urandom

    try:
        ciphertext = bob_dest_out.encrypt(opp_plaintext)
    finally:
        id_mod.X25519PrivateKey = real_X25519
        token_mod.os.urandom    = real_urandom

    # --- Round-trip: Bob can decrypt and re-parse the plaintext
    decrypted = bob_dest_in.decrypt(ciphertext)
    if decrypted != opp_plaintext:
        fail(f"Token round-trip mismatch ({label})")
    full_lxmf = bob_dest_in.hash + decrypted
    parsed = LXMessage.unpack_from_bytes(full_lxmf)
    if not parsed.signature_validated:
        fail(f"S5.5/5.6 unpack_from_bytes did not validate signature ({label})")
    if parsed.title_as_string() != title.decode("utf-8"):
        fail(f"title round-trip mismatch ({label})")
    if parsed.content_as_string() != content.decode("utf-8"):
        fail(f"content round-trip mismatch ({label})")
    if parsed.fields != fields:
        fail(f"fields round-trip mismatch ({label})")

    return {
        "label":   label,
        "inputs": {
            "src_identity_label":      "alice",
            "dst_identity_label":      "bob",
            "title_utf8":              title.decode("utf-8"),
            "content_utf8":            content.decode("utf-8"),
            "fields":                  fields,
            "lxmf_timestamp":          FIXED_LXMF_TIMESTAMP,
            "ephemeral_x25519_priv_hex": FIXED_EPH_X25519_PRIV.hex(),
            "token_iv_hex":            FIXED_TOKEN_IV.hex(),
        },
        "expected": {
            "lxmf_packed_hex":              packed.hex(),
            "opportunistic_plaintext_hex":  opp_plaintext.hex(),
            "token_ciphertext_hex":         ciphertext.hex(),
            "fields_layout": {
                "destination_hash_hex": packed[0:16].hex(),
                "source_hash_hex":      packed[16:32].hex(),
                "signature_hex":        packed[32:96].hex(),
                "msgpack_payload_hex":  packed[96:].hex(),
            },
        },
        "rns_version_at_generation":    RNS.__version__,
        "lxmf_version_at_generation":   LXMF.__version__,
        "generator_script":             "tools/regen_lxmf.py",
        "verifies_spec_sections":       ["3", "5.1", "5.2", "5.5", "5.6"],
    }


def main():
    print(f"regen_lxmf.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    init_minimal_rns()
    try:
        alice_id, bob_id = load_identities()

        # Register once; subsequent registrations of same (identity, dir,
        # type, aspects) raise. Reuse across vectors.
        alice_dest = RNS.Destination(alice_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                     "lxmf", "delivery")
        bob_dest_in  = RNS.Destination(bob_id, RNS.Destination.IN,  RNS.Destination.SINGLE,
                                       "lxmf", "delivery")
        bob_dest_out = RNS.Destination(bob_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
                                       "lxmf", "delivery")
        RNS.Identity.remember(b"\x00"*32, alice_dest.hash,  alice_id.get_public_key(), None)
        RNS.Identity.remember(b"\x00"*32, bob_dest_in.hash, bob_id  .get_public_key(), None)

        vectors = [
            build_vector(alice_dest, bob_dest_in, bob_dest_out,
                         label   = "alice_to_bob_simple",
                         title   = b"hello",
                         content = b"hi bob",
                         fields  = {}),
            build_vector(alice_dest, bob_dest_in, bob_dest_out,
                         label   = "alice_to_bob_with_fields",
                         title   = b"meeting",
                         content = b"see attached",
                         fields  = {0x01: "k1", 0x02: 42}),
        ]

        payload = {
            "_about": (
                "Opportunistic LXMF test vectors. "
                "`expected.lxmf_packed_hex` is the full plaintext body "
                "per SPEC.md S5.2: dest(16) || src(16) || sig(64) || msgpack. "
                "`expected.opportunistic_plaintext_hex` is the same with "
                "the leading dest_hash stripped (S5.1 wire form). "
                "`expected.token_ciphertext_hex` is the deterministic Token "
                "encryption of the opportunistic plaintext (S3) using the "
                "fixed ephemeral X25519 priv + IV. To verify against "
                "upstream: decrypt with Bob's identity, re-prepend Bob's "
                "dest_hash, then call LXMessage.unpack_from_bytes — it MUST "
                "succeed with signature_validated == True and title/content/"
                "fields matching the `inputs` block. Regenerate with "
                "`generator_script`."
            ),
            "vectors": vectors,
        }
        with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, indent=2, sort_keys=False)
            f.write("\n")
        print(f"Wrote {OUT_PATH} with {len(vectors)} vectors")
        print("ALL PASS")
    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass


if __name__ == "__main__":
    main()
