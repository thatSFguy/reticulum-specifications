"""
Regenerator for test-vectors/announces.json.

Builds two deterministic announce wire-byte vectors using Alice's
identity from `identities.json`:

  1. `alice_lxmf_no_ratchet`   — context_flag=0, app_data = LXMF
     2-element form `[display_name_bytes, stamp_cost]` (S4.3)
  2. `alice_lxmf_with_ratchet` — context_flag=1, fixed ratchet priv,
     same app_data

Determinism inputs:

  - Identity = Alice (private_key from `identities.json`); Ed25519
    signing is deterministic per RFC 8032 so the signature byte
    sequence is reproducible from the same plaintext + key.
  - `random_hash[0:5]` = patched constant prefix.
  - `random_hash[5:10]` = patched fixed unix-seconds value (we override
    `time.time` inside `RNS.Destination` for the duration of the
    announce build).
  - `ratchet_priv` = fixed 32 bytes (vector #2 only).
  - `app_data` = `umsgpack.packb([b"AliceTest", 0])` per S4.3.

After build we run `RNS.Identity.validate_announce` on the produced
packet and assert it accepts; this proves the recorded bytes are
upstream-valid.

Run from repo root:

    python tools/regen_announces.py

Updates `test-vectors/announces.json` in place. Exit 0 on success.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

import RNS
from RNS.vendor import umsgpack


REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH   = os.path.join(REPO_ROOT, "test-vectors", "announces.json")
IDS_PATH   = os.path.join(REPO_ROOT, "test-vectors", "identities.json")


# Stable inputs. These are vector-deterministic; do not change without
# regenerating every announce vector.
FIXED_RANDOM_PREFIX = bytes.fromhex("a1a2a3a4a5")          # random_hash[0:5]
FIXED_TIMESTAMP     = 1700000000                            # 2023-11-14, BE-uint40 -> random_hash[5:10]
FIXED_RATCHET_PRIV  = bytes.fromhex("b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0")
FIXED_APP_DATA      = umsgpack.packb([b"AliceTest", 0])    # S4.3 2-element form


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-regen-announces-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def load_alice() -> RNS.Identity:
    with open(IDS_PATH, "r", encoding="utf-8") as f:
        ids = json.load(f)
    alice = next(v for v in ids["vectors"] if v["label"] == "alice")
    prv_bytes = bytes.fromhex(alice["inputs"]["private_key_hex"])
    identity = RNS.Identity.from_bytes(prv_bytes)
    if identity is None:
        fail("Identity.from_bytes returned None for Alice")
    return identity, alice


def build_deterministic_announce(identity, with_ratchet: bool) -> bytes:
    """Drive `Destination.announce(send=False)` with patched time/random
    sources so the wire bytes are reproducible. Returns packed raw bytes."""
    import sys as _sys
    # `RNS.Identity` and `RNS.Destination` are the classes (re-exported in
    # RNS/__init__.py); the underlying modules live in sys.modules.
    dest_mod = _sys.modules["RNS.Destination"]
    id_cls   = RNS.Identity   # the class, where get_random_hash is defined

    # Patch the get_random_hash classmethod so random_hash[0:5] is fixed.
    # Destination.announce calls it once per announce (Destination.py:282).
    real_get_random_hash = id_cls.get_random_hash
    def patched_get_random_hash():
        return FIXED_RANDOM_PREFIX + b"\x00" * 27
    id_cls.get_random_hash = staticmethod(patched_get_random_hash)

    # Patch time.time inside the Destination module so
    # int(time.time()).to_bytes(5,'big') -> FIXED_TIMESTAMP. Replacing
    # `dest_mod.time.time` would mutate the global `time` module; instead
    # swap the module-level `time` reference itself.
    real_time_module = dest_mod.time
    class _FixedTime:
        @staticmethod
        def time(): return float(FIXED_TIMESTAMP)
    dest_mod.time = _FixedTime

    try:
        # Use a dedicated aspect per vector so the Destination cache
        # doesn't reject the second registration in this same process.
        aspect = "alice_announce_with_ratchet" if with_ratchet else "alice_announce_no_ratchet"
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                               "vectors", aspect)

        if with_ratchet:
            # Force the ratchet without going through enable_ratchets (which
            # writes to disk and could pick up stale state). Setting
            # latest_ratchet_time = now-eps (>= now-INTERVAL) makes
            # rotate_ratchets a no-op so our fixed priv is preserved.
            dest.ratchets             = [FIXED_RATCHET_PRIV]
            dest.ratchet_interval     = RNS.Destination.RATCHET_INTERVAL
            dest.latest_ratchet_time  = float(FIXED_TIMESTAMP)
            dest.path_responses       = {}
        # else: leave dest.ratchets = None so context_flag=0

        pkt = dest.announce(app_data=FIXED_APP_DATA, send=False)
        pkt.pack()

        # Sanity: validate_announce must accept the packet we just built.
        # We must rebuild the Packet from raw bytes via the inbound path
        # because packet.unpack mutates state.
        if not pkt.unpack():
            fail(f"Packet.unpack returned False ({aspect})")
        if not RNS.Identity.validate_announce(pkt):
            fail(f"validate_announce rejected freshly-built vector ({aspect})")

        return pkt.raw, dest.hash
    finally:
        id_cls.get_random_hash = staticmethod(real_get_random_hash)
        dest_mod.time = real_time_module


def split_body(raw: bytes, with_ratchet: bool) -> dict:
    """Split announce wire bytes into the named fields per S4.1 so the
    JSON vector is human-inspectable."""
    KEYSIZE, NAME_HASH, RANDOM_HASH, RATCHET, SIG = 64, 10, 10, 32, 64
    flags  = raw[0]
    hops   = raw[1]
    dst    = raw[2:18]
    ctx    = raw[18]

    body = raw[19:]
    pub  = body[0:KEYSIZE]
    nm   = body[KEYSIZE:KEYSIZE+NAME_HASH]
    rh   = body[KEYSIZE+NAME_HASH:KEYSIZE+NAME_HASH+RANDOM_HASH]

    if with_ratchet:
        rt   = body[KEYSIZE+NAME_HASH+RANDOM_HASH:KEYSIZE+NAME_HASH+RANDOM_HASH+RATCHET]
        sigs = KEYSIZE+NAME_HASH+RANDOM_HASH+RATCHET
    else:
        rt   = b""
        sigs = KEYSIZE+NAME_HASH+RANDOM_HASH

    sig  = body[sigs:sigs+SIG]
    ad   = body[sigs+SIG:]

    fields = {
        "header_flags_hex":     bytes([flags]).hex(),
        "header_hops_hex":      bytes([hops]).hex(),
        "header_dest_hash_hex": dst.hex(),
        "header_context_hex":   bytes([ctx]).hex(),
        "body_public_key_hex":  pub.hex(),
        "body_name_hash_hex":   nm.hex(),
        "body_random_hash_hex": rh.hex(),
        "body_signature_hex":   sig.hex(),
        "body_app_data_hex":    ad.hex(),
    }
    if with_ratchet:
        fields["body_ratchet_pub_hex"] = rt.hex()
    return fields


def main():
    print(f"regen_announces.py against RNS {RNS.__version__}")
    init_minimal_rns()
    try:
        identity, alice = load_alice()

        vectors = []
        for label, with_ratchet in [
            ("alice_lxmf_no_ratchet",   False),
            ("alice_lxmf_with_ratchet", True),
        ]:
            raw, dest_hash = build_deterministic_announce(identity, with_ratchet)
            fields = split_body(raw, with_ratchet)
            vectors.append({
                "label":            label,
                "context_flag":     1 if with_ratchet else 0,
                "with_ratchet":     with_ratchet,
                "inputs": {
                    "identity_label":            "alice",
                    "destination_full_name":     "vectors." + ("alice_announce_with_ratchet" if with_ratchet else "alice_announce_no_ratchet"),
                    "random_hash_prefix_hex":    FIXED_RANDOM_PREFIX.hex(),
                    "random_hash_timestamp":     FIXED_TIMESTAMP,
                    "ratchet_priv_hex":          FIXED_RATCHET_PRIV.hex() if with_ratchet else None,
                    "app_data_msgpack_hex":      FIXED_APP_DATA.hex(),
                    "app_data_decoded":          ["AliceTest", 0],
                },
                "expected": {
                    "destination_hash_hex":      dest_hash.hex(),
                    "wire_bytes_hex":            raw.hex(),
                    "fields":                    fields,
                },
                "rns_version_at_generation":   RNS.__version__,
                "generator_script":            "tools/regen_announces.py",
                "verifies_spec_sections":      ["2.1", "4.1", "4.2", "4.3", "4.5"],
            })

        payload = {
            "_about": (
                "Announce test vectors. Each entry's `expected.wire_bytes_hex` "
                "is the full packed announce bytes (header + body). Drop them "
                "into a fresh RNS.Packet via the inbound path and call "
                "RNS.Identity.validate_announce; it MUST accept. The "
                "`expected.fields` block decomposes the wire bytes into "
                "named slices per SPEC.md S4.1 for human inspection. "
                "Regenerate with the script in `generator_script`."
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
