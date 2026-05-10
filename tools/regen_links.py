"""
Regenerator for test-vectors/links.json.

Builds a deterministic Link handshake vector pair (LINKREQUEST + LRPROOF)
between Alice (initiator) and Bob (responder) using identities from
`identities.json`.

Determinism inputs:

  - Alice and Bob long-term identities (fixed via identities.json).
  - Initiator's ephemeral X25519 private key (`Link.prv`,
    `RNS/Link.py:285`) — fixed.
  - Initiator's ephemeral Ed25519 private key (`Link.sig_prv`,
    `RNS/Link.py:286`) — fixed. (This is *not* Alice's long-term key;
    Link's signing key is generated fresh per handshake.)
  - Responder's ephemeral X25519 private key (`Link.prv`,
    `RNS/Link.py:278`) — fixed.
  - Both Ed25519 signatures are deterministic per RFC 8032.

Outputs recorded per vector:

  - `linkrequest_raw_hex`        — full packed LINKREQUEST packet bytes
  - `linkrequest_body_hex`       — initiator_X25519_pub || initiator_Ed25519_pub
                                    [|| signalling] (S6.1)
  - `link_id_hex`                — derived per S6.3 (N=2 for HEADER_1)
  - `lrproof_raw_hex`            — full packed LRPROOF packet bytes
  - `lrproof_body_hex`           — signature || responder_X25519_pub
                                    [|| signalling] (S6.2)
  - `derived_key_hex`            — HKDF output for AES256_CBC mode
                                    (length=64, salt=link_id, context=context)
                                    — both sides must arrive at the same
                                    bytes after handshake().

Run from repo root:

    python tools/regen_links.py

Updates `test-vectors/links.json` in place. Exit 0 on success.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile

import RNS
from RNS.Link import Link
from RNS.vendor import umsgpack


REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH   = os.path.join(REPO_ROOT, "test-vectors", "links.json")
IDS_PATH   = os.path.join(REPO_ROOT, "test-vectors", "identities.json")


# Stable inputs. Three distinct fixed priv key blobs for the three
# ephemeral generations the handshake performs.
INITIATOR_X25519_PRIV   = bytes.fromhex("11"*32)
INITIATOR_ED25519_PRIV  = bytes.fromhex("22"*32)
RESPONDER_X25519_PRIV   = bytes.fromhex("33"*32)

# Pinned LRRTT inputs. The IV here gets injected via os.urandom while
# packing the LRRTT packet so the wire bytes are reproducible. RTT
# value is the initiator's measured LRREQ->LRPROOF time per S6.4.2;
# the exact value is non-load-bearing (responder takes max with its
# own measurement) but pinning it keeps the wire bytes deterministic.
LRRTT_RTT_SECONDS       = 0.05
LRRTT_IV                = bytes.fromhex("44"*16)


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-regen-links-")
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


class _StaticPrivQueue:
    """Wraps an upstream X25519/Ed25519 dispatcher class so that
    `.generate()` returns a private key seeded with the next blob in a
    fixed queue. Each consumed blob is removed; if the queue underflows
    we delegate to the real `.generate()` so non-handshake code paths
    still work."""
    def __init__(self, real_cls, blobs):
        self._real_cls = real_cls
        self._blobs    = list(blobs)

    def generate(self):
        if self._blobs:
            blob = self._blobs.pop(0)
            return self._real_cls.from_private_bytes(blob)
        return self._real_cls.generate()

    # Defer everything else (from_private_bytes, from_public_bytes, etc.)
    # to the real class so the rest of upstream's surface keeps working.
    def __getattr__(self, name):
        return getattr(self._real_cls, name)


def main():
    print(f"regen_links.py against RNS {RNS.__version__}")
    init_minimal_rns()
    try:
        alice_id, bob_id = load_identities()

        # Bob's destination — the link target. Mark Bob's identity
        # discoverable to Alice so Link initiator can find pub keys.
        bob_dest_in = RNS.Destination(bob_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                      "vectors", "link")
        bob_dest_out = RNS.Destination(bob_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
                                       "vectors", "link")
        RNS.Identity.remember(b"\x00"*32, bob_dest_in.hash, bob_id.get_public_key(), None)

        # Patch the X25519 / Ed25519 generators that Link.__init__ uses
        # to drive deterministic ephemeral keys. Order of consumption
        # follows the source:
        #   line 285: initiator self.prv     = X25519PrivateKey.generate()
        #   line 286: initiator self.sig_prv = Ed25519PrivateKey.generate()
        #   line 278: responder self.prv     = X25519PrivateKey.generate()
        link_mod = sys.modules["RNS.Link"]
        real_X25519  = link_mod.X25519PrivateKey
        real_Ed25519 = link_mod.Ed25519PrivateKey

        link_mod.X25519PrivateKey  = _StaticPrivQueue(real_X25519,
                                                     [INITIATOR_X25519_PRIV,
                                                      RESPONDER_X25519_PRIV])
        link_mod.Ed25519PrivateKey = _StaticPrivQueue(real_Ed25519,
                                                     [INITIATOR_ED25519_PRIV])

        # Capture LINKREQUEST emission. Patch Transport.outbound (not
        # Packet.send) so Packet.pack() runs and packet.raw is populated.
        captured_lr = {}
        captured_pf = {}
        real_outbound = RNS.Transport.outbound

        def fake_outbound(packet):
            if packet.packet_type == RNS.Packet.LINKREQUEST and "raw" not in captured_lr:
                captured_lr["raw"]  = packet.raw
                captured_lr["data"] = packet.data
            elif packet.context == RNS.Packet.LRPROOF and "raw" not in captured_pf:
                captured_pf["raw"]  = packet.raw
                captured_pf["data"] = packet.data
            return True

        RNS.Transport.outbound = staticmethod(fake_outbound)
        try:
            # 1. Build initiator-side Link → LINKREQUEST emitted via outbound
            initiator = Link(destination=bob_dest_out)

            # 2. Walk the responder side by hand (Link.validate_request
            #    inlined). This keeps the script self-contained.
            inbound = RNS.Packet(None, captured_lr["raw"])
            if not inbound.unpack():
                fail("Failed to unpack the captured LINKREQUEST")
            inbound.destination = bob_dest_in

            request_data = captured_lr["data"]
            responder = Link(
                owner            = bob_dest_in,
                peer_pub_bytes   = request_data[:Link.ECPUBSIZE//2],
                peer_sig_pub_bytes = request_data[Link.ECPUBSIZE//2:Link.ECPUBSIZE],
            )
            responder.set_link_id(inbound)

            if len(request_data) == Link.ECPUBSIZE + Link.LINK_MTU_SIZE:
                responder.mtu  = Link.mtu_from_lr_packet(inbound) or RNS.Reticulum.MTU
                responder.mode = Link.mode_from_lr_packet(inbound)

            responder.destination = inbound.destination
            responder.handshake()    # populates responder.derived_key
            responder.prove()        # emits LRPROOF via outbound
        finally:
            RNS.Transport.outbound      = real_outbound
            link_mod.X25519PrivateKey   = real_X25519
            link_mod.Ed25519PrivateKey  = real_Ed25519

        # 3. Drive the initiator's handshake by feeding it the captured
        #    LRPROOF, so its derived_key is computed too. We assert
        #    initiator.derived_key == responder.derived_key.
        proof_pkt = RNS.Packet(None, captured_pf["raw"])
        if not proof_pkt.unpack():
            fail("Failed to unpack the captured LRPROOF")
        # validate_proof needs the link instance to know its destination
        proof_pkt.destination = initiator
        # Set up the initiator state so validate_proof can run end-to-end
        import time as _time
        initiator.request_time = _time.time()
        if not initiator.validate_proof(proof_pkt):
            # Some versions return None on success, so don't hard-fail
            # solely on that — but check derived_key was populated.
            pass
        if initiator.derived_key is None:
            fail("Initiator derived_key not populated after validate_proof")
        if responder.derived_key is None:
            fail("Responder derived_key not populated after handshake")
        if initiator.derived_key != responder.derived_key:
            fail("Initiator and responder derived_key disagree:\n"
                 f"  initiator: {initiator.derived_key.hex()}\n"
                 f"  responder: {responder.derived_key.hex()}")
        if initiator.link_id != responder.link_id:
            fail(f"link_id disagree: ini={initiator.link_id.hex()} res={responder.link_id.hex()}")

        # 4. Build the initiator's LRRTT packet (S6.4.2). The initiator
        #    emits this immediately after LRPROOF validation, before any
        #    application DATA. We pin os.urandom so the Token IV is
        #    deterministic; the rest of the wire form falls out of the
        #    link's derived_key (already populated above).
        lrrtt_plaintext = umsgpack.packb(LRRTT_RTT_SECONDS)
        token_mod = sys.modules["RNS.Cryptography.Token"]
        real_urandom = token_mod.os.urandom

        def fake_urandom(n):
            if n == 16: return LRRTT_IV
            return real_urandom(n)

        token_mod.os.urandom = fake_urandom
        try:
            lrrtt_packet = RNS.Packet(initiator, lrrtt_plaintext,
                                      context=RNS.Packet.LRRTT)
            lrrtt_packet.pack()
        finally:
            token_mod.os.urandom = real_urandom

        # Sanity round-trip: the responder side should decrypt
        # the captured ciphertext and recover the same float.
        if responder.decrypt(lrrtt_packet.ciphertext) != lrrtt_plaintext:
            fail("LRRTT round-trip failed: responder.decrypt did not "
                 "recover the pinned plaintext.")

        # Slice fields per S6.1 / S6.2 for human inspection
        lr_data = captured_lr["data"]
        ini_x25519_pub  = lr_data[:32]
        ini_ed25519_pub = lr_data[32:64]
        lr_signalling   = lr_data[64:] if len(lr_data) > 64 else b""

        pf_data = captured_pf["data"]
        pf_signature = pf_data[:64]
        pf_responder_x25519 = pf_data[64:96]
        pf_signalling = pf_data[96:] if len(pf_data) > 96 else b""

        vector = {
            "label":   "alice_to_bob_aes256cbc",
            "inputs": {
                "initiator_identity_label":      "alice",
                "responder_identity_label":      "bob",
                "destination_full_name":         "vectors.link",
                "initiator_x25519_priv_hex":     INITIATOR_X25519_PRIV.hex(),
                "initiator_ed25519_priv_hex":    INITIATOR_ED25519_PRIV.hex(),
                "responder_x25519_priv_hex":     RESPONDER_X25519_PRIV.hex(),
                "mode":                          "MODE_AES256_CBC (0x01)",
            },
            "expected": {
                "linkrequest_raw_hex":           captured_lr["raw"].hex(),
                "linkrequest_body_hex":          lr_data.hex(),
                "linkrequest_fields": {
                    "initiator_x25519_pub_hex":  ini_x25519_pub.hex(),
                    "initiator_ed25519_pub_hex": ini_ed25519_pub.hex(),
                    "signalling_hex":            lr_signalling.hex(),
                },
                "link_id_hex":                   initiator.link_id.hex(),
                "lrproof_raw_hex":               captured_pf["raw"].hex(),
                "lrproof_body_hex":              pf_data.hex(),
                "lrproof_fields": {
                    "signature_hex":             pf_signature.hex(),
                    "responder_x25519_pub_hex":  pf_responder_x25519.hex(),
                    "signalling_hex":            pf_signalling.hex(),
                },
                "shared_secret_hex":             initiator.shared_key.hex(),
                "derived_key_hex":               initiator.derived_key.hex(),
                "mtu":                           initiator.mtu,
                "mode":                          initiator.mode,
                "lrrtt": {
                    "rtt_seconds":               LRRTT_RTT_SECONDS,
                    "iv_hex":                    LRRTT_IV.hex(),
                    "plaintext_hex":             lrrtt_plaintext.hex(),
                    "raw_hex":                   lrrtt_packet.raw.hex(),
                    "body_hex":                  lrrtt_packet.ciphertext.hex(),
                },
            },
            "rns_version_at_generation":         RNS.__version__,
            "generator_script":                  "tools/regen_links.py",
            "verifies_spec_sections":            ["6.1", "6.2", "6.3", "6.4.1",
                                                  "6.4.2", "6.6"],
        }

        payload = {
            "_about": (
                "Link handshake test vectors. Each vector records a full "
                "Reticulum Link handshake: LINKREQUEST (initiator -> "
                "responder) and LRPROOF (responder -> initiator). The "
                "ephemeral X25519/Ed25519 keys are pinned via the "
                "`inputs.*_priv_hex` blobs; both Ed25519 signatures are "
                "RFC 8032 deterministic so the resulting wire bytes are "
                "reproducible. A clean-room implementation can verify by: "
                "(a) packing a LINKREQUEST from the recorded initiator "
                "ephemerals and confirming bytes match `linkrequest_raw_hex`; "
                "(b) computing `link_id` per SPEC.md S6.3 (N=2 for HEADER_1) "
                "and matching `link_id_hex`; (c) packing an LRPROOF as the "
                "responder, with bob's identity Ed25519 sig over `link_id || "
                "responder_X25519_pub || responder_long_term_Ed25519_pub || "
                "signalling`, and matching `lrproof_raw_hex`; (d) running "
                "ECDH+HKDF on either side and matching `derived_key_hex`; "
                "(e) building an LRRTT packet (S6.4.2) addressed to the "
                "link_id with `context=LRRTT (0xfe)` and an encrypted body "
                "of `umsgpack.packb(lrrtt.rtt_seconds)`, using `lrrtt.iv_hex` "
                "as the Token IV, and matching `lrrtt.raw_hex` / `lrrtt.body_hex`. "
                "Regenerate with `generator_script`."
            ),
            "vectors": [vector],
        }
        with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, indent=2, sort_keys=False)
            f.write("\n")
        print(f"Wrote {OUT_PATH} with 1 vector")
        print("ALL PASS")
    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass


if __name__ == "__main__":
    main()
