"""
Verifier for SPEC.md S5.6 / S5.6.1 (msgpack canonical encoding).

Proves that canonical msgpack encoding is a MUST for any message
carrying a S5.7 stamp, and only a SHOULD without one — by handing
upstream LXMF both forms and reading its verdict.

Why the distinction exists, in upstream's own code:

  Sender  (LXMF/LXMessage.py:362-381)
      payload      = [timestamp, title, content, fields]   # :362
      hashed_part += msgpack.packb(payload)                # :367  signed over 4
      hash         = full_hash(hashed_part)                # :368  = message_id
      payload.append(stamp)                                # :373  now 5
      signature    = source.sign(signed_part)              # :378
      packed_payload = msgpack.packb(payload)              # :381  5 on the wire

  Receiver (LXMF/LXMessage.py:751-764)
      packed_payload   = <raw wire bytes>                  # :751
      unpacked_payload = msgpack.unpackb(packed_payload)   # :752
      if len(unpacked_payload) > 4:                        # :755  <-- the gate
          unpacked_payload = unpacked_payload[:4]          # :757
          packed_payload   = msgpack.packb(unpacked_payload)  # :758  RE-ENCODE
      hashed_part  = destination_hash + source_hash + packed_payload  # :762
      message_hash = full_hash(hashed_part)                # :763
      signed_part  = hashed_part + message_hash            # :764

The re-encode at :758 happens ONLY inside the len > 4 branch. So:

  * stamped   -> the receiver never verifies against the wire bytes. It
                 verifies against ITS OWN re-encoding of the decoded
                 values, which must byte-equal the sender's :367 output.
                 Canonical encoding is load-bearing: MUST.
  * unstamped -> packed_payload stays the raw wire bytes from :751, the
                 sender's own encoding is what gets verified, and a
                 non-canonical encoder still interoperates: SHOULD.

Upstream Python satisfies the stamped case trivially (same encoder on
both sides), which is exactly why this is invisible from the Python
side and why it needs stating normatively for everyone else.

The non-canonical form used here is the one that bit a real
implementation: an LXMF field key of 6 encoded as int8 (0xd0 0x06)
instead of positive fixint (0x06). Valid msgpack, decodes to the same
integer, one byte longer than umsgpack's _pack_integer emits
(RNS/vendor/umsgpack.py:288).

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import os
import sys
import tempfile

import RNS
import LXMF
from LXMF.LXMessage import LXMessage
import RNS.vendor.umsgpack as umsgpack


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-canonical-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


# --- payload construction -------------------------------------------------
#
# Both encoders below produce the SAME logical payload. They differ in
# exactly one byte: how the integer field key 6 is enveloped.

FIELD_KEY = 6
FIELD_VAL = b"canonical-encoding-test"

CANONICAL_KEY    = b"\x06"        # positive fixint, what umsgpack emits
NONCANONICAL_KEY = b"\xd0\x06"    # int8, valid msgpack, one byte wider


def pack_payload(timestamp, title, content, key_bytes, stamp=None):
    """Hand-rolled msgpack for [timestamp, title, content, fields(, stamp)]
    so the integer-key envelope can be chosen explicitly."""
    fields = b"\x81" + key_bytes + umsgpack.packb(FIELD_VAL)
    elements = [umsgpack.packb(timestamp), umsgpack.packb(title),
                umsgpack.packb(content), fields]
    if stamp is not None:
        elements.append(umsgpack.packb(stamp))
    n = len(elements)
    if n > 15:
        raise ValueError("fixarray only")
    return bytes([0x90 | n]) + b"".join(elements)


def build_lxmf(source_identity, dest_hash, source_hash, key_bytes, stamp):
    """Build a signed LXMF body exactly as LXMessage.pack does, but with
    the caller's choice of integer-key envelope.

    Mirrors LXMF/LXMessage.py:362-390: sign over the 4-element payload,
    put the 5-element payload on the wire when a stamp is present."""
    timestamp = 1735689600.0
    title     = b"t"
    content   = b"canonical encoding matters"

    signed_payload = pack_payload(timestamp, title, content, key_bytes)
    hashed_part    = dest_hash + source_hash + signed_payload
    message_hash   = RNS.Identity.full_hash(hashed_part)
    signed_part    = hashed_part + message_hash
    signature      = source_identity.sign(signed_part)

    wire_payload = pack_payload(timestamp, title, content, key_bytes, stamp=stamp)
    return dest_hash + source_hash + signature + wire_payload, message_hash


def check(label, source_identity, dest_hash, source_hash, key_bytes, stamp,
          want_valid):
    lxmf_bytes, sender_message_id = build_lxmf(
        source_identity, dest_hash, source_hash, key_bytes, stamp)
    message = LXMessage.unpack_from_bytes(lxmf_bytes)

    if message.signature_validated != want_valid:
        fail(f"S5.6.1 {label}: signature_validated = "
             f"{message.signature_validated}, want {want_valid}")

    if want_valid:
        if message.message_id != sender_message_id:
            fail(f"S5.6.1 {label}: receiver derived a different message_id "
                 f"than the sender, despite a valid signature")
        print(f"PASS S5.6.1 {label}: signature_validated = True, "
              f"message_id agrees")
    else:
        if message.unverified_reason != LXMessage.SIGNATURE_INVALID:
            fail(f"S5.6.1 {label}: unverified_reason = "
                 f"{message.unverified_reason}, want SIGNATURE_INVALID "
                 f"(0x02)")
        if message.message_id == sender_message_id:
            fail(f"S5.6.1 {label}: receiver reproduced the sender's "
                 f"message_id — the re-encode at :758 did not diverge, so "
                 f"this case does not demonstrate what it claims")
        print(f"PASS S5.6.1 {label}: signature_validated = False, "
              f"unverified_reason = SIGNATURE_INVALID, message_id diverged")
    return message


def main():
    print(f"verify_canonical_msgpack.py against RNS {RNS.__version__} / "
          f"LXMF {LXMF.__version__}")
    init_minimal_rns()
    try:
        # Sanity: the two key encodings really are different bytes that
        # decode to the same integer. If umsgpack ever starts emitting the
        # wide form, this test is measuring nothing.
        if umsgpack.packb(FIELD_KEY) != CANONICAL_KEY:
            fail(f"S5.6.1 umsgpack.packb({FIELD_KEY}) = "
                 f"{umsgpack.packb(FIELD_KEY)!r}, want {CANONICAL_KEY!r} "
                 f"(_pack_integer, RNS/vendor/umsgpack.py:288)")
        if umsgpack.unpackb(NONCANONICAL_KEY) != FIELD_KEY:
            fail("S5.6.1 the non-canonical envelope does not decode to the "
                 "same integer — the test premise is wrong")
        if CANONICAL_KEY == NONCANONICAL_KEY:
            fail("S5.6.1 canonical and non-canonical forms are identical")
        print(f"PASS S5.6.1 field key {FIELD_KEY}: umsgpack emits "
              f"{CANONICAL_KEY.hex()}; {NONCANONICAL_KEY.hex()} is valid "
              f"msgpack for the same value")

        alice = RNS.Identity()
        bob   = RNS.Identity()
        src = RNS.Destination(alice, RNS.Destination.OUT, RNS.Destination.SINGLE,
                              "lxmf", "delivery")
        dst = RNS.Destination(bob, RNS.Destination.OUT, RNS.Destination.SINGLE,
                              "lxmf", "delivery")
        # unpack_from_bytes resolves the source via Identity.recall.
        RNS.Identity.remember(b"\x00"*32, src.hash, alice.get_public_key(), None)
        RNS.Identity.remember(b"\x00"*32, dst.hash, bob.get_public_key(), None)

        stamp = os.urandom(32)

        # --- STAMPED: the receiver re-encodes (:758), so canonical is a MUST
        check("stamped + canonical", alice, dst.hash, src.hash,
              CANONICAL_KEY, stamp, want_valid=True)
        check("stamped + non-canonical", alice, dst.hash, src.hash,
              NONCANONICAL_KEY, stamp, want_valid=False)

        # --- UNSTAMPED: no re-encode, so the sender's own bytes are verified
        check("unstamped + canonical", alice, dst.hash, src.hash,
              CANONICAL_KEY, None, want_valid=True)
        m = check("unstamped + non-canonical", alice, dst.hash, src.hash,
                  NONCANONICAL_KEY, None, want_valid=True)
        if m.stamp is not None:
            fail("S5.6.1 unstamped case unexpectedly carried a stamp")
        print("     ^ this is the control: the SAME non-canonical encoding "
              "that fails when stamped verifies fine when unstamped,")
        print("       because :755 never takes the re-encode branch. That is "
              "why S5.6.1 splits MUST from SHOULD on stamp presence.")

    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass
    print("ALL PASS")


if __name__ == "__main__":
    main()
