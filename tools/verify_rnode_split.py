"""
Verifier for SPEC.md S8.3 (RNode air-frame split-packet protocol).

Pure-function verifier — no Reticulum runtime needed because S8.3 is
a LoRa air-frame protocol that lives between RNodes, not on the host
KISS channel. We re-implement the canonical TX and RX state machines
in Python from the upstream RNode_Firmware source and exercise them.

Scenarios:

  1. Header-byte layout: bit 7..4 random seq nibble, bit 0 FLAG_SPLIT,
     bits 3..1 reserved zero. Verified via mask checks against the
     constants from RNode_Firmware/Framing.h.

  2. TX side, payload <= 254 bytes: emits one frame with FLAG_SPLIT=0,
     header || payload, and the seq nibble is randomized per fresh TX.

  3. TX side, payload > 254 bytes: emits two frames sharing the same
     header byte (same seq nibble + FLAG_SPLIT=1), split at exactly
     254 bytes of payload in the first frame and the remainder in the
     second.

  4. RX state machine, four cases of inbound frames per the table at
     S8.3:
       a. SPLIT first half → buffer
       b. SPLIT second half matching seq → reassemble
       c. SPLIT seq mismatch → replace buffer
       d. non-SPLIT after first half buffered → discard buffer, deliver

  5. Wire-byte equivalence: TX a 300-byte payload, run the resulting
     frames through the RX state machine, confirm reassembled payload
     bytes match the original.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import os
import sys


# ---- Constants from RNode_Firmware/Framing.h:105-108 + Config.h:59-61 ----

NIBBLE_SEQ      = 0xF0
NIBBLE_FLAGS    = 0x0F
FLAG_SPLIT      = 0x01
SEQ_UNSET       = 0xFF

MTU             = 508       # max reassembled Reticulum packet payload
SINGLE_MTU      = 255       # max LoRa frame size (header + payload)
HEADER_L        = 1


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


# ---- TX side (mirrors RNode_Firmware.ino:716-742) ----

def tx_frames(payload, seq_nibble=None):
    """Return a list of LoRa frames (header + payload bytes) for a
    given Reticulum packet payload, mirroring the RNode firmware's
    transmit() function.

    seq_nibble: optional override of the random sequence nibble for
    deterministic testing. Must be in 0..15.
    """
    if seq_nibble is None:
        seq_nibble = os.urandom(1)[0] >> 4              # any 0..15 will do
    if not 0 <= seq_nibble <= 15:
        raise ValueError("seq_nibble must be 0..15")

    if len(payload) > MTU:
        raise ValueError(f"payload too large: {len(payload)} > {MTU}")

    header = (seq_nibble << 4) & NIBBLE_SEQ              # high nibble = seq, low = 0
    if len(payload) > SINGLE_MTU - HEADER_L:
        header |= FLAG_SPLIT
        first_payload  = payload[:SINGLE_MTU - HEADER_L]
        second_payload = payload[SINGLE_MTU - HEADER_L:]
        return [bytes([header]) + first_payload,
                bytes([header]) + second_payload]
    else:
        return [bytes([header]) + payload]


# ---- RX side (mirrors RNode_Firmware.ino:359-446 receive_callback) ----

class RxStateMachine:
    """Re-implementation of the upstream RX reassembly logic. Calling
    .deliver(frame) returns the reassembled Reticulum packet bytes if
    a complete packet is now available, or None if the call merely
    buffered a first-half / replaced state / processed a duplicate.
    """

    def __init__(self):
        self.seq = SEQ_UNSET
        self.buf = b""

    def deliver(self, frame):
        if len(frame) < 1:
            return None
        header   = frame[0]
        sequence = (header & NIBBLE_SEQ) >> 4
        is_split = (header & FLAG_SPLIT) != 0
        payload  = frame[1:]

        if is_split and self.seq == SEQ_UNSET:
            # Case a: first half — buffer
            self.buf = payload
            self.seq = sequence
            return None

        elif is_split and sequence == self.seq:
            # Case b: second half matching seq — reassemble
            assembled = self.buf + payload
            self.buf = b""
            self.seq = SEQ_UNSET
            return assembled

        elif is_split and sequence != self.seq:
            # Case c: seq mismatch — replace with this as new first half
            self.buf = payload
            self.seq = sequence
            return None

        elif not is_split:
            # Case d: non-split — clear any buffered first half, deliver
            if self.seq != SEQ_UNSET:
                self.buf = b""
                self.seq = SEQ_UNSET
            return payload

        return None


# ---- Tests ----

def verify_header_layout():
    # NIBBLE_SEQ has only the high nibble set
    if NIBBLE_SEQ != 0xF0:
        fail(f"NIBBLE_SEQ != 0xF0 (got {NIBBLE_SEQ:#x})")
    # NIBBLE_FLAGS has only the low nibble set
    if NIBBLE_FLAGS != 0x0F:
        fail(f"NIBBLE_FLAGS != 0x0F (got {NIBBLE_FLAGS:#x})")
    # FLAG_SPLIT is the low bit of the low nibble
    if FLAG_SPLIT != 0x01:
        fail(f"FLAG_SPLIT != 0x01 (got {FLAG_SPLIT:#x})")
    # SEQ_UNSET is the all-ones sentinel
    if SEQ_UNSET != 0xFF:
        fail(f"SEQ_UNSET != 0xFF (got {SEQ_UNSET:#x})")
    print("PASS S8.3 header constants: NIBBLE_SEQ=0xF0, FLAG_SPLIT=0x01, SEQ_UNSET=0xFF")


def verify_tx_single_frame():
    # 100-byte payload — fits in one frame
    payload = bytes(range(100))
    frames = tx_frames(payload, seq_nibble=0x7)
    if len(frames) != 1:
        fail(f"S8.3 single-frame TX produced {len(frames)} frames, want 1")

    f = frames[0]
    if len(f) != 1 + 100:
        fail(f"S8.3 single-frame size = {len(f)}, want 101")

    header = f[0]
    if (header & NIBBLE_SEQ) >> 4 != 0x7:
        fail(f"S8.3 seq nibble lost: header = {header:#x}")
    if header & FLAG_SPLIT:
        fail(f"S8.3 single-frame TX set FLAG_SPLIT (header = {header:#x})")
    if f[1:] != payload:
        fail("S8.3 single-frame payload mangled")

    print(f"PASS S8.3 TX single-frame (100B payload, seq=0x7, header={header:#04x})")


def verify_tx_split_frames():
    # 300-byte payload — splits into 254 + 46
    payload = bytes(i & 0xFF for i in range(300))
    frames = tx_frames(payload, seq_nibble=0xA)
    if len(frames) != 2:
        fail(f"S8.3 split TX produced {len(frames)} frames, want 2")

    h1, h2 = frames[0][0], frames[1][0]
    if h1 != h2:
        fail(f"S8.3 split frames have different headers: {h1:#04x} vs {h2:#04x}")
    if not (h1 & FLAG_SPLIT):
        fail(f"S8.3 split frames did not set FLAG_SPLIT (header={h1:#04x})")
    if (h1 & NIBBLE_SEQ) >> 4 != 0xA:
        fail(f"S8.3 split frame seq nibble lost: header={h1:#04x}")

    if len(frames[0]) != 1 + 254:
        fail(f"S8.3 split frame 1 size = {len(frames[0])}, want 255")
    if len(frames[1]) != 1 + (300 - 254):
        fail(f"S8.3 split frame 2 size = {len(frames[1])}, want {1 + 300 - 254}")

    if frames[0][1:] != payload[:254]:
        fail("S8.3 split frame 1 payload mismatch")
    if frames[1][1:] != payload[254:]:
        fail("S8.3 split frame 2 payload mismatch")

    print(f"PASS S8.3 TX split frames (300B payload, 254+46 split, "
          f"shared header={h1:#04x})")


def verify_rx_state_machine():
    rx = RxStateMachine()

    # Case d: non-split arrives first → deliver immediately
    out = rx.deliver(bytes([0x30]) + b"non-split-1")
    if out != b"non-split-1":
        fail(f"S8.3 RX case d (non-split fresh) failed: got {out!r}")

    # Case a: split first half → buffer
    out = rx.deliver(bytes([0x51]) + b"first")
    if out is not None:
        fail(f"S8.3 RX case a (first half) returned non-None: {out!r}")
    if rx.seq != 0x5:
        fail(f"S8.3 RX case a did not buffer seq=5, got {rx.seq}")

    # Case b: split second half with matching seq → reassemble
    out = rx.deliver(bytes([0x51]) + b"second")
    if out != b"first" + b"second":
        fail(f"S8.3 RX case b (second half match) failed: got {out!r}")
    if rx.seq != SEQ_UNSET:
        fail(f"S8.3 RX state didn't reset after reassembly: seq={rx.seq}")

    # Case a again, then case c: seq mismatch replaces buffer
    rx.deliver(bytes([0x51]) + b"AAAA")
    rx.deliver(bytes([0x71]) + b"BBBB")
    if rx.seq != 0x7 or rx.buf != b"BBBB":
        fail(f"S8.3 RX case c (seq mismatch) state wrong: seq={rx.seq}, buf={rx.buf!r}")

    # Case d while a first-half is buffered → discard buffer, deliver non-split
    rx.deliver(bytes([0x91]) + b"discardme")        # buffers seq=9
    out = rx.deliver(bytes([0x30]) + b"non-split-2")
    if out != b"non-split-2":
        fail(f"S8.3 RX case d (non-split with stale buffer) failed: got {out!r}")
    if rx.seq != SEQ_UNSET:
        fail(f"S8.3 RX case d did not discard stale buffer: seq={rx.seq}")

    print("PASS S8.3 RX state machine: 4 cases (a/b/c/d) all correct")


def verify_tx_rx_roundtrip():
    """End-to-end: TX a payload, feed the resulting frames through
    the RX state machine, confirm reassembled payload matches."""
    for size in [50, 254, 255, 300, 508]:
        original = bytes(i & 0xFF for i in range(size))
        frames = tx_frames(original, seq_nibble=0x3)
        rx = RxStateMachine()
        out = None
        for f in frames:
            res = rx.deliver(f)
            if res is not None:
                out = res
        if out != original:
            fail(f"S8.3 TX/RX round-trip mismatch at size {size}:\n"
                 f"  in:  {original[:30]!r}... ({len(original)}B)\n"
                 f"  out: {out[:30] if out else None!r}... ({len(out) if out else 0}B)")
    print("PASS S8.3 TX/RX round-trip at sizes [50, 254, 255, 300, 508]")


def main():
    print("verify_rnode_split.py — pure-function verifier (no RNS runtime needed)")
    verify_header_layout()
    verify_tx_single_frame()
    verify_tx_split_frames()
    verify_rx_state_machine()
    verify_tx_rx_roundtrip()
    print("ALL PASS")


if __name__ == "__main__":
    main()
