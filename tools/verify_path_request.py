"""
Verifier for SPEC.md S7.1, S7.2 (path requests).

Verifies:
  - The well-known path-request destination hash:
        SHA256(SHA256("rnstransport.path.request")[:10])[:16]
        == 6b9f66014d9853faab220fba47d02761
  - The full SPEC table for `name_hash` values.
  - The path-request payload upstream `RNS.Transport.request_path` emits,
    captured at runtime (RNS >= 1.6.0; leaf and transport nodes alike):
       unstamped: destination_hash(16) || transport_id(16) || tag(16)     -> 48B
       stamped  : ... || 0xC1 0x00 || stamp(14)                           -> 64B
    and that the stamp is proof of work over SHA256(dest || tag || stamp).
    Through RNS 1.5.7 a leaf sent destination_hash || tag (32B) and nothing
    was stamped.
  - The receive-side gate in `Transport.preprocess_inbound`: only 32, 48 and
    64-byte requests pass, and stamps are validated but not enforced by
    default (`Transport.STAMPS_ENFORCED = False`).
  - That LXMF triggers a path? request from `LXMRouter.handle_outbound`
    (line 1777 in LXMF 1.1.0) ONLY when `not has_path(destination_hash) and
    method == OPPORTUNISTIC`. The "always-precedes" claim in older spec drafts
    is too strong: the request is conditional on the path-table miss.
  - The S7.1 retry-loop timing constants on the LXMRouter class
    (LXMF/LXMRouter.py:30-34): PATH_REQUEST_WAIT = 7, DELIVERY_RETRY_WAIT = 10,
    MAX_DELIVERY_ATTEMPTS = 5, MAX_PATHLESS_TRIES = 1.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import sys
import tempfile
import time

import RNS
import LXMF
from LXMF.LXMRouter import LXMRouter
from RNS.Interfaces.Interface import Interface


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def verify_well_known_hashes():
    cases = [
        ("lxmf.delivery",                   "6ec60bc318e2c0f0d908"),
        ("lxmf.propagation",                "e03a09b77ac21b22258e"),
        ("nomadnetwork.node",               "213e6311bcec54ab4fde"),
        ("nomadnetwork.gossip",             "0ad8bff9ff75737c058e"),
        ("rnstransport.broadcasts",         "9efb9c771eeb5ae90ea6"),
        ("rnstransport.remote.management",  "4848a053c16415bed6c8"),
        ("rnstransport.path.request",       "7926bbe7dd7f9aba88b0"),
        ("rnstransport.discovery.interface", "55aa39e85c3e045e9cb1"),
    ]
    for name, expected_namehash_hex in cases:
        actual = hashlib.sha256(name.encode("utf-8")).digest()[:10]
        if actual.hex() != expected_namehash_hex:
            fail(f"S1.2 name_hash for {name!r}: "
                 f"got {actual.hex()} want {expected_namehash_hex}")
    print("PASS S1.2 well-known name_hash table")

    # Full path-request dest_hash: SHA256(name_hash || identity_hash)[:16]
    # with identity=None -> identity_hash = b"" (Destination.hash w/ identity=None
    # at RNS/Destination.py:121 has addr_hash_material = name_hash only).
    expected_pr_dest_hash = "6b9f66014d9853faab220fba47d02761"
    namehash = hashlib.sha256(b"rnstransport.path.request").digest()[:10]
    pr_dest_hash = hashlib.sha256(namehash).digest()[:16]
    if pr_dest_hash.hex() != expected_pr_dest_hash:
        fail(f"S7.1 path-request dest_hash: got {pr_dest_hash.hex()} "
             f"want {expected_pr_dest_hash}")
    print("PASS S7.1 path-request dest_hash 6b9f66014d9853faab220fba47d02761")


PR_DEST_HASH = bytes.fromhex("6b9f66014d9853faab220fba47d02761")
EXT_MARKER = 0xC1       # RNS.Identity.EXTPAYLOADMARKER
STAMP_LEN = 14          # RNS.Identity.STAMPLENGTH


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-pr-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def leading_zero_bits(b: bytes) -> int:
    n = int.from_bytes(b, "big")
    return len(b) * 8 - n.bit_length()


def capture_request_path(dest_hash, **kwargs) -> bytes:
    """Run upstream Transport.request_path and return the payload of the
    packet it hands to Packet.send."""
    sent = []
    orig = RNS.Packet.send

    def fake_send(self):
        sent.append(self)
        return None

    RNS.Packet.send = fake_send
    try:
        RNS.Transport.request_path(dest_hash, **kwargs)
    finally:
        RNS.Packet.send = orig
    if len(sent) != 1:
        fail(f"S7.1 request_path sent {len(sent)} packets, expected 1")
    pkt = sent[0]
    if pkt.destination.hash != PR_DEST_HASH:
        fail(f"S7.1 request_path addressed {pkt.destination.hash.hex()}")
    if (pkt.packet_type, pkt.header_type, pkt.transport_type, pkt.context) != (
            RNS.Packet.DATA, RNS.Packet.HEADER_1, RNS.Transport.BROADCAST, RNS.Packet.NONE):
        fail("S7.1 request_path packet is not DATA/HEADER_1/BROADCAST/NONE")
    return pkt.data


def verify_request_path_payload_format():
    """S7.1 (RNS >= 1.6.0): every emitted path request carries a transport_id,
    leaf or not, and by default a 16-byte stamp extension."""
    target = os.urandom(16)
    tid = RNS.Transport.identity.hash

    # Unstamped form (STAMP_PRS off): dest || transport_id || tag = 48 bytes.
    # Through RNS 1.5.7 a leaf (transport disabled, as here) sent dest || tag.
    RNS.Transport.STAMP_PRS = False
    try:
        data = capture_request_path(target)
    finally:
        RNS.Transport.STAMP_PRS = True
    if len(data) != 48:
        fail(f"S7.1 unstamped leaf path request is {len(data)} bytes, expected "
             f"48 (dest || transport_id || tag); RNS < 1.6.0 sent 32")
    if data[:16] != target or data[16:32] != tid:
        fail("S7.1 unstamped path request is not dest || Transport.identity.hash || tag")
    print("PASS S7.1 unstamped path request = dest(16) || transport_id(16) || "
          "tag(16), sent by a leaf too")

    # Stamped form (the default): dest || transport_id || tag || C1 00 || stamp(14)
    tag, ext = RNS.Transport.stamp_path_request(target, return_payload=True)
    data = capture_request_path(target, tag=tag, ext_payload=ext)
    if len(data) != 64:
        fail(f"S7.1 stamped path request is {len(data)} bytes, expected 64")
    if data[:16] != target or data[16:32] != tid or data[32:48] != tag:
        fail("S7.1 stamped path request prefix is not dest || transport_id || tag")
    if data[48] != EXT_MARKER or data[49] != 0x00:
        fail(f"S7.1 stamp extension header is {data[48:50].hex()}, expected c100")
    stamp = data[50:]
    # Independent of upstream's stamp code: the proof of work is SHA-256 over
    # dest || tag || stamp, no workblock expansion, and the default emitted
    # value is 15.8 bits, so at least 15 leading zero bits.
    lz = leading_zero_bits(hashlib.sha256(target + tag + stamp).digest())
    if lz < 15:
        fail(f"S7.1 path request stamp has {lz} leading zero bits over "
             f"SHA256(dest || tag || stamp); expected >= 15 for PR_VALUE 15.8")
    if not RNS.Transport.validate_pr_stamp(stamp, target, tag):
        fail("S7.1 upstream validate_pr_stamp rejected its own stamp")
    if RNS.Transport.validate_pr_stamp(stamp, os.urandom(16), tag):
        fail("S7.1 validate_pr_stamp accepted a stamp bound to another destination")
    print(f"PASS S7.1 stamped path request = ... || c1 00 || stamp(14); "
          f"SHA256(dest||tag||stamp) has {lz} leading zero bits (PR_VALUE "
          f"{RNS.Transport.PR_VALUE}, PR_COST {RNS.Transport.PR_COST})")


class PRInterface(Interface):
    """A real upstream Interface that records what preprocess_inbound does."""

    def __init__(self):
        super().__init__()
        self.name = "verify-pr"
        self.online = True
        # Attributes a concrete interface class sets for itself.
        self.HW_MTU = RNS.Reticulum.MTU
        self.ifac_size = 0
        self.ifac_identity = None
        self.bitrate = 10_000_000
        self.violations = []
        self.prs_received = 0

    def protocol_violation(self, description=None, level=None):
        self.violations.append(description)

    def received_path_request(self, size=0, from_spawned=False):
        self.prs_received += 1

    def process_outgoing(self, data):
        pass

    def __str__(self):
        return "PRInterface"


def pr_frame(data: bytes) -> bytes:
    # flags 0x08: HEADER_1, BROADCAST, destination_type PLAIN, packet_type DATA
    return bytes([0x08, 0x00]) + PR_DEST_HASH + bytes([0x00]) + data


def feed(data: bytes):
    iface = PRInterface()
    RNS.Transport.inbound(pr_frame(data), iface)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and not (iface.violations or iface.prs_received):
        time.sleep(0.01)
    return iface


def verify_path_request_ingress():
    """S7.2.1 (RNS >= 1.6.0): only 32 (legacy), 48 and 64-byte path requests
    are accepted; stamps are checked but, by default, not enforced."""
    def tag():
        return os.urandom(16)

    for n in (33, 47, 49, 63):
        iface = feed(os.urandom(n))
        if iface.prs_received or not any("Invalid path request size" in (v or "")
                                         for v in iface.violations):
            fail(f"S7.2.1 a {n}-byte path request was not refused as an invalid "
                 f"size: {iface.violations}")
    iface = feed(os.urandom(65))
    if not any("Excessive path request size" in (v or "") for v in iface.violations):
        fail(f"S7.2.1 a 65-byte path request was not refused: {iface.violations}")
    iface = feed(os.urandom(16))
    if not any("Tagless" in (v or "") for v in iface.violations):
        fail(f"S7.2.1 a 16-byte (tagless) path request was not refused: {iface.violations}")
    print("PASS S7.2.1 path-request sizes: 16 / 33-47 / 49-63 / >64 refused as "
          "protocol violations")

    target = os.urandom(16)
    tid = os.urandom(16)
    legacy = target + tag()
    plain = target + tid + tag()
    bogus = target + tid + tag() + bytes([EXT_MARKER, 0x00]) + os.urandom(STAMP_LEN)
    t = tag()
    _, ext = RNS.Transport.stamp_path_request(target, tag=t, return_payload=True)
    good = target + tid + t + ext

    for name, data in (("32-byte legacy", legacy), ("48-byte unstamped", plain),
                       ("64-byte bad-stamp", bogus), ("64-byte stamped", good)):
        iface = feed(data)
        if iface.violations or not iface.prs_received:
            fail(f"S7.2.1 a {name} path request was not accepted with stamps "
                 f"unenforced: {iface.violations}")
    print("PASS S7.2.1 with STAMPS_ENFORCED=False (the default) legacy, "
          "unstamped and bad-stamp path requests are all still accepted")

    RNS.Transport.STAMPS_ENFORCED = True
    try:
        for name, data, want in (
            ("48-byte unstamped", target + tid + tag(), False),
            ("64-byte bad-stamp", target + tid + tag() + bytes([EXT_MARKER, 0x00]) + os.urandom(STAMP_LEN), False),
            ("64-byte stamped", None, True),
        ):
            if data is None:
                t = tag()
                _, ext = RNS.Transport.stamp_path_request(target, tag=t, return_payload=True)
                data = target + tid + t + ext
            iface = feed(data)
            if bool(iface.prs_received) != want:
                fail(f"S7.2.1 under STAMPS_ENFORCED a {name} path request was "
                     f"{'dropped' if want else 'accepted'}")
    finally:
        RNS.Transport.STAMPS_ENFORCED = False
    print("PASS S7.2.1 with STAMPS_ENFORCED=True only a valid stamp is accepted")


def verify_lxmf_only_when_pathless():
    # Confirm the LXMF outbound path-request is gated on
    # `not has_path(destination_hash) and method == OPPORTUNISTIC`.
    src = inspect.getsource(LXMRouter.handle_outbound)
    if "not RNS.Transport.has_path(destination_hash) and lxmessage.method == LXMessage.OPPORTUNISTIC" not in src:
        fail("S7.1 LXMF path-request gating expression not found in "
             "LXMRouter.handle_outbound — upstream may have changed the rule. "
             f"Source excerpt:\n{src[:2000]}")
    if "Pre-emptively requesting unknown path" not in src:
        fail("S7.1 LXMF 'Pre-emptively requesting unknown path' log line not found "
             "in handle_outbound")
    print(f"PASS S7.1 LXMF {LXMF.__version__}: path? issued only when "
          "has_path()=False AND method=OPPORTUNISTIC "
          "(LXMF/LXMRouter.py handle_outbound)")


def verify_retry_constants():
    # S7.1 timing constants — class-level on LXMRouter (LXMF/LXMRouter.py:30-34).
    expected = {
        "PATH_REQUEST_WAIT": 7,
        "DELIVERY_RETRY_WAIT": 10,
        "MAX_DELIVERY_ATTEMPTS": 5,
        "MAX_PATHLESS_TRIES": 1,
    }
    for name, want in expected.items():
        got = getattr(LXMRouter, name, None)
        if got != want:
            fail(f"S7.1 LXMRouter.{name}: got {got!r} want {want!r} "
                 f"(LXMF {LXMF.__version__}) — upstream changed the retry "
                 "timing; update SPEC.md S7.1 and flows/lxmf-outbound-retry.md")
    print("PASS S7.1 retry constants (PATH_REQUEST_WAIT=7, DELIVERY_RETRY_WAIT=10, "
          "MAX_DELIVERY_ATTEMPTS=5, MAX_PATHLESS_TRIES=1)")


def main():
    print(f"verify_path_request.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    verify_well_known_hashes()
    reticulum = init_minimal_rns()
    verify_request_path_payload_format()
    verify_path_request_ingress()
    verify_lxmf_only_when_pathless()
    verify_retry_constants()
    print("ALL PASS")


if __name__ == "__main__":
    main()
