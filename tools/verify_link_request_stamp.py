"""
Verifier for SPEC.md S6.1 link-request stamps (RNS >= 1.6).

Since RNS 1.6 an initiator may make its ephemeral X25519 public key a
*stamped key*: SHA-256(dest_hash || initiator_Ed25519_pub || X25519_pub)
meets the target for the link cost the destination announced in its S4.7
trailer. The LINKREQUEST layout does not change; the stamp is the key.

  1. Defaults: STAMP_LRS on, ALWAYS_STAMP_LRS off, LR_STAMPS_ENFORCED off,
     LR_COST 12.5, LINK_COST_CAP 40; Link.STAMP_FAILURE = 0x04.

  2. Initiator, destination announced lr_cost 6: the LINKREQUEST is still
     64 or 67 bytes, and its X25519 key is valid against
     material = dest_hash || initiator_Ed25519_pub at cost 6.

  3. Initiator, no announced cost: the request is not stamped (sent
     synchronously from the constructor, as through RNS 1.5.7).

  4. Responder, Link.validate_request: with LR_STAMPS_ENFORCED a request
     below owner.get_link_cost() is refused (returns None) and a stamped
     one is accepted; with enforcement off (the default) both are
     accepted and the measured value is recorded on link.stamp_cost.

Exit code 0 on PASS, non-zero on FAIL. Fails at RNS 1.5.7.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import time

import RNS
from RNS.Link import Link


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-lr-stamp-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


class Capture:
    """Swallow outbound packets, keeping the LINKREQUESTs."""
    def __init__(self):
        self.requests = []
        self.real = RNS.Transport.outbound

    def __enter__(self):
        def fake_outbound(packet):
            if packet.packet_type == RNS.Packet.LINKREQUEST:
                self.requests.append(packet)
            return True
        RNS.Transport.outbound = staticmethod(fake_outbound)
        return self

    def __exit__(self, *a):
        RNS.Transport.outbound = self.real


def responder(aspect):
    bob_id = RNS.Identity()
    bob_in = RNS.Destination(bob_id, RNS.Destination.IN, RNS.Destination.SINGLE, "verify_lr_stamp", aspect)
    bob_out = RNS.Destination(bob_id, RNS.Destination.OUT, RNS.Destination.SINGLE, "verify_lr_stamp", aspect)
    return bob_id, bob_in, bob_out


def send_request(bob_id, bob_out, lr_cost):
    RNS.Identity.remember(os.urandom(32), bob_out.hash, bob_id.get_public_key(), None, lr_cost=lr_cost)
    with Capture() as cap:
        link = Link(destination=bob_out)
        deadline = time.time() + 60
        while not cap.requests and time.time() < deadline:
            time.sleep(0.05)
    if not cap.requests:
        fail(f"S6.1 no LINKREQUEST was emitted for lr_cost={lr_cost!r}")
    return link, cap.requests[0]


def verify_defaults():
    T = RNS.Transport
    got = (T.STAMP_LRS, T.ALWAYS_STAMP_LRS, T.LR_STAMPS_ENFORCED, T.LR_COST, T.LINK_COST_CAP, T.LINK_STAMP_TIMEOUT)
    if got != (True, False, False, 12.5, 40, 15):
        fail(f"S6.1 (STAMP_LRS, ALWAYS_STAMP_LRS, LR_STAMPS_ENFORCED, LR_COST, LINK_COST_CAP, LINK_STAMP_TIMEOUT) = {got}")
    if Link.STAMP_FAILURE != 0x04:
        fail(f"S6.7.4 Link.STAMP_FAILURE = {Link.STAMP_FAILURE!r}, want 0x04")
    print("PASS S6.1 defaults: stamp LRs when a cost is announced, enforcement off, LR_COST 12.5, cap 40; STAMP_FAILURE 0x04")


def verify_initiator():
    bob_id, bob_in, bob_out = responder("stamped")
    link, req = send_request(bob_id, bob_out, 6.0)
    body = req.data
    if len(body) not in (64, 67):
        fail(f"S6.1 stamped LINKREQUEST body is {len(body)} bytes, want 64 or 67")
    x_pub, ed_pub = body[:32], body[32:64]
    if x_pub != link.pub_bytes or ed_pub != link.sig_pub_bytes:
        fail("S6.1 LINKREQUEST keys are not the link's ephemeral keys")
    material = bob_out.hash + ed_pub
    if not RNS.Stamps.stamp_valid(x_pub, 6.0, material):
        fail("S6.1 initiator X25519 key does not meet the announced link cost 6")
    lz = 256 - int.from_bytes(hashlib.sha256(material + x_pub).digest(), "big").bit_length()
    print(f"PASS S6.1 stamped LINKREQUEST: {len(body)}-byte body, X25519 key meets cost 6 over "
          f"dest_hash||Ed25519_pub ({lz} leading zero bits)")

    _, bob_in2, bob_out2 = responder("plain")
    bob_id2 = bob_out2.identity
    link2, req2 = send_request(bob_id2, bob_out2, None)
    if link2.stamp_cost is not None:
        fail(f"S6.1 no announced cost, yet link.stamp_cost = {link2.stamp_cost!r}")
    print("PASS S6.1 no announced lr_cost: the request is not stamped")
    return bob_in, req, bob_in2, req2


def validate(owner, req):
    inbound = RNS.Packet(None, req.raw)
    inbound.unpack()
    inbound.destination = owner
    with Capture():
        return Link.validate_request(owner, inbound.data, inbound)


def verify_responder(bob_in, stamped_req, bob_in2, plain_req):
    T = RNS.Transport
    bob_in.set_link_cost(6.0)

    # A request that misses cost 6 against bob_in. Reuse the unstamped
    # request's key material only if it happens to miss; otherwise draw
    # fresh ephemeral keys until one does.
    while True:
        x = RNS.Cryptography.X25519PrivateKey.generate().public_key().public_bytes()
        e = RNS.Cryptography.Ed25519PrivateKey.generate().public_key().public_bytes()
        if not RNS.Stamps.stamp_valid(x, 6.0, bob_in.hash + e):
            break
    weak = RNS.Packet(bob_in, x + e, packet_type=RNS.Packet.LINKREQUEST)
    weak.pack()

    T.LR_STAMPS_ENFORCED = True
    try:
        if validate(bob_in, weak) is not None:
            fail("S6.1 enforced: a LINKREQUEST below the link cost was accepted")
        link = validate(bob_in, stamped_req)
        if link is None:
            fail("S6.1 enforced: a stamped LINKREQUEST meeting the cost was refused")
        if not link.stamp_cost >= 6.0:
            fail(f"S6.1 accepted link records stamp_cost {link.stamp_cost!r}, want >= 6")
    finally:
        T.LR_STAMPS_ENFORCED = False
    print("PASS S6.1 LR_STAMPS_ENFORCED: below-cost request refused, stamped request accepted")

    link = validate(bob_in, weak)
    if link is None:
        fail("S6.1 not enforced (default): a below-cost LINKREQUEST was refused")
    if link.stamp_cost is None or link.stamp_cost >= 6.0:
        fail(f"S6.1 not enforced: recorded stamp_cost {link.stamp_cost!r}, want the measured value below 6")
    print(f"PASS S6.1 default (not enforced): below-cost request accepted, value {link.stamp_cost} recorded")


def main():
    print(f"verify_link_request_stamp.py against RNS {RNS.__version__}")
    if not hasattr(RNS.Transport, "LR_STAMPS_ENFORCED"):
        fail("S6.1 this RNS has no link-request stamps (added in RNS 1.6)")
    init_minimal_rns()
    try:
        verify_defaults()
        bob_in, req, bob_in2, req2 = verify_initiator()
        verify_responder(bob_in, req, bob_in2, req2)
    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass
    print("ALL PASS")


if __name__ == "__main__":
    main()
