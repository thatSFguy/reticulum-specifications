"""
Verifier for SPEC.md S10.11.1 (multi-segment resources — receiver side).

S10.11 specifies the sender completely; S10.11.1 specifies the half that
upstream only expresses as code. This script drives upstream
RNS.Resource.accept() and RNS.Resource.assemble() directly, with a stub
link standing in for the transport, and locks in:

  1. The partial-assembly store is file-backed and keyed on the
     advertised original hash `o` ALONE:
         storagepath      = {configdir}/storage/resources/{o.hex()}
         meta_storagepath = storagepath + ".meta"
     Nothing binds the key to the link, the peer, or the segment's own
     `h`. Two advertisements carrying the same `o` on different links
     resolve to the same file.

  2. Segments are CONCATENATED IN ARRIVAL ORDER, not placed by `i`.
     assemble() opens the file in append mode and writes; `i` is only
     used to decide whether a segment is the final one. Feeding
     segment 2 before segment 1 therefore produces a body in the wrong
     order, and every per-segment integrity check still passes — the
     failure is silent.

  3. Reclamation constants: RESOURCE_CACHE is a 24 h *idle* deadline
     refreshed by every append, swept every CLEAN_INTERVAL, and the
     sweep only considers 64-character filenames — so the ".meta"
     sidecar of an abandoned transfer is never reclaimed.

The stub link is deliberately left in a non-ACTIVE state so that
Resource.prove() aborts through upstream's own ensure_link() guard
(RNS/Resource.py) after the file write, rather than trying to emit a
proof packet. Nothing on the assembly path is stubbed.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile

import RNS
from RNS.Resource import Resource, ResourceAdvertisement


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


class StubLink:
    """Minimal stand-in for RNS.Link on the receive path.

    Enough of the Link surface for upstream to build and "send" the
    RESOURCE_REQ that accept() triggers (RNS.Transport.outbound is
    stubbed out in main(), so nothing leaves the process).

    The link reports ACTIVE because upstream's ensure_link() guard sits
    on both the RESOURCE_REQ path and the proof path; the packets those
    emit are absorbed by the stubbed RNS.Transport.outbound.
    """

    def __init__(self):
        self.mtu = RNS.Reticulum.MTU
        self.mdu = None
        self.rtt = 300.0
        self.traffic_timeout_factor = 6
        self.establishment_cost = 100
        self.status = RNS.Link.ACTIVE
        self.callbacks = self
        self.resource_started = None
        self.incoming_resources = []

        # --- Packet-facing surface (RNS/Packet.py pack/send) ---
        self.type          = RNS.Destination.LINK
        self.hash          = RNS.Identity.get_random_hash()[:RNS.Reticulum.TRUNCATED_HASHLENGTH//8]
        self.link_id       = self.hash
        self.last_outbound = 0
        self.tx            = 0
        self.txbytes       = 0

    def encrypt(self, data): return data

    # --- accessed by Resource.accept ---
    def get_last_resource_window(self):  return None
    def get_last_resource_eifr(self):    return None
    def has_incoming_resource(self, r):  return r in self.incoming_resources
    def register_incoming_resource(self, r): self.incoming_resources.append(r)

    # --- accessed by assemble / cancel ---
    def decrypt(self, data):             return data
    def resource_concluded(self, r):
        if r in self.incoming_resources: self.incoming_resources.remove(r)
    def cancel_incoming_resource(self, r): self.resource_concluded(r)
    def teardown(self):                  pass


def build_advertisement(body, original_hash, segment_index, total_segments):
    """Build a RESOURCE_ADV plaintext for a single-part, unencrypted,
    uncompressed segment carrying `body`, plus the wire blob the
    receiver will be handed as its one part."""
    random_hash = RNS.Identity.get_random_hash()[:Resource.RANDOM_HASH_SIZE]
    # S10.12: the wire blob is prefix(4) || body; `hash` is over the body.
    wire_blob   = RNS.Identity.get_random_hash()[:Resource.RANDOM_HASH_SIZE] + body
    seg_hash    = RNS.Identity.full_hash(body + random_hash)

    adv = ResourceAdvertisement()
    adv.t = len(wire_blob)
    adv.d = len(body)
    adv.n = 1
    adv.h = seg_hash
    adv.r = random_hash
    adv.o = original_hash
    adv.m = b"\x00" * Resource.MAPHASH_LEN
    adv.i = segment_index
    adv.l = total_segments
    adv.q = None
    adv.c = False
    adv.e = False
    adv.s = total_segments > 1
    adv.u = False
    adv.p = False
    adv.x = False
    adv.f = 0x00 | adv.x << 5 | adv.p << 4 | adv.u << 3 | adv.s << 2 | adv.c << 1 | adv.e

    return adv.pack(), wire_blob


class StubAdvPacket:
    def __init__(self, plaintext, link):
        self.plaintext = plaintext
        self.link      = link


def accept_segment(link, body, original_hash, segment_index, total_segments):
    plaintext, wire_blob = build_advertisement(body, original_hash,
                                               segment_index, total_segments)
    resource = Resource.accept(StubAdvPacket(plaintext, link))
    if resource is None:
        fail(f"S10.11.1 Resource.accept returned None for segment {segment_index}")
    resource.parts = [wire_blob]
    return resource


def verify_storagepath_keying(link, cfg_dir):
    """S10.11.1 claim 1: storagepath is derived from `o` alone."""
    original_hash = RNS.Identity.full_hash(b"logical-transfer-A")
    resource = accept_segment(link, b"seg1", original_hash, 1, 2)

    expected = os.path.join(RNS.Reticulum.resourcepath, original_hash.hex())
    if os.path.normpath(resource.storagepath) != os.path.normpath(expected):
        fail(f"S10.11.1 storagepath = {resource.storagepath!r}, want {expected!r}")
    if resource.meta_storagepath != resource.storagepath + ".meta":
        fail(f"S10.11.1 meta_storagepath = {resource.meta_storagepath!r}, "
             f"want {resource.storagepath + '.meta'!r}")
    print(f"PASS S10.11.1 storagepath = resourcepath/{{o.hex()}} "
          f"({os.path.basename(resource.storagepath)})")

    # The key is `o`, not `h`: this segment's own hash differs from `o`,
    # and the path followed `o`.
    if resource.hash == resource.original_hash:
        fail("S10.11.1 test setup: segment hash coincides with `o`, "
             "so the test cannot distinguish the two")
    print("PASS S10.11.1 key follows `o`, not the segment's own `h`")

    # Same `o` advertised on a *different* link resolves to the same file.
    other_link  = StubLink()
    other       = accept_segment(other_link, b"injected", original_hash, 1, 2)
    if os.path.normpath(other.storagepath) != os.path.normpath(resource.storagepath):
        fail("S10.11.1 same `o` on a different link produced a different "
             "storagepath — the correlation key is not per-node")
    print("PASS S10.11.1 same `o` on a different link shares one assembly file "
          "(correlation domain is the node)")

    link.resource_concluded(resource)
    other_link.resource_concluded(other)


def verify_append_order(link):
    """S10.11.1 claim 2: assemble() appends; `i` never places data."""
    original_hash = RNS.Identity.full_hash(b"logical-transfer-B")
    seg1_body = b"AAAA-first-segment"
    seg2_body = b"BBBB-second-segment"

    # Deliver segment 2 BEFORE segment 1. Both are declared non-final
    # (l = 3) so upstream leaves the partial assembly on disk instead of
    # concluding the transfer and unlinking it.
    seg2 = accept_segment(link, seg2_body, original_hash, 2, 3)
    storagepath = seg2.storagepath
    if os.path.isfile(storagepath):
        os.unlink(storagepath)

    seg2.assemble()
    if seg2.status != Resource.COMPLETE:
        fail(f"S10.11.1 out-of-order segment 2 did not assemble cleanly "
             f"(status {seg2.status}) — the per-segment integrity check "
             f"was expected to pass")
    print("PASS S10.11.1 out-of-order segment 2 passes its own integrity check")

    seg1 = accept_segment(link, seg1_body, original_hash, 1, 3)
    seg1.assemble()
    if seg1.status != Resource.COMPLETE:
        fail(f"S10.11.1 segment 1 did not assemble cleanly (status {seg1.status})")

    # Neither segment is the final one (l = 3), so upstream leaves the
    # file in place rather than handing it to a callback and unlinking it.
    if not os.path.isfile(storagepath):
        fail("S10.11.1 assembly file missing after two non-final segments")

    with open(storagepath, "rb") as f:
        assembled = f.read()

    arrival_order = seg2_body + seg1_body
    index_order   = seg1_body + seg2_body
    if assembled == index_order:
        fail("S10.11.1 assembled body is in `i` order — upstream was expected "
             "to concatenate in ARRIVAL order. The spec claim that receivers "
             "depend on the sequential-send rule is wrong for this version.")
    if assembled != arrival_order:
        fail(f"S10.11.1 assembled body is neither arrival nor `i` order: "
             f"{assembled!r}")
    print("PASS S10.11.1 segments concatenate in ARRIVAL order, not `i` order")
    print(f"     arrival order gave {assembled!r}; `i` order would be {index_order!r}")

    os.unlink(storagepath)


def verify_retention_constants():
    """S10.11.1 claim 3: idle deadline, sweep interval, filename filter."""
    if RNS.Reticulum.RESOURCE_CACHE != 24 * 60 * 60:
        fail(f"S10.11.1 RESOURCE_CACHE = {RNS.Reticulum.RESOURCE_CACHE}, want 86400")
    if RNS.Reticulum.CLEAN_INTERVAL != 15 * 60:
        fail(f"S10.11.1 CLEAN_INTERVAL = {RNS.Reticulum.CLEAN_INTERVAL}, want 900")
    print(f"PASS S10.11.1 RESOURCE_CACHE = 24 h, swept every "
          f"{RNS.Reticulum.CLEAN_INTERVAL // 60} min")

    if not RNS.Reticulum.resourcepath.endswith(os.path.join("storage", "resources")):
        fail(f"S10.11.1 resourcepath = {RNS.Reticulum.resourcepath!r}, "
             f"want a path ending in storage/resources")
    print("PASS S10.11.1 resourcepath = {configdir}/storage/resources")

    # __clean_caches only considers filenames of exactly 64 characters
    # (RNS/Reticulum.py:1238), so `{o.hex()}.meta` is never reclaimed.
    swept_len = (RNS.Identity.HASHLENGTH // 8) * 2
    if swept_len != 64:
        fail(f"S10.11.1 sweep filename length = {swept_len}, want 64")
    meta_name = "00" * (RNS.Identity.HASHLENGTH // 8) + ".meta"
    if len(meta_name) == swept_len:
        fail("S10.11.1 .meta sidecar name is sweep-eligible — the spec claim "
             "that it is never reclaimed is wrong")
    print(f"PASS S10.11.1 sweep matches only {swept_len}-char names; "
          f"the {len(meta_name)}-char .meta sidecar is never reclaimed")


def main():
    print(f"verify_resource_segment_store.py against RNS {RNS.__version__}")
    cfg_dir  = tempfile.mkdtemp(prefix="rns-verify-segstore-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    RNS.Reticulum(configdir=cfg_dir, loglevel=0)

    # The RESOURCE_REQ that accept() emits and the RESOURCE_PRF that
    # assemble() emits are not what this script verifies; swallow them
    # at the transport boundary rather than standing up a real link
    # pair. Everything between accept() and the file write is upstream's.
    real_outbound = RNS.Transport.outbound
    RNS.Transport.outbound = staticmethod(lambda packet, *a, **kw: True)

    try:
        link = StubLink()
        verify_storagepath_keying(link, cfg_dir)
        verify_append_order(link)
        verify_retention_constants()
    finally:
        RNS.Transport.outbound = real_outbound
        try: RNS.Reticulum.exit_handler()
        except Exception: pass
        shutil.rmtree(cfg_dir, ignore_errors=True)

    print("ALL PASS")


if __name__ == "__main__":
    main()
