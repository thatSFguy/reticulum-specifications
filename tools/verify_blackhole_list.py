"""
Verifier for SPEC.md S12.7 (blackhole lists, `rnstransport.info.blackhole`).

A node can publish its list of blackholed identities, and other nodes can
subscribe to it. Publishing is a SINGLE destination `rnstransport.info.blackhole`
under the transport identity, with one request handler, `/list` (S11), whose
response is the node's whole `blackholed_identities` table. This drives upstream
directly and checks:

  1. name_hash of `rnstransport.info.blackhole`; with `publish_blackhole = yes`
     the destination exists under Transport.identity, has a link cost of 5.25,
     and registers `/list` with ALLOW_ALL.
  2. Entry shape from Transport.blackhole_identity:
        {identity_hash(16): {"source": bytes(16), "until": float|int|None,
                              "reason": str|None}}
     and its msgpack encoding (bin16 keys, str sub-keys), which is the `/list`
     response body before S11 framing.
  3. `/list` returns ALL entries, including ones learned from other sources.
  4. Only locally-sourced entries are persisted, to storage/blackhole/local.
  5. Subscriber merge (BlackholeUpdater.update_link_established, fed a stub
     link): new entries are added, existing ones are not overwritten, and
     the list is persisted to storage/blackhole/<source hex>.
  6. reload_blackhole: a file whose source is not in blackhole_sources is
     ignored; expired entries are dropped; a remote list never replaces a
     local entry.
  7. A blackholed identity's announce is refused (S4.5 step 5).

The `/list` round trip over a real Link is not run here: that needs a second
Reticulum instance. The response framing is S11's, checked by its own
verifiers; this checks the body it carries.

Exit code 0 on PASS, non-zero on FAIL. Fails at RNS 1.5.7, where the
destination has no link cost.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import time

import RNS
import RNS.Discovery as D
from RNS.vendor import umsgpack as msgpack


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", flush=True)
    os._exit(1)


def init_rns(source_hex: str):
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-blackhole-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n"
                "publish_blackhole = yes\n"
                f"blackhole_sources = {source_hex}\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


class StubReceipt:
    def __init__(self, response): self.response = response
    def concluded(self): return True
    def get_response(self): return self.response


class StubLink:
    """What BlackholeUpdater.update_link_established touches on a Link."""
    def __init__(self, remote_identity, response):
        self.remote_identity, self.response, self.requested = remote_identity, response, []
    def get_remote_identity(self): return self.remote_identity
    def request(self, path, *a, **kw): self.requested.append(path); return StubReceipt(self.response)
    def teardown(self): pass


def read_msgpack(path):
    with open(path, "rb") as f: return msgpack.unpackb(f.read())


def main():
    source = RNS.Identity()          # a remote blackhole publisher we subscribe to
    init_rns(source.hash.hex())
    T = RNS.Transport
    print(f"verify_blackhole_list.py against RNS {RNS.__version__}")

    # 1. the publishing destination
    nh = hashlib.sha256(b"rnstransport.info.blackhole").digest()[:10].hex()
    d = T.blackhole_destination
    if d is None:
        fail("S12.7 publish_blackhole = yes did not create Transport.blackhole_destination")
    if d.name_hash.hex() != nh or nh != "9e059549ef49a8c64d18":
        fail(f"S12.7 name_hash {d.name_hash.hex()} / {nh}, want 9e059549ef49a8c64d18")
    if d.identity is not T.identity or d.type != RNS.Destination.SINGLE:
        fail("S12.7 blackhole destination is not SINGLE under Transport.identity")
    if d.hash != RNS.Destination.hash_from_name_and_identity("rnstransport.info.blackhole", T.identity.hash):
        fail("S12.7 subscribers derive the destination from the publisher's identity hash; they disagree")
    if not hasattr(d, "get_link_cost"):
        fail("S12.7 this RNS has no destination link costs (added in RNS 1.6)")
    if d.get_link_cost() != 5.25:
        fail(f"S12.7 blackhole destination link cost = {d.get_link_cost()}, want 5.25")
    ph = RNS.Identity.truncated_hash(b"/list")
    if ph not in d.request_handlers or d.request_handlers[ph][2] != RNS.Destination.ALLOW_ALL:
        fail("S12.7 `/list` is not registered with ALLOW_ALL")
    print("PASS S12.7 rnstransport.info.blackhole (name_hash 9e059549ef49a8c64d18): SINGLE under the "
          "transport identity, link cost 5.25, `/list` open to all")

    # 2. entry shape and encoding
    local_bad = RNS.Identity().hash
    until = time.time() + 3600
    if T.blackhole_identity(local_bad, until=until, reason="spam") is not True:
        fail("S12.7 blackhole_identity did not return True")
    entry = T.blackholed_identities[local_bad]
    if entry != {"source": T.identity.hash, "until": until, "reason": "spam"}:
        fail(f"S12.7 local entry = {entry!r}")
    body = T.blackhole_list_handler("/list", None, b"\x00" * 16, b"\x00" * 16, None, time.time())
    packed = msgpack.packb(body)
    if not packed.startswith(b"\x81\xc4\x10" + local_bad):
        fail(f"S12.7 `/list` body does not start with a 1-entry map keyed by bin16: {packed[:20].hex()}")
    if msgpack.unpackb(packed) != {local_bad: entry}:
        fail("S12.7 `/list` body does not round-trip through msgpack")
    print("PASS S12.7 entry = {source: bin16, until: float|nil, reason: str|nil}; `/list` body is a "
          "msgpack map keyed by bin16 identity hash")

    # 5. subscriber merge (before 3, so the table holds a remote entry)
    remote_new = RNS.Identity().hash
    remote_list = {
        remote_new: {"source": source.hash, "until": None, "reason": "remote"},
        local_bad:  {"source": source.hash, "until": None, "reason": "would overwrite"},
    }
    link = StubLink(source, remote_list)
    D.BlackholeUpdater().update_link_established(link)
    if link.requested != ["/list"]:
        fail(f"S12.7 subscriber requested {link.requested}, want ['/list']")
    if T.blackholed_identities.get(remote_new, {}).get("reason") != "remote":
        fail("S12.7 subscriber did not add a new remote entry")
    if T.blackholed_identities[local_bad]["reason"] != "spam":
        fail("S12.7 a remote list overwrote an existing entry")
    srcfile = os.path.join(RNS.Reticulum.blackholepath, source.hash.hex())
    if not os.path.isfile(srcfile) or read_msgpack(srcfile) != remote_list:
        fail("S12.7 subscriber did not persist the fetched list verbatim under storage/blackhole/<source hex>")
    print("PASS S12.7 subscriber requests `/list`, adds new entries, never overwrites, persists to "
          "storage/blackhole/<source>")

    # 5b. upstream stores fetched entries as received, `source` included. An
    # entry claiming source = OUR transport identity is then treated as local
    # and written to storage/blackhole/local by the next persist. This asserts
    # current upstream behaviour (S12.7 hazard); if upstream starts rewriting
    # `source` to the publisher, this fails and S12.7 needs updating.
    spoofed = RNS.Identity().hash
    D.BlackholeUpdater().update_link_established(
        StubLink(source, {spoofed: {"source": T.identity.hash, "until": None, "reason": "claims local"}}))
    extra_local = RNS.Identity().hash
    T.blackhole_identity(extra_local)                  # any local blackhole persists
    if spoofed not in read_msgpack(os.path.join(RNS.Reticulum.blackholepath, "local")):
        fail("S12.7 hazard no longer reproduces: a fetched entry claiming our own source was not "
             "persisted as local. Upstream changed; update S12.7")
    T.unblackhole_identity(spoofed)
    print("PASS S12.7 hazard: fetched entries keep the publisher-supplied `source`; one claiming ours "
          "is persisted as local")

    # 3. `/list` republishes everything it holds
    body = T.blackhole_list_handler("/list", None, b"\x00" * 16, b"\x00" * 16, None, time.time())
    if remote_new not in body:
        fail("S12.7 `/list` omitted an entry learned from another source")
    print("PASS S12.7 `/list` returns every entry held, including ones learned from other publishers")

    # 4. only local entries persist locally
    local = read_msgpack(os.path.join(RNS.Reticulum.blackholepath, "local"))
    if set(local) != {local_bad, extra_local}:
        fail(f"S12.7 storage/blackhole/local holds {len(local)} entries, want only the two local ones")
    print("PASS S12.7 storage/blackhole/local holds only locally-sourced entries")

    # 6. reload rules
    stranger = RNS.Identity()
    expired, live = RNS.Identity().hash, RNS.Identity().hash
    with open(os.path.join(RNS.Reticulum.blackholepath, stranger.hash.hex()), "wb") as f:
        f.write(msgpack.packb({RNS.Identity().hash: {"until": None}}))
    with open(srcfile, "wb") as f:
        f.write(msgpack.packb({expired: {"until": time.time() - 10},
                               live: {"until": None, "reason": "r"},
                               local_bad: {"until": None, "reason": "would overwrite"}}))
    T.blackholed_identities.clear()
    T.reload_blackhole()
    got = T.blackholed_identities
    if set(got) != {local_bad, extra_local, live}:
        fail(f"S12.7 after reload: {len(got)} entries, want the two local ones and the live remote one")
    if got[live]["source"] != source.hash:
        fail("S12.7 a reloaded remote entry's source is not the file's publisher")
    if got[local_bad]["source"] != T.identity.hash or got[local_bad]["reason"] != "spam":
        fail("S12.7 a remote list replaced a local entry on reload")
    print("PASS S12.7 reload: unsubscribed sources ignored, expired entries dropped, local entries win")

    # 7. enforcement on announces
    bad_id = RNS.Identity()
    dest = RNS.Destination(bad_id, RNS.Destination.IN, RNS.Destination.SINGLE, "verify", "blackhole")
    T.STAMP_DESTINATIONS = False
    pkt = dest.announce(send=False); pkt.pack()
    def fresh():
        RNS.Identity._reset_validation_caches()
        p = RNS.Packet(None, pkt.raw); p.unpack(); return p
    if not RNS.Identity.validate_announce(fresh()):
        fail("S12.7 control: announce rejected before blackholing")
    T.blackhole_identity(bad_id.hash)
    if RNS.Identity.validate_announce(fresh()):
        fail("S12.7 announce from a blackholed identity was accepted")
    if RNS.Identity.validate_announce(fresh(), signal_blackholed=True) != "blackholed":
        fail("S12.7 signal_blackholed did not return \"blackholed\"")
    print("PASS S12.7 a blackholed identity's announce is refused (S4.5 step 5)")

    print("ALL PASS", flush=True)
    os._exit(0)


if __name__ == "__main__":
    main()
