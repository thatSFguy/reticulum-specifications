"""
Verifier for SPEC.md S4.8 (interface discovery announces).

A Reticulum instance can advertise its own interfaces so that other nodes can
find and connect to them. The advertisement is an ordinary announce of the
SINGLE destination `rnstransport.discovery.interface`, whose app_data is

    flags(1) || msgpack(info map) || stamp(32)                 (FLAG_ENCRYPTED clear)
    flags(1) || network_identity.encrypt(msgpack(info) || stamp)  (FLAG_ENCRYPTED set)

This drives upstream's real producer (InterfaceAnnouncer.get_interface_announce_data)
and real consumer (InterfaceAnnounceHandler.received_announce) and checks:

  1. name_hash of `rnstransport.discovery.interface`.
  2. Producer layout: flags byte, msgpack map with small-int keys, 32-byte
     stamp at the end; key set and value types for a TCPServerInterface.
  3. Stamp: SHA-256(workblock || stamp) meets the cost, where workblock is
     stamp_workblock(SHA-256(packed), expand_rounds=20). Leading-zero bits
     are counted here with hashlib, not with upstream's validator.
  4. Consumer accepts it and reports the decoded fields.
  5. Consumer rejects: unknown path (hops_to == PATHFINDER_M), a stamp below
     required_value, a tampered map, an interface type outside the
     discoverable list, an integer latitude, and app_data that still carries
     the S4.7 announce-stamp trailer.
  6. Consumer also accepts a stamp over the NON-expanded workblock
     (transitional, RNS >= 1.6).
  7. Encrypted form: flags = 0x02, decryptable only with the network identity.

Low costs (4) keep stamp generation instant; upstream's default is 16 to emit
and 16 to accept.

Exit code 0 on PASS, non-zero on FAIL. Fails at RNS 1.5.7, which emits no
DST_COST / PR_COST keys.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile

import RNS
import RNS.Discovery as D
from RNS.vendor import umsgpack as msgpack

COST = 4
STAMP_SIZE = 32
EXPAND_ROUNDS = 20


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", flush=True)
    os._exit(1)


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-verify-discovery-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


class Owner:
    """Stands in for RNS.Transport as InterfaceAnnouncer's owner."""
    def __init__(self, network_identity=None):
        self.interfaces = []
        self.identity = RNS.Identity()
        self.network_identity = network_identity
    def has_network_identity(self): return self.network_identity is not None


class TCPServerInterface:
    """Only type(...).__name__ matters to the producer."""
    def __init__(self, **kw):
        self.discovery_stamp_value = COST
        self.discovery_location = None
        self.destination_cost = 23.5
        self.pr_cost = 15.8
        self.discovery_name = "Verifier Node"
        self.discovery_latitude = 52.5
        self.discovery_longitude = 13.25
        self.discovery_height = 40.0
        self.discovery_lxmf_address = None
        self.kiss_framing = False
        self.reachable_on = "198.51.100.7"
        self.bind_port = 4242
        self.discovery_publish_ifac = False
        self.ifac_netname = None
        self.ifac_netkey = None
        self.discovery_encrypt = False
        self.__dict__.update(kw)


def leading_zero_bits(b: bytes) -> int:
    return 256 - int.from_bytes(b, "big").bit_length()


def split(app_data):
    flags, payload = app_data[0], app_data[1:]
    return flags, payload[:-STAMP_SIZE], payload[-STAMP_SIZE:]


def consume(app_data, identity, required=COST, hops=1):
    """Run upstream's handler; return the info dict it reports, or None."""
    got = []
    h = D.InterfaceAnnounceHandler(required_value=required, callback=got.append)
    real = RNS.Transport.hops_to
    RNS.Transport.hops_to = lambda _d: hops
    try:
        h.received_announce(b"\x00" * 16, identity, app_data)
    finally:
        RNS.Transport.hops_to = real
    return got[0] if got else None


def stamp_passes(app_data):
    """Would the handler's stamp check accept this (unencrypted) app_data?
    Both workblocks are tried, as the handler does. At COST = 4 a random
    stamp passes about 1 time in 8, so negative cases must be chosen to fail
    this, or the check they make is only probabilistic."""
    _, packed, stamp = split(app_data)
    infohash = RNS.Identity.full_hash(packed)
    return any(RNS.Stamps.stamp_valid(stamp, COST, RNS.Stamps.stamp_workblock(infohash, expand_rounds=r))
               for r in (0, EXPAND_ROUNDS))


def failing_variant(make):
    """Call make(i) until it yields app_data whose stamp fails both workblocks."""
    for i in range(256):
        candidate = make(i)
        if not stamp_passes(candidate): return candidate
    fail("S4.8 could not build a negative case whose stamp fails")


def restamp(packed, no_expand=False):
    infohash = RNS.Identity.full_hash(packed)
    stamp, _ = RNS.Stamps.generate_stamp(infohash, stamp_cost=COST,
                                         expand_rounds=0 if no_expand else EXPAND_ROUNDS,
                                         no_expand=no_expand)
    return stamp


def main():
    init_minimal_rns()
    print(f"verify_interface_discovery.py against RNS {RNS.__version__}")
    if not hasattr(RNS, "Stamps"):
        fail("S4.8 this RNS has no RNS.Stamps (discovery stamps came from LXMF before RNS 1.6)")

    # 1. name_hash
    nh = hashlib.sha256(b"rnstransport.discovery.interface").digest()[:10].hex()
    d = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE,
                        "rnstransport", "discovery", "interface")
    if d.name_hash.hex() != nh or nh != "55aa39e85c3e045e9cb1":
        fail(f"S4.8 name_hash {d.name_hash.hex()} / {nh}, want 55aa39e85c3e045e9cb1")
    print("PASS S4.8 name_hash(rnstransport.discovery.interface) = 55aa39e85c3e045e9cb1")

    # 2. producer layout
    owner = Owner()
    announcer = D.InterfaceAnnouncer(owner)
    if announcer.discovery_destination.name_hash.hex() != nh:
        fail("S4.8 announcer does not use rnstransport.discovery.interface")
    if announcer.discovery_destination.identity is not owner.identity:
        fail("S4.8 without a network identity the announcer should use the owner's identity")

    iface = TCPServerInterface()
    app_data = announcer.get_interface_announce_data(iface)
    if not app_data:
        fail("S4.8 producer returned nothing for a TCPServerInterface")
    flags, packed, stamp = split(app_data)
    if flags != 0x00:
        fail(f"S4.8 flags = {flags:#04x}, want 0x00 for an unencrypted announce")
    info = msgpack.unpackb(packed)
    if msgpack.packb(info) != packed:
        fail("S4.8 the bytes before the stamp are not exactly one msgpack map")

    want = {
        0x00: ("TCPServerInterface", str), 0x01: (False, bool),
        0xFE: (RNS.Transport.identity.hash, bytes), 0xFD: ("RNS", str),
        0xFC: (RNS.__version__, str), 0xFB: (23.5, float), 0xFA: (RNS.Stamps.quantize_cost(15.8), float),
        0xFF: ("Verifier Node", str), 0x03: (52.5, float), 0x04: (13.25, float),
        0x05: (40.0, float), 0x02: ("198.51.100.7", str), 0x06: (4242, int),
    }
    if set(info) != set(want):
        fail(f"S4.8 key set {sorted(info)} != {sorted(want)}")
    for k, (v, t) in want.items():
        if type(info[k]) is not t or info[k] != v:
            fail(f"S4.8 key {k:#04x} = {info[k]!r} ({type(info[k]).__name__}), want {v!r} ({t.__name__})")
    if len(info[0xFE]) != 16:
        fail("S4.8 TRANSPORT_ID is not 16 bytes")
    print("PASS S4.8 producer: 0x00 || msgpack map (int keys, typed values) || 32-byte stamp")

    # 3. stamp, counted independently
    infohash = hashlib.sha256(packed).digest()
    workblock = RNS.Stamps.stamp_workblock(infohash, expand_rounds=EXPAND_ROUNDS)
    lz = leading_zero_bits(hashlib.sha256(workblock + stamp).digest())
    if lz < COST:
        fail(f"S4.8 stamp has {lz} leading zero bits over the 20-round workblock, need {COST}")
    print(f"PASS S4.8 stamp: SHA-256(workblock(SHA-256(packed), 20 rounds) || stamp) has {lz} >= {COST} zero bits")

    # 4. consumer accepts
    announced = RNS.Identity()
    got = consume(app_data, announced)
    if not got:
        fail("S4.8 upstream handler rejected upstream's own discovery announce")
    checks = {"type": "TCPServerInterface", "impl_name": "RNS", "transport": False,
              "transport_id": RNS.Transport.identity.hash.hex(), "network_id": announced.hash.hex(),
              "reachable_on": "198.51.100.7", "port": 4242, "dst_cost": 23.5, "hops": 1}
    for k, v in checks.items():
        if got.get(k) != v:
            fail(f"S4.8 handler reported {k} = {got.get(k)!r}, want {v!r}")
    dh = hashlib.sha256((got["transport_id"] + got["name"]).encode()).digest()
    if got.get("discovery_hash") != dh:
        fail("S4.8 discovery_hash != SHA-256(hex(transport_id) || name)")
    print("PASS S4.8 handler accepts it; network_id = announcing identity, discovery_hash = SHA-256(hex tid || name)")

    # 5. consumer rejections
    if consume(app_data, announced, hops=RNS.Transport.PATHFINDER_M):
        fail("S4.8 handler accepted a discovery announce with no known path (hops_to = PATHFINDER_M)")
    if consume(app_data, announced, required=COST + 40):
        fail("S4.8 handler accepted a stamp below required_value")
    def tamper(i):
        t = bytearray(app_data); t[5] ^= 0x01; t[6] ^= i; return bytes(t)
    if consume(failing_variant(tamper), announced):
        fail("S4.8 handler accepted a tampered info map")

    bad_type = dict(info); bad_type[0x00] = "UDPInterface"
    p = msgpack.packb(bad_type)
    if consume(b"\x00" + p + restamp(p), announced):
        fail("S4.8 handler accepted interface type UDPInterface")

    int_lat = dict(info); int_lat[0x03] = 52
    p = msgpack.packb(int_lat)
    if consume(b"\x00" + p + restamp(p), announced):
        fail("S4.8 handler accepted an integer latitude; it requires float or nil")

    with_trailer = failing_variant(lambda i: app_data + bytes([0xC1, 0x00]) + os.urandom(14) + b"\x80\x0c")
    if consume(with_trailer, announced):
        fail("S4.8 handler accepted app_data with an S4.7 trailer still attached")
    print("PASS S4.8 handler rejects: no path, low stamp, tampered map, bad type, int latitude, attached S4.7 trailer")

    # 6. non-expanded stamp (transitional)
    p = packed
    if not consume(b"\x00" + p + restamp(p, no_expand=True), announced):
        fail("S4.8 handler rejected a stamp over the non-expanded workblock (accepted since RNS 1.6)")
    print("PASS S4.8 handler also accepts a stamp over the non-expanded workblock (transitional)")

    # 7. encrypted form
    netid = RNS.Identity()
    enc_announcer = D.InterfaceAnnouncer(Owner(network_identity=netid))
    if enc_announcer.discovery_destination.identity is not netid:
        fail("S4.8 with a network identity the announcer should announce under it")
    enc = enc_announcer.get_interface_announce_data(TCPServerInterface(discovery_encrypt=True))
    if not enc or enc[0] != 0x02:
        fail(f"S4.8 encrypted announce flags = {enc[0] if enc else None!r}, want 0x02")
    plain = netid.decrypt(enc[1:])
    if not plain or msgpack.unpackb(plain[:-STAMP_SIZE])[0x00] != "TCPServerInterface":
        fail("S4.8 encrypted payload is not network_identity.encrypt(packed || stamp)")
    saved = RNS.Transport.network_identity
    try:
        RNS.Transport.network_identity = None
        if consume(enc, netid):
            fail("S4.8 handler accepted an encrypted announce without the network identity")
        RNS.Transport.network_identity = netid
        if not consume(enc, netid):
            fail("S4.8 handler rejected an encrypted announce it holds the network identity for")
    finally:
        RNS.Transport.network_identity = saved
    print("PASS S4.8 encrypted form: flags 0x02, readable only with the network identity")

    print("ALL PASS", flush=True)
    os._exit(0)


if __name__ == "__main__":
    main()
