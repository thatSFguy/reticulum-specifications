# Reticulum Wire Specifications

A byte-level reference for implementing Reticulum-compatible clients. This document focuses on what implementations need to interop with the canonical Python implementation ([`markqvist/Reticulum`](https://github.com/markqvist/Reticulum) and [`markqvist/LXMF`](https://github.com/markqvist/LXMF)) plus the existing client ecosystem (Sideband, Nomadnet, MeshChat, the various firmware projects).

**Last verified against:** `RNS 1.2.0` / `LXMF 0.9.6` / `RNode_Firmware` (master at the spec's last revision date). Each section's source citations were re-checked against these versions; runtime verifiers in [`tools/`](tools/) lock the wire-format claims in against actually-running upstream code. When you upgrade past these, re-run every `tools/verify_*.py` and look for `FAIL`s.

Source citations refer to the standard `pip install rns lxmf` install layout (`RNS/`, `LXMF/`).

---

## 1. Identity and destination hashes

### 1.1 Identity composition

A Reticulum identity is two keypairs concatenated:

```
public_key  = X25519_pub(32) || Ed25519_pub(32)        // 64 bytes
private_key = X25519_priv(32) || Ed25519_priv(32)      // 64 bytes
```

X25519 for ECDH (encryption / shared-secret derivation), Ed25519 for signatures.

```
identity_hash = SHA256(public_key)[:16]                // 16 bytes truncated
```

The 16-byte truncation is consistent across all hashes Reticulum stores on the wire (destinations, link IDs, packet hashes, etc.). The full SHA-256 is used internally for signing inputs but never appears in headers.

### 1.2 Destination hash

The 16-byte destination hash that appears in packet headers and announces is:

```
name_hash = SHA256(full_app_name_string)[:10]
dest_hash = SHA256(name_hash || identity_hash)[:16]
```

Where `full_app_name_string` is e.g. `"lxmf.delivery"`, `"nomadnetwork.node"`, `"rnstransport.path.request"`. **The hex-encoded identity hash is NOT part of the input** — only the plain ASCII app-name string. This is the `identity=None` branch of upstream's `expand_name()` function (`RNS/Destination.py`). The identity hex appears only in the human-readable `Destination.name` debug string.

Common pre-computed `name_hash` values:

| 10-byte hex | App name |
|---|---|
| `6ec60bc318e2c0f0d908` | `lxmf.delivery` |
| `e03a09b77ac21b22258e` | `lxmf.propagation` |
| `213e6311bcec54ab4fde` | `nomadnetwork.node` |
| `0ad8bff9ff75737c058e` | `nomadnetwork.gossip` |
| `9efb9c771eeb5ae90ea6` | `rnstransport.broadcasts` |
| `4848a053c16415bed6c8` | `rnstransport.remote.management` |
| `7926bbe7dd7f9aba88b0` | `rnstransport.path.request` (resulting `dest_hash` with `identity=None`: `6b9f66014d9853faab220fba47d02761`) |

### 1.3 Private key on-disk format

`RNS.Identity.to_file(path)` writes the raw 64-byte private-key blob with **no header, no version byte, no checksum, no encryption**. The byte order is the **same** as the public_key concatenation in §1.1 — verified by `tools/verify_destination_hash.py`'s existing `Identity.from_bytes` round-trip:

```
prv_bytes_blob  =  X25519_priv(32) || Ed25519_priv(32)         // 64 bytes total
```

`Identity.get_private_key()` at `RNS/Identity.py:694-698` returns this exact concatenation:

```python
def get_private_key(self):
    return self.prv_bytes + self.sig_prv_bytes
    #      ^^^^^^^^^^^^^   X25519 priv (set at line 679 from X25519PrivateKey.generate())
    #                       ^^^^^^^^^^^^^^^   Ed25519 priv (set at line 682)
```

`Identity.load_private_key(prv_bytes)` at line 706-717 slices it back the same way:

```python
self.prv_bytes     = prv_bytes[:32]   # X25519
self.sig_prv_bytes = prv_bytes[32:]   # Ed25519
```

`to_file` is a thin wrapper that writes `get_private_key()` to the path; `from_file` reads back with no extra parsing.

#### File-system facts

- **Size:** exactly 64 bytes. No magic, no length prefix.
- **Encryption:** none. Anyone with read access can fully impersonate the identity.
- **Permissions:** upstream doesn't `chmod` the file; clients are expected to put it in a directory protected by OS permissions (`~/.reticulum/storage` on Linux/macOS, `%APPDATA%/Reticulum/storage` on Windows by default).
- **Filename:** caller-controlled. RNS itself uses `transport_identity` for the transport node and lets app-level callers choose for delivery destinations (LXMF puts these in `LXMF.LXMRouter.storagepath`).

#### Constructing from raw bytes — `from_bytes` HAZARD

`Identity.from_bytes(prv_bytes)` at line 611-623 takes the same 64-byte concat and reconstitutes an `Identity`. The upstream docstring explicitly warns:

> **HAZARD!** Never use this to generate a new key by feeding random data in prv_bytes.

The reason: `X25519PrivateKey.from_private_bytes` and `Ed25519PrivateKey.from_private_bytes` both accept arbitrary 32-byte values without scalar clamping or rejection — a clean-room implementation that feeds raw random data into `from_bytes` skips the keypair-generation invariants enforced by the upstream `cryptography` library's `.generate()` methods (e.g. X25519 scalar clamping per RFC 7748 §5). Always generate fresh keys via the `cryptography` (or equivalent) library's keypair generator, then concatenate; never invent your own bytes.

#### Cross-implementation portability

The format is portable across implementations because there's nothing in it but the raw bytes. A 64-byte file written by Python RNS is byte-identical to one written by any clean-room implementation that follows this section, and both produce the same `identity_hash` and `lxmf.delivery` `destination_hash` when fed back through §1.1 and §1.2 — test vectors at [`test-vectors/identities.json`](test-vectors/identities.json) demonstrate the round-trip against RNS 1.2.0.

> ⚠️ **Spec correction:** Earlier revisions of this section described the on-disk order as Ed25519 first, X25519 second ("opposite of the public_key concatenation"). That was wrong — verified by re-running `Identity.to_file` and reading back the bytes against the test vector at `test-vectors/identities.json`, the actual order is X25519 first, Ed25519 second, identical to the public_key order. Implementations following the prior spec wording would have corrupted identity files when interoperating with upstream Python RNS.

### 1.4 GROUP destinations (symmetric-key alternative to SINGLE)

Most Reticulum traffic — including all LXMF — uses `SINGLE` destinations with the X25519 ECDH + Ed25519 signing scheme described above. There is also a **`GROUP`** destination type (`RNS.Destination.GROUP = 0x01`, in the `dest_type` field of the packet header per §2.1) that uses a **pre-shared symmetric key** instead, intended for closed channels where every participant should be able to decrypt every message without per-recipient ECDH.

#### 1.4.1 Key generation

`Destination.create_keys()` for `GROUP` calls `Token.generate_key()` (`RNS/Cryptography/Token.py:53-56`):

```python
@staticmethod
def generate_key(mode=AES_256_CBC):
    if   mode == AES_128_CBC: return os.urandom(32)    # 16B signing + 16B encryption
    elif mode == AES_256_CBC: return os.urandom(64)    # 32B signing + 32B encryption
```

The default is AES-256-CBC, so the symmetric key is **64 random bytes**, split into:

```
signing_key     = key[ 0..32]      // HMAC-SHA256 input
encryption_key  = key[32..64]      // AES-256-CBC key
```

A clean-room implementation that needs to interop with a GROUP destination must use AES-256-CBC by default and derive the same split. AES-128-CBC mode (32-byte key, 16/16 split) is supported by the `Token` class but no upstream caller currently selects it for GROUPs.

#### 1.4.2 Wire format

GROUP destinations encrypt and decrypt via `Token.encrypt` / `Token.decrypt` — **the same Token format used by Link-derived encryption** (§3.1, the no-ephemeral-pub form):

```
wire_body  =  iv(16) || aes_ciphertext || hmac_sha256(32)
```

There is **no ephemeral_pub prefix** because there is no ECDH — every participant already shares the same `(signing_key, encryption_key)` pair. The format is identical to a Link DATA payload after the link is established (§6.4). Reticulum's `Token` class is shared across both code paths; see `RNS/Destination.py:601-609` and `:645-653` for GROUP encrypt/decrypt, and `RNS/Cryptography/Token.py:87-114` for the underlying primitive.

#### 1.4.3 Destination hash for GROUP

GROUP destinations use the same `dest_hash` recipe as SINGLE (§1.2) — `SHA256(name_hash || identity_hash)[:16]` — with two wrinkles:

- The constructor accepts an `identity` argument optionally. If provided, `identity_hash = SHA256(identity.public_key)[:16]` per §1.1; the resulting `dest_hash` is keyed to that identity's public key as well as the group name. Different identities → different group destinations even with the same name.
- If `identity` is not provided (`None`), `dest_hash = SHA256(name_hash)[:16]` (same recipe as PLAIN destinations — see the `path-request` example in §1.2).

The identity (if any) does NOT participate in encryption — it's purely a way to disambiguate group destinations sharing a name across owners. The actual encryption uses the symmetric key from §1.4.1.

#### 1.4.4 On-disk format

`Destination.get_private_key()` for GROUP returns `self.prv_bytes` — the 64 (or 32) raw key bytes. `Destination.load_private_key(key)` accepts the same. There is no canonical file path or filename — the application chooses where to store the symmetric key, and is responsible for distributing it to every group member out of band.

Like the SINGLE identity file (§1.3), the GROUP key file has **no header, no encryption-at-rest, no checksum**. Anyone with read access can fully impersonate the group.

#### 1.4.5 Why most clients don't bother

GROUP destinations are rarely seen in the wild because:

- LXMF doesn't use them (every chat is one-to-one between SINGLE destinations, even in multi-party rooms — those are application-layer constructs).
- NomadNet pages use SINGLE destinations.
- The forward-secrecy properties of SINGLE (per-message ephemeral X25519 + ratchet rotation per §7.3) are absent for GROUP — once the symmetric key is leaked, every past and future message decryptable by that key is compromised.
- Group key distribution is an unsolved problem at the protocol level — Reticulum doesn't help with this.

A clean-room client that targets LXMF interop only can ignore GROUP destinations entirely. Implementations of `Destination.encrypt`/`decrypt` should still recognize the `GROUP (0x01)` type byte in the packet header to gracefully reject (rather than crash on) inbound packets to a GROUP whose key the receiver doesn't hold.

---

## 2. Packet header

### 2.1 Flag byte layout

Every Reticulum packet starts with a 1-byte flag field:

```
bit 7-6 : header_type      (0 = HEADER_1, 1 = HEADER_2)
bit 5   : context_flag     (1 = announce includes a ratchet pubkey)
bit 4   : transport_type   (0 = BROADCAST, 1 = TRANSPORT)
bit 3-2 : destination_type (0=SINGLE, 1=GROUP, 2=PLAIN, 3=LINK)
bit 1-0 : packet_type      (0=DATA, 1=ANNOUNCE, 2=LINKREQUEST, 3=PROOF)
```

### 2.2 Two header forms

```
HEADER_1: flags(1) hops(1) dest_hash(16) context(1) data(...)        // min 19 bytes
HEADER_2: flags(1) hops(1) transport_id(16) dest_hash(16) context(1) data(...)   // min 35 bytes
```

`HEADER_2` carries a `transport_id` (the next-hop transport node's identity hash) before the final destination hash. A relay converts a HEADER_1 packet to HEADER_2 by setting bit 6 of flags, inserting its own identity at offset 2, and re-transmitting.

### 2.3 Originator HEADER_1 → HEADER_2 conversion

This is non-obvious and matters: when an **originator** (not a relay) sends a packet to a destination known to be more than 1 hop away, the originator MUST also do the HEADER_2 conversion. From `RNS/Transport.py::outbound` (lines 1074-1083 in RNS 1.2.0; verified by `tools/verify_packet_header.py`):

```python
if path_entry[IDX_PT_HOPS] > 1:
    if packet.header_type == RNS.Packet.HEADER_1:
        new_flags = (RNS.Packet.HEADER_2) << 6 | (Transport.TRANSPORT) << 4 | (packet.flags & 0b00001111)
        new_raw  = struct.pack("!B", new_flags)
        new_raw += packet.raw[1:2]                       # hops byte unchanged
        new_raw += path_entry[IDX_PT_NEXT_HOP]           # 16B transport_id at offset 2
        new_raw += packet.raw[2:]                        # original dest_hash + context + payload
```

For destinations 0 or 1 hops away, the originator may stay HEADER_1 — the receiving rnsd auto-fills the transport_id when the destination matches a local client (`for_local_client` branch at `RNS/Transport.py:1451` in RNS 1.2.0). Implementations that always emit HEADER_1 will silently fail to deliver to multi-hop destinations even with a known path.

### 2.4 Hop count

Byte 1 is `hops`, an 8-bit counter that each transit relay increments by 1. `0` for a packet still on the originator. `255` would in theory wrap, but no Reticulum mesh in practice has paths anywhere near that long.

### 2.5 Context byte

Single byte after the destination hash (offset 18 for HEADER_1, offset 34 for HEADER_2). Common values:

Full context inventory from `RNS/Packet.py:72-92` (RNS 1.2.0):

| Hex | Name | Used for |
|---|---|---|
| `0x00` | NONE | Generic / opportunistic DATA packet |
| `0x01` | RESOURCE | One part (chunk) of a Resource transfer (§10) |
| `0x02` | RESOURCE_ADV | Resource advertisement |
| `0x03` | RESOURCE_REQ | Resource part request (from receiver to sender) |
| `0x04` | RESOURCE_HMU | Resource hashmap update (next-segment hashmap) |
| `0x05` | RESOURCE_PRF | Resource proof (a PROOF-type packet using this context) |
| `0x06` | RESOURCE_ICL | Resource cancel from the initiator |
| `0x07` | RESOURCE_RCL | Resource cancel from the receiver / reject of an advertisement |
| `0x08` | CACHE_REQUEST | Cache lookup over a Link |
| `0x09` | REQUEST | Link REQUEST (NomadNet page fetch, propagation `/get`) |
| `0x0A` | RESPONSE | Link RESPONSE matching a REQUEST |
| `0x0B` | PATH_RESPONSE | An ANNOUNCE emitted in response to a `path?` request — distinguishes it from a periodic re-announce. Receivers handle the two paths differently (see §7.2 and §4.5) |
| `0x0C` | COMMAND | Channel-style remote-execution command |
| `0x0D` | COMMAND_STATUS | Status reply for a COMMAND |
| `0x0E` | CHANNEL | Link channel multiplexed payload |
| `0xFA` | KEEPALIVE | Link keepalive (sent periodically while a Link is idle) |
| `0xFB` | LINKIDENTIFY | Backchannel-identify proof on an established Link (§5 backchannel) |
| `0xFC` | LINKCLOSE | Link teardown notification |
| `0xFD` | LINKPROOF | Defined but **not actually emitted** by upstream RNS 1.2.0 in this revision. Both `Identity.prove` and `Link.prove_packet` build their proof packets with `context = NONE (0x00)` — the proof-ness is conveyed by `packet_type = PROOF (3)`, not by this context byte. Reserved for a future revision; see §6.5 |
| `0xFE` | LRRTT | Link RTT measurement reply |
| `0xFF` | LRPROOF | Link request proof (§6.2) |

### 2.6 Source

`RNS/Packet.py` for the constants and `_pack` / `_unpack` methods. `RNS/Transport.py` for the routing-side HEADER_1↔HEADER_2 transitions.

---

## 3. Token cryptography (modified Fernet)

Reticulum's "Token" construction is a modified Fernet used for opportunistic destination encryption (single packet), as well as for derived-key channels on established Links.

### 3.1 Wire format

```
ephemeral_pub(32) || iv(16) || aes_ciphertext(...) || hmac_sha256(32)
```

For Link-derived-key encryption (after the Link handshake has produced a session key), the `ephemeral_pub` prefix is omitted and the wire form is just `iv || ciphertext || hmac`.

### 3.2 Encrypt steps (opportunistic)

1. Generate ephemeral X25519 keypair `(eph_priv, eph_pub)`.
2. ECDH: `shared = X25519(eph_priv, recipient_X25519_pub)`. The recipient's X25519 pub is either their long-term `encPub` (first 32 bytes of public_key) or their currently-announced `ratchet_pub` if present.
3. HKDF-SHA256: `derived = HKDF(shared, salt = recipient_identity_hash, info = "", L = 64)`. **The salt is the recipient's 16-byte identity hash** — not their destination hash, not the ratchet hash.
4. Split: `signing_key = derived[0..32]`, `encryption_key = derived[32..64]`.
5. Random 16-byte IV.
6. AES-256-CBC encrypt plaintext with `encryption_key` and `iv`. **Do NOT manually pad** — the platform AES-CBC API (`AES/CBC/PKCS5Padding` on JCA, Web Crypto's default) auto-pads PKCS#7. Manual padding on top causes 16 garbage bytes of double-padding.
7. `hmac = HMAC-SHA256(signing_key, iv || ciphertext)`.
8. Concatenate as the wire format above.

### 3.3 Decrypt steps

Reverse of encrypt. Critically:

- **Verify HMAC BEFORE attempting decryption** (encrypt-then-MAC; prevents AES padding-oracle attacks).
- A receiver that has multiple candidate X25519 private keys (typically the current ratchet privkey + the long-term identity privkey) should try each in order until one produces a matching HMAC. Senders that haven't seen the receiver's latest ratchet announce will encrypt to the long-term key as a fallback.

### 3.4 Source

`RNS/Cryptography/Token.py` (and the equivalents in vendor crypto modules). The webclient's `reference/js-reference/crypto.js` is a faithful port.

---

## 4. Announce wire format

### 4.1 Packet body

The Reticulum packet header (HEADER_1, packet_type=ANNOUNCE, dest_type=SINGLE, transport_type=BROADCAST) is followed by an announce body:

```
public_key(64) || name_hash(10) || random_hash(10) || [ratchet_pub(32) if context_flag] || signature(64) || app_data(...)
```

The 64-byte `public_key` is the X25519 || Ed25519 concat described in section 1.1.

`random_hash` is **NOT** 10 random bytes — only the first 5 bytes are random; the trailing 5 bytes carry the emission timestamp as a big-endian unsigned 40-bit Unix-seconds integer (`RNS/Destination.py:282`):

```python
random_hash = RNS.Identity.get_random_hash()[0:5] + int(time.time()).to_bytes(5, "big")
```

Transit relays read the timestamp portion via `Transport.timebase_from_random_blob(random_blob) = int.from_bytes(random_blob[5:10], "big")` (`RNS/Transport.py:3100-3101`) to make ordering decisions when an inbound announce carries a higher hop count than the cached path: only newer-emitted announces can refresh the path table (see §4.5). 5 bytes of seconds covers ~34,000 years, so wraparound is not a near-term concern. Implementations MUST emit this exact format, including a clock value that's monotonically non-decreasing across announces from the same destination — clockless sender devices (per §9.6) may end up locked out of long-range path table updates.

> ⚠️ **UNVERIFIED — Known deviation:** `attermann/microReticulum/src/Destination.cpp:270-272` (and therefore every project that uses microReticulum unmodified, including [`thatSFguy/reticulum-lora-repeater`](https://github.com/thatSFguy/reticulum-lora-repeater) and the Faketec sibling project) currently emits 10 fully-random bytes for `random_hash` — the timestamp half is a TODO that never landed:
>
> ```cpp
> //p random_hash = Identity::get_random_hash()[0:5] << int(time.time()).to_bytes(5, "big")
> // CBA TODO add in time to random hash
> Bytes random_hash = Cryptography::random(Type::Identity::RANDOM_HASH_LENGTH/8);
> ```
>
> Python RNS receivers interpret `random_hash[5:10]` as a big-endian uint40 unix_seconds. A uniformly-random uint40 has median value ~5.5×10¹¹ ≈ year 19403 AD, so a microReticulum announce will (with overwhelming probability) appear "far-future" to a Python receiver. Effect: once one such announce populates `path_table[dest][IDX_PT_RANDBLOBS]`, the equal-or-greater-hop branch at `RNS/Transport.py:1721-1745` will reject any real-timestamped announce as "stale" until the path TTL expires. First-contact path-table population is unaffected; the bug only surfaces on path replacement under §4.5 step 6.3. The microReticulum receive side does NOT consult the timestamp half so microReticulum-to-microReticulum traffic is unaffected. The repeater repo's `pre_build.py` patches several microReticulum protocol bugs but not this one (as of [`thatSFguy/reticulum-lora-repeater@95823ad`-vintage upstream](https://github.com/thatSFguy/reticulum-lora-repeater)). Verifying by capture-and-decode against an actual mixed-vendor mesh is the work that would let this callout be removed.

The optional 32-byte `ratchet_pub` (an X25519 public key) is present iff the packet header's `context_flag` bit is 1. Indexing through this layout accordingly is mandatory; see `RNS/Identity.py::validate_announce` for the canonical parser.

### 4.2 Signed data

```
signed_data = dest_hash(16) || public_key(64) || name_hash(10) || random_hash(10) || [ratchet_pub(32)] || app_data
signature   = Ed25519_sign(signed_data, identity.Ed25519_priv)
```

Note that `dest_hash` is INCLUDED in the signed data even though it's not in the wire-format announce body (the receiver gets it from the packet header). The signing key is the Ed25519 half (last 32 bytes) of the identity's `private_key`.

### 4.3 `app_data` format for LXMF delivery destinations

Upstream `LXMF/LXMRouter.py::get_announce_app_data` produces a 2-element msgpack array (verified against LXMF 0.9.6 by `tools/verify_announce_app_data.py`):

```python
# LXMF/LXMRouter.py:986-1002 in LXMF 0.9.6
peer_data = [display_name, stamp_cost]   # stamp_cost = None unless 1 ≤ N ≤ 254
return msgpack.packb(peer_data)
```

Wire bytes for `display_name = "Reticulum5"`, `stamp_cost = None`:

```
92         # fixarray, 2 elements
c4 0a      # bin8, length 10
52 65 74 69 63 75 6c 75 6d 35    # "Reticulum5"
c0         # nil (stamp_cost)
```

Encoding the display name as msgpack `bin` (`0xc4 NN`) is required for upstream interop — see section 9.3 below. The stamp_cost field can be `int 0` (`0x00`) or `nil` (`0xc0`); upstream's `stamp_cost_from_app_data` doesn't strict-type-check.

**A third optional `[capability_flags]` element** (e.g. `[SF_COMPRESSION]`, the only flag currently defined at `LXMF/LXMF.py:108`) is **read by the parser** (`compression_support_from_app_data` at `LXMF/LXMF.py:154-167`) but is **not emitted by the LXMF 0.9.6 producer** — `LXMRouter.py:999` computes `supported_functionality = [SF_COMPRESSION]` but never appends it to `peer_data`. Implementations should accept the 3-element form on inbound (a future LXMF version may re-enable it; older deployments may emit it) but should not rely on receiving it.

The parser also tolerates a 1-element msgpack array (just the name) and a raw UTF-8 string ("original announce format" branch at `LXMF/LXMF.py:138-139`) — see `LXMF/LXMF.py::display_name_from_app_data` for all four accepted shapes.

### 4.4 Announce filtering by `name_hash`

When ingesting an announce, clients should distinguish by `name_hash`:

- `lxmf.delivery` (`6ec60bc318e2c0f0d908`) — messagable peers, surface in contacts UI
- `lxmf.propagation` (`e03a09b77ac21b22258e`) — propagation node, surface separately
- `nomadnetwork.node` (`213e6311bcec54ab4fde`) — page-serving NomadNet host
- `rnstransport.broadcasts` / `rnstransport.remote.management` — transport-internal, ignore for user UI
- Any other `name_hash` — non-LXMF custom destination (telemetry beacons, application-specific)

Treating every announce as a contact (the naive default) populates the UI with hundreds of irrelevant rows.

### 4.5 Announce validation rules (receive side)

These are the MUST rules a receiver applies to every inbound announce before considering the announced destination "known". The canonical implementation is `RNS/Identity.py::validate_announce` (line 496-598 in RNS 1.2.0); the dispatch site that calls it is `RNS/Transport.py::inbound` line 1623-1650.

#### 1. Body parse — branch on `context_flag`

The `context_flag` bit (bit 5 of the packet's 1-byte flag field, §2.1) selects between two body layouts. Slice offsets, with `keysize = 64`, `name_hash_len = 10`, `random_hash_len = 10`, `ratchet_size = 32`, `sig_len = 64`:

```
context_flag == 1 (ratchet present):
   public_key   = data[ 0                                     :  64]
   name_hash    = data[ 64                                    :  74]
   random_hash  = data[ 74                                    :  84]
   ratchet_pub  = data[ 84                                    : 116]
   signature    = data[116                                    : 180]
   app_data     = data[180                                    :    ]   # may be empty

context_flag == 0 (no ratchet):
   public_key   = data[ 0                                     :  64]
   name_hash    = data[ 64                                    :  74]
   random_hash  = data[ 74                                    :  84]
   signature    = data[ 84                                    : 148]
   app_data     = data[148                                    :    ]   # may be empty
```

A client that uses a fixed offset for `signature` regardless of the flag (a real bug from the SF webclient's first cut) silently rejects every ratchet-bearing announce as having a bad signature.

#### 2. Signature verification

Reconstruct the signed_data exactly per §4.2:

```
signed_data = destination_hash || public_key || name_hash || random_hash || ratchet || app_data
```

Where `ratchet` is `b""` (empty, **not** absent) when `context_flag == 0`, and `app_data` is `b""` when not present in the packet. `destination_hash` comes from the **outer packet header**, NOT from the announce body — re-using the body bytes as the dest_hash would let a sender forge announces for arbitrary destinations.

Verify the 64-byte signature with the announced public_key's Ed25519 half (last 32 bytes). Reject on failure.

#### 3. `destination_hash` recomputation

Recompute the dest_hash from the announced inputs:

```
identity_hash    = SHA256(public_key)[:16]
expected_hash    = SHA256(name_hash || identity_hash)[:16]
```

Reject the announce iff `expected_hash != packet.destination_hash` (the value from the outer header). This catches both random hash collisions and active spoofing attempts that pair a valid signature with an unrelated dest_hash. (`RNS/Identity.py:548-551`).

#### 4. Public-key collision rejection

If the receiver already has a different public_key cached for this `destination_hash` (from a prior announce), the new announce MUST be rejected with a critical-severity log even if the signature is otherwise valid. Per the upstream comment: "In reality, this should never occur, but in the odd case that someone manages a hash collision, we reject the announce" (`RNS/Identity.py:554-560`).

This rule means: **first-announcer-wins for any given destination_hash** within a receiver's lifetime. A peer who loses their identity material and regenerates with the same display name + app_name will produce a different identity_hash → different destination_hash → no collision. A peer who tries to *replace* their announced public key under the same destination_hash, however, gets rejected — the real defense against this class of attack.

#### 5. Blackhole list check

Before everything else, check `RNS.Transport.blackholed_identities`. An identity_hash on the blackhole list is dropped silently regardless of signature validity (`RNS/Identity.py:538-541`). This is operator-controlled state, not a wire feature.

#### 6. Caching the announce contents

On a fully validated announce, the receiver MUST update its caches in this order:

1. **`known_destinations[destination_hash]`** ← `[recv_time, packet_hash, public_key, app_data, last_used]` — populates the table that `RNS.Identity.recall(dest_hash)` reads when constructing outbound destinations (`RNS/Identity.py::remember`, line 100-112). Without this, every subsequent outbound message to this peer fails because no public key is available for Token encryption.
2. **`known_ratchets[destination_hash]`** ← `ratchet_pub` (only if `context_flag == 1` and `ratchet_pub != b""`) — `Identity._remember_ratchet`, line 395-428. The ratchet is also persisted to disk under `{storagepath}/ratchets/{hexhash}` for use across restarts.
3. **`path_table`** entry update or insertion (see §4.6 — TBD when the relay rebroadcast spec lands), gated by:
   - `random_blob` (= `random_hash`) not in the cached `random_blobs` history for this destination — cheap replay defence (`RNS/Transport.py:1707, 1732, 1745`).
   - Hop count comparison against any existing entry: equal-or-fewer hops always win; more hops win only if the cached path has expired or the new announce's emission timestamp (from `random_hash[5:10]`) is more recent than every cached blob's timestamp (`RNS/Transport.py:1700-1745`).

#### 7. `PATH_RESPONSE` distinction

An announce whose outer packet `context == PATH_RESPONSE (0x0B)` is the responder's reply to a recent `path?` request, not a periodic re-announce. Validation is identical (rules 1-6 above), but listener dispatch differs:

- The default behavior of `Transport.announce_handlers` registered via `RNS.Transport.register_announce_handler` is to **skip** path-response announces unless the handler sets `receive_path_responses = True` on itself (`RNS/Transport.py:1989-1991`).
- The path table population path is the same either way — both regular and path-response announces refresh the path entry — so a leaf client that ignores PATH_RESPONSE entirely at the application layer still benefits from the path-table side effect.

#### 8. Implementation-private behavior (SHOULD)

These are not wire-spec MUST rules but most working clients implement them; without them the implementation will misbehave in busy meshes:

- **Per-interface ingress rate limiting.** When the inbound announce rate on an interface exceeds `IC_BURST_FREQ_NEW = 6 Hz` (interfaces less than 2 hours old) or `IC_BURST_FREQ = 35 Hz` (older), and the announced destination is **not** in `path_table` and **not** in `path_requests`, the announce is held in the interface's `held_announces` dict for later release rather than processed immediately. Released later in lowest-hop-count-first order. (`RNS/Interfaces/Interface.py:60-200`.) Without this, a flood of unknown-destination announces can drown out everything else.
- **`random_blob` history cap.** The cached `random_blobs` list per destination is bounded by `Transport.MAX_RANDOM_BLOBS` to keep the path table from growing without bound under a long-lived destination's announce stream (`RNS/Transport.py:1820`).
- **Self-announce filter.** §9.5 — drop announces where `destination_hash` matches one of the receiver's own destinations to avoid populating its own contact list with itself.

#### 9. Source map for §4.5

| File | What it pins down |
|---|---|
| `RNS/Identity.py:496-598` | `validate_announce` — body parse, signed_data, sig verify, dest_hash recompute, collision check |
| `RNS/Identity.py:100-112` | `Identity.remember` — `known_destinations` update |
| `RNS/Identity.py:395-428` | `_remember_ratchet` — ratchet persistence |
| `RNS/Transport.py:1623-2024` | inbound dispatch for `packet_type == ANNOUNCE`: quick sig check, ingress limiting, path table population, handler dispatch |
| `RNS/Transport.py:3100-3117` | `timebase_from_random_blob`, `announce_emitted` |
| `RNS/Interfaces/Interface.py:60-200` | ingress-limit constants, `should_ingress_limit`, `hold_announce`, `process_held_announces` |
| `RNS/Packet.py:83` | `PATH_RESPONSE = 0x0B` context constant |

---

## 5. LXMF wire format

LXMF has two delivery methods with **different** plaintext layouts.

### 5.1 Opportunistic delivery (single Reticulum DATA packet)

Plaintext (after Token decryption):

```
source_hash(16) || signature(64) || msgpack_payload(...)
```

The recipient's destination_hash is **stripped** (the outer Reticulum packet's `dest_hash` already conveys it; including it would waste bytes).

### 5.2 Direct delivery (over an established Reticulum Link)

```
destination_hash(16) || source_hash(16) || signature(64) || msgpack_payload(...)
```

Full layout. The Link's session key encrypts the whole blob.

### 5.3 `msgpack_payload`

A msgpack array of 4 elements (5th optional):

```python
[timestamp_seconds_double, title_bytes, content_bytes, fields_dict]
# optional 5th element: stamp (varies)
```

Times are seconds-since-Unix-epoch as a double-precision float. Title and content are msgpack `bin` (Python `bytes`). Fields is a msgpack map; usually `{}` for plain text, but used for attachments, stickers, etc.

### 5.4 Source/destination semantics

`source_hash` is the SENDER's **destination hash** (`SHA256(name_hash || identity_hash)[:16]`), NOT the raw identity hash. A common implementation bug is to write the identity_hash here; the recipient then can't look the sender up in their contacts (which are keyed by destination_hash).

### 5.5 Signed data

```
hashed_part  = destination_hash(16) || source_hash(16) || msgpack_payload
message_hash = SHA256(hashed_part)
signed_data  = hashed_part || message_hash
signature    = Ed25519_sign(signed_data, sender_identity.Ed25519_priv)
```

For opportunistic delivery, `destination_hash` is the recipient's destination hash (from the outer packet header, not from the LXMF body).

### 5.6 Signature verification — msgpack variant tolerance

Different msgpack encoders produce subtly different byte sequences for the same logical value (e.g. integer encoding choice, string vs bin selection). The signer signed over THEIR encoder's output. A receiver should try verifying against:

1. The **raw** msgpack bytes from the wire as-received (`msgpack_payload` exactly).
2. A **stripped** re-encoded version (decode then re-encode the first 4 elements, omitting the optional stamp field).

If either matches, the signature is valid. Strict raw-only verification fails interop with anything that's been through a msgpack re-encode somewhere in the chain.

### 5.7 LXMF stamps and tickets (anti-spam)

`LXMF.LXMessage.payload[4]` (the optional 5th element of the msgpack body — see §5.3) is a **stamp**: a proof-of-work value that lets a recipient gate inbound messages against unsolicited senders. Modern Sideband installs (≥ 1.x) treat unstamped messages as low-trust and may drop them at the application layer.

#### 5.7.1 Stamp wire format

`LXMessage.STAMP_SIZE = HASHLENGTH//8 = 32 bytes` (`LXMF/LXStamper.py`). The stamp is appended to the payload msgpack array as the 5th element only if the receiver requires one or the sender has an outbound ticket. Wire form is just 32 raw bytes inside a `bin8/bin16` msgpack envelope.

When stripping the stamp during signature verification (§5.6), the receiver removes element [4] from the unpacked array and re-encodes the first 4 elements as `packed_payload` for hash computation. This is what lets a sender add or remove a stamp without invalidating the Ed25519 signature.

#### 5.7.2 Stamp generation (proof-of-work)

`LXMF/LXStamper.py::generate_stamp(message_id, target_cost)` and `::stamp_valid(stamp, target_cost, workblock)`. The algorithm:

1. **Workblock construction** — expensive HKDF-driven memory inflation:
   ```python
   def stamp_workblock(material, expand_rounds=3000):       # WORKBLOCK_EXPAND_ROUNDS
       workblock = b""
       for n in range(expand_rounds):
           workblock += RNS.Cryptography.hkdf(
               length=256,
               derive_from=material,
               salt=RNS.Identity.full_hash(material + msgpack.packb(n)),
               context=None)
       return workblock                                     # 768 KiB total
   ```
   `material` is the 32-byte `message_id` (= `SHA256(dest_hash || src_hash || msgpack_payload)`). 3000 rounds of 256-byte HKDF produces a 768 KiB workblock — designed to be cache-unfriendly enough that GPU/ASIC speedup is limited.

2. **Stamp search** — find a 32-byte value such that `SHA256(workblock || stamp)` has at least `target_cost` leading zero bits:
   ```python
   def stamp_valid(stamp, target_cost, workblock):
       target = 1 << (256 - target_cost)
       return int.from_bytes(SHA256(workblock + stamp), "big") <= target
   ```
   The `target_cost` is the Hamming-distance-from-2^256 in bit-leading-zeros — `target_cost = 8` means the result must be ≤ `2^248`, i.e. start with at least 8 zero bits.

3. **Stamp value** — for received valid stamps, `stamp_value(workblock, stamp)` returns the actual leading-zero count, which can exceed the recipient's required cost. Exceeded cost = "extra effort spent" and is exposed to the application for prioritization.

The default `WORKBLOCK_EXPAND_ROUNDS = 3000` (regular stamps), `WORKBLOCK_EXPAND_ROUNDS_PN = 1000` (propagation-node stamps — cheaper because store-and-forward already throttles), `WORKBLOCK_EXPAND_ROUNDS_PEERING = 25` (peering keys between propagation nodes — even cheaper).

#### 5.7.3 Tickets — pre-shared shortcut around proof-of-work

A **ticket** is a 16-byte (`TICKET_LENGTH = TRUNCATED_HASHLENGTH//8`) shared secret a recipient hands to a known sender, letting them skip the PoW step. With a ticket, the "stamp" becomes:

```python
stamp = SHA256(ticket || message_id)[:32]      # truncated to STAMP_SIZE
```

(`LXMessage.py::get_stamp` line 297). The recipient validates by trying every ticket they've issued the sender against the inbound stamp:

```python
# LXMessage.py::validate_stamp line 270-280
for ticket in tickets:
    if self.stamp == RNS.Identity.truncated_hash(ticket + self.message_id):
        self.stamp_value = LXMessage.COST_TICKET
        return True
```

`COST_TICKET` is a sentinel value (not a real cost) that just marks "valid by ticket".

Tickets are exchanged via the **`FIELD_TICKET = 0x0C`** key in the `fields` dict of an inbound message:

```python
# LXMRouter.lxmf_delivery, line 1741-1752
if message.signature_validated and FIELD_TICKET in message.fields:
    ticket_entry = message.fields[FIELD_TICKET]   # [expires_unix_seconds, ticket_bytes]
    if type(ticket_entry) == list and len(ticket_entry) > 1:
        if time.time() < ticket_entry[0]:
            self.remember_ticket(message.source_hash, ticket_entry)
```

Format: `fields[FIELD_TICKET] = [expires_unix_seconds(int), ticket(bytes, 16)]`. Stored under the sender's `source_hash` in the receiver's persistent ticket cache. Subsequent outbound messages from the receiver to the same sender automatically use this ticket via `LXMessage.outbound_ticket`. Tickets expire at `expires_unix_seconds`; expired tickets are evicted and the next outbound message falls back to PoW.

#### 5.7.4 The full stamp-cost field inventory

LXMF announces (§4.3) carry a `stamp_cost` integer in the `app_data` msgpack array's element [1]. A receiver tells potential senders "you must do this much PoW to message me" by setting their delivery destination's `stamp_cost` and re-announcing. Senders who get this announce store the cost in `RNS.Identity.known_destinations[dest_hash][3].app_data` and apply it to outbound messages via `LXMRouter.outbound_stamp_costs`.

When a receiver gets a message:

- If `delivery_destination.stamp_cost == None`: no stamp required; messages without one are accepted.
- If `delivery_destination.stamp_cost != None` AND the inbound message has no valid stamp AND `_enforce_stamps == True`: the message is **dropped** (`LXMRouter.py:1768-1770`).
- If `_enforce_stamps == False` (default): the message is accepted regardless, and the application is told via `message.stamp_valid` whether the stamp checked out.

A clean-room implementation that doesn't implement stamps at all will:
- Successfully send to peers with `stamp_cost = None`.
- Be silently rejected by peers with `stamp_cost != None` AND `_enforce_stamps`.
- Be flagged as "untrusted" / "spam" in receiver UIs that promote stamp validation to a UX signal even without enforcement.

For interop coverage today, "implement PoW for outbound; tolerate-but-don't-validate inbound" is the minimum. Full ticket support is a Tier-3 nice-to-have.

#### 5.7.5 Source map

| File | What |
|---|---|
| `LXMF/LXStamper.py:18-46` | `stamp_workblock`, `stamp_value`, `stamp_valid` |
| `LXMF/LXMessage.py:41` | `TICKET_LENGTH = 16` |
| `LXMF/LXMessage.py:270-291` | `validate_stamp` (ticket-then-PoW dispatch) |
| `LXMF/LXMessage.py:293-324` | `get_stamp` (ticket-or-PoW emission) |
| `LXMF/LXMRouter.py:1741-1774` | inbound dispatch — ticket cache + stamp validation + drop logic |
| `LXMF/LXMF.py:19` | `FIELD_TICKET = 0x0C` constant |

### 5.8 Propagation node protocol (offline message store-and-forward)

A **propagation node** is an LXMF node configured to accept and store messages on behalf of recipients who are temporarily offline, then deliver them when the recipient comes back online and asks. Without propagation nodes, every message requires both peers online simultaneously — a fatal assumption for mobile / mesh-edge deployments. Propagation nodes form a peer mesh that syncs messages between themselves so a recipient can retrieve mail from any one of them.

The `PROPAGATED` LXMF method (`LXMessage.py:423-441`, mentioned in `flows/send-link-lxmf.md` step 3) submits a message to a propagation node rather than directly to the recipient. The propagation node stores it and offers it to peers via §5.8.2 sync, and to the recipient via §5.8.3 retrieval.

#### 5.8.1 The `lxmf.propagation` destination

Every propagation node registers a SINGLE destination of name `lxmf.propagation` (`LXMRouter.py:173`):

```python
self.propagation_destination = RNS.Destination(
    self.identity, IN, SINGLE, APP_NAME, "propagation",
)
```

Per §1.2, the well-known `name_hash` is `e03a09b77ac21b22258e` (`SHA256("lxmf.propagation")[:10]`). The propagation node's identity is its own — different propagation nodes have different identity hashes and therefore different destination hashes. Receivers of `lxmf.propagation` announces filter by name_hash to surface "propagation node available" UI separately from "messageable peer available" UI per §4.4.

The destination registers four request handlers via `register_request_handler` (`LXMRouter.py:651-655`):

| Path | Constant | Allow | Purpose |
|---|---|---|---|
| `/offer` | `LXMPeer.OFFER_REQUEST_PATH` | `ALLOW_ALL` | Peer-to-peer message-set offer (§5.8.2) |
| `/get` | `LXMPeer.MESSAGE_GET_PATH` | `ALLOW_ALL` | Client message retrieval (§5.8.3) |
| `/stats` | `LXMRouter.STATS_GET_PATH` | implementation-defined | Operator stats query |
| `/sync` | `LXMRouter.SYNC_REQUEST_PATH` | `ALLOW_LIST` | Operator-triggered sync push |

All four are reached over an active Reticulum Link via the §11 REQUEST/RESPONSE protocol. The link must be `identify()`-d before `/offer` and `/get` requests are honored — that's how the propagation node knows which client / peer is making the request.

#### 5.8.2 Peer-to-peer sync via `/offer`

Two propagation nodes that have peered with each other periodically sync. The initiator sends an `/offer` REQUEST whose `data` is:

```python
data = [peering_key(32), [transient_id_1, transient_id_2, ...]]
```

Where:

- `peering_key` is a 32-byte proof-of-work key per §5.8.4.
- `transient_id_N` is the 16-byte hash of an LXM (`= SHA256(lxmf_data)[:16]` — the truncated hash of the full encrypted LXMF body) that the offering node has and thinks the receiving node might want.

The receiving node validates the peering_key, then for each `transient_id`:

- If it already has the message in `propagation_entries`: skip.
- Otherwise: add to `wanted_ids`.

Then returns one of three response shapes (`LXMRouter.py:2185-2187`):

| Response | Meaning |
|---|---|
| `False` (boolean) | Peer already has every offered message; no transfer needed. |
| `True` (boolean) | Peer wants every offered message. |
| `[wanted_id_1, ...]` (list) | Peer wants the listed subset only. |

If the response indicates the peer wants any messages, the offering node packs them into a Resource (§10) and sends:

```python
resource_data = msgpack.packb([time.time(), [lxmf_data_1, lxmf_data_2, ...]])
RNS.Resource(resource_data, link, callback=...)
```

The Resource contains the **full encrypted LXMF bodies** — the bytes that were signed and encrypted by the original sender; the propagation nodes never decrypt them. The receiving node writes each one to its propagation store under its `transient_id` key.

Error responses (`LXMPeer.py:14-50`):

| Constant | Hex | Meaning |
|---|---|---|
| `ERROR_NO_IDENTITY` | `0xf0` | Link wasn't `identify()`-d before the offer arrived. Initiator should retry with `link.identify()`. |
| `ERROR_NO_ACCESS` | `0xf1` | Peer rejected (e.g. `from_static_only=True` on the receiver). |
| `ERROR_THROTTLED` | `0xf2` | Peer is rate-limiting; postpone for `PN_STAMP_THROTTLE` (default 30 minutes). |
| `ERROR_INVALID_KEY` | `0xf3` | Peering key failed proof-of-work validation. |
| `ERROR_INVALID_DATA` | `0xf4` | Offer payload didn't match the expected `[key, [ids]]` shape. |
| `ERROR_NOT_FOUND` | `0xf5` | (Used by `/sync` and stats-query paths) |

#### 5.8.3 Client retrieval via `/get`

A regular LXMF client (Sideband, NomadNet client, custom) retrieves stored messages with an `/get` REQUEST whose `data` is:

```python
data = [wanted_ids, have_ids, optional_transfer_limit_kb]
```

Where:

- **`wanted_ids = None`** AND **`have_ids = None`** triggers a **listing query**: the propagation node returns `[transient_id_1, transient_id_2, ...]` of every message it holds for the requesting identity, sorted by size ascending.
- **`wanted_ids`** is a list of transient_ids the client wants delivered. Propagation node responds with a Resource (or single packet if small enough) carrying `msgpack.packb([time.time(), [lxmf_data_1, ...]])`.
- **`have_ids`** is a list of transient_ids the client confirms it has stored locally. Propagation node deletes those from its store. (Equivalent to "ack and purge".)
- **`optional_transfer_limit_kb`** lets the client cap the transfer size — propagation node skips messages that would exceed the cap.

Common usage: client first sends `/get` with `[None, None]` to get the list, picks which ones it wants based on size, then sends `/get` with `[wanted_subset, prior_subset_to_purge]` to fetch the new ones and acknowledge previously-fetched ones.

The propagation node only returns messages whose `propagation_entries[tid][0] == requester's destination_hash` (`LXMRouter.py:1440, 1455`) — each message is keyed to its intended recipient and the propagation node is structurally unable to deliver it to the wrong address. The LXMF body is still encrypted to the recipient's public key as a defence-in-depth.

#### 5.8.4 Peering keys (PoW for peer-to-peer auth)

Two propagation nodes that want to peer must each compute a peering key for the relationship (`LXStamper.py::validate_peering_key` and `stamp_workblock` with `WORKBLOCK_EXPAND_ROUNDS_PEERING = 25`):

```python
peering_id = self.identity.hash + remote_identity.hash    # 32 bytes (16 + 16)
workblock  = stamp_workblock(peering_id, expand_rounds=25)
peering_key = (find any 32B value such that
               SHA256(workblock || peering_key)
               has at least target_cost leading zero bits)
```

`target_cost` is the receiving node's `peering_cost` (announced in element [5][2] of the propagation announce app_data, see §5.8.5). With only 25 rounds of HKDF expansion (vs 3000 for regular message stamps in §5.7), the workblock is ~6 KiB and peering keys can be computed in milliseconds. Peering keys are amortized: computed once between two propagation nodes and reused for every subsequent `/offer` for the lifetime of the peering.

#### 5.8.5 Propagation node announce app_data

Distinct from §4.3 (which is for `lxmf.delivery`). For `lxmf.propagation` announces, `LXMRouter.get_propagation_node_app_data` (line 307-319) emits a 7-element msgpack array:

```python
announce_data = [
    False,                                  # [0] legacy-LXMF-PN-support flag (always False now)
    int(time.time()),                       # [1] node timebase (unix seconds, big-int)
    node_state,                             # [2] bool — accepting messages right now?
    propagation_per_transfer_limit,         # [3] int — per-transfer cap in KB
    propagation_per_sync_limit,             # [4] int — per-sync incoming cap in KB
    [stamp_cost, stamp_cost_flexibility,
     peering_cost],                         # [5] list of three ints
    metadata,                               # [6] dict — operator-supplied node metadata
]
return msgpack.packb(announce_data)
```

Element [5] sub-fields:

| Index | Name | Meaning |
|---|---|---|
| `[5][0]` | `stamp_cost` | PoW cost (leading zero bits) for client `/get` retrieval stamps |
| `[5][1]` | `stamp_cost_flexibility` | Tolerance — client stamps within this many bits below `stamp_cost` are still accepted |
| `[5][2]` | `peering_cost` | PoW cost for peering keys per §5.8.4 |

Receivers parse this via `pn_announce_data_is_valid` (`LXMF/LXMF.py:191-206`), which insists on exactly 7 elements with type-correct positions. **A client that misparses element [5] as a single integer (rather than a 3-element list) silently fails to compute the right peering / retrieval stamp and is rejected** — this is the most common interop break in custom propagation-node implementations.

#### 5.8.6 Source map

| File | What |
|---|---|
| `LXMF/LXMRouter.py:173` | propagation_destination construction |
| `LXMF/LXMRouter.py:307-319` | propagation announce app_data shape |
| `LXMF/LXMRouter.py:651-655` | `/offer` and `/get` handler registration |
| `LXMF/LXMRouter.py:1427-1500` | `message_get_request` handler (client `/get`) |
| `LXMF/LXMRouter.py:2142-2192` | `offer_request` handler (peer `/offer`) |
| `LXMF/LXMPeer.py:14-50` | path constants and error-response constants |
| `LXMF/LXMPeer.py:370-486` | initiator-side `/offer` flow |
| `LXMF/LXStamper.py::validate_peering_key` | peering-key PoW validation |
| `LXMF/LXMF.py:191-206` | `pn_announce_data_is_valid` parser |

### 5.9 Source

`LXMF/LXMessage.py` for pack/unpack; `LXMF/LXMF.py` for the app_data extraction helpers; `LXMF/LXStamper.py` for stamps; `LXMF/LXMRouter.py` for receive-side stamp/ticket dispatch and propagation handlers; `LXMF/LXMPeer.py` for the propagation peer-to-peer state machine.

---

## 6. Reticulum Link protocol

A Link is an ephemeral encrypted channel between two destinations, established via a 2-packet handshake (LINKREQUEST → LRPROOF) and used afterward for full-duplex DATA.

### 6.1 LINKREQUEST (initiator → responder)

A regular packet with `packet_type = LINKREQUEST (2)`, `dest_type = SINGLE`, addressed to the responder's destination hash. Body:

```
initiator_X25519_pub(32) || initiator_Ed25519_pub(32) || [signalling(3)]
```

Both initiator-side keys are **fresh ephemeral keys** (not the initiator's long-term identity). The optional 3-byte signalling field encodes a packed 21-bit MTU and 3-bit link mode — see §6.6 for the bit layout and the negotiation rules. Receivers detect its presence by body length: `len(data) == 64` means no signalling, `len(data) == 67` means signalling present.

### 6.2 LRPROOF (responder → initiator)

A `packet_type = PROOF (3)` with `context = 0xff`, addressed to the link itself — i.e. `dest_hash` in the packet header is the 16-byte `link_id` (`RNS/Packet.py:182-184`: when context is `LRPROOF`, `header += destination.link_id` and the body is appended unencrypted).

Body (`proof_data` at `RNS/Link.py:376`):

```
signature(64) || responder_X25519_pub(32) || [signalling(3)]
```

Only the responder's X25519 is fresh-ephemeral; the responder signs with its **long-term** Ed25519 private key (asymmetric with the initiator). The responder's long-term Ed25519 public key is **not** sent on the wire — both sides already know it from the responder's prior announce, and it is included implicitly in the signature input. Signature input (`RNS/Link.py:373` for the signer, `:417` for the validator):

```
signed_data = link_id || responder_X25519_pub || responder_long_term_Ed25519_pub || [signalling]
```

The full wire packet is therefore: `flags(1) || hops(1) || link_id(16) || context=0xff(1) || signature(64) || responder_X25519_pub(32) || [signalling(3)]`.

The signalling slot, when present, carries the responder's `confirmed_mtu` and the link mode in a 24-bit packed integer — see §6.6. Receivers detect its presence by length: body 96 vs 99 bytes. **Critical for interop:** the signalling bytes (when present) MUST be included in `signed_data` exactly where shown above; an implementation that signs without them on a peer that emits them — or vice versa — fails signature validation and the link never establishes. This is the most common cause of link-handshake failures with mixed-version peers.

### 6.3 link_id derivation

```
link_id = SHA256(hashable_part_of_LINKREQUEST_packet)[:16]
```

`hashable_part` is built by `Packet.get_hashable_part` (`RNS/Packet.py:354-361`):

```
hashable_part = byte(flags & 0x0F) || raw[N:]
   where N = 2  for HEADER_1   (strip flags + hops)
         N = 18 for HEADER_2   (strip flags + hops + transport_id)
```

The "hashable part" deliberately strips `header_type`, `context_flag`, `transport_type` (top 4 bits of flags — modifiable by transit relays), the `hops` byte (modified by every relay), and (for HEADER_2) the `transport_id` (added by the originator and re-written by each relay). What remains in both cases is the low nibble of flags + dest_hash + context + body, so the resulting `link_id` is the same whether the LINKREQUEST is hashed at the initiator (HEADER_1) or at the responder after one or more transport relays (HEADER_2). Both sides agree on the 16-byte ID.

For LINKREQUEST packets specifically, the trailing signalling bytes (if present, indicated by `len(packet.data) > Link.ECPUBSIZE` in `link_id_from_lr_packet` at `RNS/Link.py:340-347`) are stripped from the END of `hashable_part` before hashing, so the link_id is invariant under MTU-discovery signalling.

### 6.4 Session key derivation

Both sides compute:

```
shared       = X25519(my_ephemeral_priv, peer_ephemeral_pub)
session_key  = HKDF(shared, salt = link_id, info = "", L = 64)
signing_key  = session_key[0..32]
encrypt_key  = session_key[32..64]
```

Subsequent DATA packets on the link use the Link-derived-key Token format (section 3.1, no ephemeral_pub prefix).

### 6.5 Packet receipts (regular `PROOF` packets)

A `PROOF`-type packet (`packet_type = 3`, `context = NONE (0x00)`) is the receipt that closes the loop on every CTX_NONE DATA packet — both opportunistic DATA addressed to a SINGLE destination and DATA flowing on an active Link. Without it, the sender's `PacketReceipt` never resolves, its retransmit queue fires repeatedly, and on a Link the KEEPALIVE budget is exhausted and the link torn down.

This section specifies the regular PROOF body. Two related proof formats are documented elsewhere and are NOT compatible with this format:

- **`LRPROOF (context = 0xFF)`** is the link-establishment proof (§6.2). Different body, different signature input.
- **`RESOURCE_PRF (context = 0x05)`** is the proof for a completed Resource transfer (§10.8). Different body (`resource_hash || full_proof`), no signature.

#### 6.5.1 Two body formats: explicit vs implicit

Regular PROOFs come in two wire forms (`RNS/Packet.py:413-414`):

```
EXPL_LENGTH = HASHLENGTH//8 + SIGLENGTH//8 = 32 + 64 = 96 bytes
IMPL_LENGTH = SIGLENGTH//8                 =      64 = 64 bytes

explicit body  =  packet_hash(32) || signature(64)
implicit body  =                     signature(64)
```

Where:

- `packet_hash = Identity.full_hash(original_packet.get_hashable_part())` — the full SHA-256 (32 bytes, **not** truncated to 16) of the prove-target packet's hashable part. `get_hashable_part` is the same recipe used for `link_id` derivation in §6.3, so the proof binds to the version of the packet that survived any HEADER_1↔HEADER_2 conversion in transit (the high nibble of flags, hops byte, and any HEADER_2 transport_id are stripped before hashing).
- `signature` is the destination's (or link's) Ed25519 signature **over `packet_hash`**, NOT over the proof body itself. The signing key is the destination's long-term Ed25519 private key for an opportunistic DATA proof, or the link-derived signing key for a Link DATA proof.

The two forms are distinguished **purely by length** at the receiver. `PacketReceipt.validate_proof` (`RNS/Packet.py:497-548`) dispatches on `len(proof) == 96` (explicit) vs `len(proof) == 64` (implicit); lengths matching neither are rejected outright. There is no flag bit or context byte that signals which form is being used — wire length is the only signal.

#### 6.5.2 Choosing which form to emit

Sender side, two distinct policies:

**Opportunistic DATA addressed to a SINGLE destination** — `RNS.Identity.prove(packet, destination)` at `RNS/Identity.py:912-923`:

```python
def prove(self, packet, destination=None):
    signature = self.sign(packet.packet_hash)
    if RNS.Reticulum.should_use_implicit_proof():
        proof_data = signature                                  # 64 bytes
    else:
        proof_data = packet.packet_hash + signature             # 96 bytes
    proof = RNS.Packet(destination_or_proof_dest, proof_data,
                       RNS.Packet.PROOF, attached_interface=...)
    proof.send()
```

The default upstream value is `Reticulum.__use_implicit_proof = True` (`RNS/Reticulum.py:259`), so **upstream emits the 64-byte implicit form by default**. The 96-byte explicit form is only emitted when the operator's `[reticulum]` config sets `use_implicit_proof = No`. A clean-room implementation that hardcodes either single form will fail to interop with peers running the other one — receiver-side validators handle both, but a hardcoded sender writing the wrong length to the wire is not negotiable.

**DATA on an active Link** — `RNS.Link.prove_packet(packet)` at `RNS/Link.py:383-394`:

```python
def prove_packet(self, packet):
    signature = self.sign(packet.packet_hash)
    proof_data = packet.packet_hash + signature                 # 96 bytes — always
    proof = RNS.Packet(self, proof_data, RNS.Packet.PROOF)
    proof.send()
```

with the upstream comment `# TODO: Hardcoded as explicit proof for now`. Link DATA proofs are **always** the 96-byte explicit form in RNS 1.2.0 regardless of the `use_implicit_proof` setting, and the matching `validate_link_proof` at `RNS/Packet.py:449-494` has the implicit-form branch commented out with the same note. Today, Link DATA proofs are explicit-only on both ends; an implementation may match this behavior with a single hardcoded length on the link path, but should be ready to revisit if upstream re-enables the implicit branch (no fixed timeline).

#### 6.5.3 Where the proof packet is addressed

The dest_hash position in the proof packet's outer header depends on which side of which transport the proven packet was on:

- **Opportunistic DATA proof:** `dest_hash = packet_hash[:16]` (the 16-byte truncation of the full SHA-256 of the proved packet's hashable part, used as a synthetic `ProofDestination` — `RNS/Packet.py:390-396`). The proof rides through `Transport.outbound` and follows the reverse path home via the receiver's `reverse_table`.
- **Link DATA proof:** `dest_hash = link.link_id` (the 16-byte link id, just like all other Link traffic; `RNS/Packet.py:182-184` notes this position is filled by `destination.link_id` whenever the destination object is a Link). The proof rides on the link itself.

#### 6.5.4 Wire summary

```
explicit form (96 bytes total body):
[ 1B flags ][ 1B hops ][ 16B dest_hash || link_id ][ 1B context=0x00 ]
[ 32B SHA256(get_hashable_part(original_packet)) ]
[ 64B Ed25519_signature(SHA256(get_hashable_part(original_packet))) ]

implicit form (64 bytes total body):
[ 1B flags ][ 1B hops ][ 16B dest_hash || link_id ][ 1B context=0x00 ]
[ 64B Ed25519_signature(SHA256(get_hashable_part(original_packet))) ]
```

Note `context = 0x00 (NONE)` in both cases — the proof-ness is conveyed by `packet_type = PROOF (3)` in the flag byte, not by a context. This is in contrast to LRPROOF (which uses `context = 0xFF`) and RESOURCE_PRF (which uses `context = 0x05`). The `LINKPROOF (0xFD)` context constant defined at `RNS/Packet.py:90` is reserved but not actually used by either prove path in RNS 1.2.0.

#### 6.5.5 Receiver tolerance

A new implementation's PROOF validator MUST accept both 64- and 96-byte bodies for opportunistic DATA proofs (per `validate_proof`'s length-dispatch above) so it interops with peers running either policy. Hardcoding only one form at the validator silently fails on traffic from a peer with the opposite setting. Length-dispatch is also the only place the validator ever distinguishes the two — there is no "I want explicit" hint a sender can express.

A receiver that gets a PROOF whose length matches neither form treats it as malformed and returns `False` from `validate_proof`; no NACK is sent to the originator.

#### 6.5.6 Why this matters for Link interop

After processing each `NONE` DATA packet on an active link, the receiver MUST emit the explicit-form PROOF described above. Without it, the sender's retransmit queue fires and the same packet arrives repeatedly, eventually exceeding the link's KEEPALIVE budget and tearing down the link. This is `Packet.prove_packet` upstream — non-optional for any client that wants to receive content over a Link without spamming the sender.

### 6.6 MTU and mode signalling (3-byte trailer on LINKREQUEST and LRPROOF)

The optional 3-byte `signalling` slot referenced in §6.1 and §6.2 carries two negotiated parameters in a single 24-bit big-endian packed integer: the link MTU (21 bits) and the link mode (3 bits, top of the high byte). When present, the signalling bytes are also included in the LRPROOF's signed_data, so the responder's signature commits to the negotiated values and a peer flipping a bit in transit invalidates the proof.

#### 6.6.1 Wire layout

3 bytes total, big-endian. Byte 0 is split: top 3 bits are `mode`, low 5 bits are the most-significant 5 bits of the 21-bit `mtu`. Bytes 1 and 2 are the remaining 16 bits of `mtu`:

```
byte 0 :  M M M m m m m m       — top 3 bits = mode (0..7), low 5 bits = mtu[20..16]
byte 1 :  m m m m m m m m       — mtu[15..8]
byte 2 :  m m m m m m m m       — mtu[7..0]
```

Encoded by `RNS/Link.py:147-151`:

```python
@staticmethod
def signalling_bytes(mtu, mode):
    if not mode in Link.ENABLED_MODES:
        raise TypeError(f"Requested link mode {Link.MODE_DESCRIPTIONS[mode]} not enabled")
    signalling_value = (mtu & Link.MTU_BYTEMASK) + (((mode << 5) & Link.MODE_BYTEMASK) << 16)
    return struct.pack(">I", signalling_value)[1:]    # big-endian uint32, drop top byte
```

with `MTU_BYTEMASK = 0x1FFFFF` (21 bits) and `MODE_BYTEMASK = 0xE0` (top 3 bits of a byte).

Decoded mode and mtu (from `mode_from_lr_packet` line 171-176, `mtu_from_lr_packet` line 153-157):

```python
mode = (signalling[0] & 0xE0) >> 5
mtu  = ((signalling[0] << 16) + (signalling[1] << 8) + signalling[2]) & 0x1FFFFF
```

The mtu decode trick: the full 24-bit value of all three bytes is masked with the 21-bit `MTU_BYTEMASK`, which strips the top 3 bits (i.e. the mode bits) without any explicit byte 0 masking step. Implementations that use `(signalling[0] & 0x1F) << 16 | …` instead get the same answer.

#### 6.6.2 Mode field

3-bit value (0..7) at the top of byte 0. Defined values, with `RNS/Link.py:125-142`:

| Mode | Name | Status in RNS 1.2.0 | Derived key length |
|---|---|---|---|
| `0x00` | `MODE_AES128_CBC` | Defined, NOT enabled (sender-side will raise `TypeError`) | 32 bytes |
| `0x01` | `MODE_AES256_CBC` | Default; the only enabled mode (`ENABLED_MODES = [0x01]`) | 64 bytes |
| `0x02` | `MODE_AES256_GCM` | Reserved, not enabled | — |
| `0x03` | `MODE_OTP_RESERVED` | Reserved, not enabled | — |
| `0x04`–`0x07` | `MODE_PQ_RESERVED_*` | Reserved for the post-quantum migration; not enabled | — |

The `derived_key_length` at `RNS/Link.py:358-360` is what the HKDF in §6.4 produces, split as `signing_key(32) || encrypt_key(32)` for the AES-256 path or `signing_key(16) || encrypt_key(16)` for the AES-128 path.

A receiver MUST tolerate seeing any 3-bit value in the mode field on inbound traffic — `mode_from_lr_packet` returns the raw integer without validating it against `ENABLED_MODES`. The mode is enforced at handshake time (`Link.handshake` at line 353-368): unknown / disabled modes raise `TypeError` and the link transitions to `CLOSED` rather than `ACTIVE`. Senders MUST NOT emit any mode value not in `ENABLED_MODES` — `signalling_bytes()` raises if you try.

A clean-room implementation today can safely hardcode mode = `0x01` on emit. On receive, it should accept `0x01` and reject the rest as "mode not supported by this implementation" rather than silently treating them as the default — a future RNS version that flips the default to `0x04` (one of the PQ slots) would render a hardcoded-default decoder ambiguous about whether the wire bytes mean "AES_256_CBC" or "the new default".

#### 6.6.3 MTU field

21-bit unsigned integer in the low 21 bits of the 24-bit signalling value. Max representable: `0x1FFFFF = 2,097,151` bytes. Real Reticulum `HW_MTU` values are radically smaller (LoRa: 508; TCP: typical HW MTU ~64 KiB; AutoInterface: matches its bearer). The 21-bit width is forward-looking: it leaves room for future high-bandwidth interfaces without a wire-format change.

When the initiator emits a LINKREQUEST with signalling, the encoded `mtu` is the next-hop interface's `HW_MTU` (`RNS/Link.py:309-314`):

```python
nh_hw_mtu = RNS.Transport.next_hop_interface_hw_mtu(destination.hash)
if RNS.Reticulum.link_mtu_discovery() and nh_hw_mtu:
    signalling_bytes = Link.signalling_bytes(nh_hw_mtu, self.mode)
else:
    signalling_bytes = Link.signalling_bytes(RNS.Reticulum.MTU, self.mode)
```

When the responder emits an LRPROOF with signalling, the encoded `mtu` is the **min** of its own next-hop view and what arrived in the LINKREQUEST, computed during validation (`RNS/Transport.py:2042-2051`):

```python
path_mtu = Link.mtu_from_lr_packet(packet) or Reticulum.MTU
nh_mtu   = receiving_interface.HW_MTU if AUTOCONFIGURE_MTU/FIXED_MTU else Reticulum.MTU
if nh_mtu < path_mtu:
    path_mtu = nh_mtu
    clamped_signalling = Link.signalling_bytes(path_mtu, mode)
    packet.data = packet.data[:-LINK_MTU_SIZE] + clamped_signalling
```

The clamp is rewritten **into the LINKREQUEST packet's data buffer in place** before that packet enters the responder's `Destination.receive` path, so the responder's eventual LRPROOF carries the clamped value, not the originally-requested one. The clamp also affects link_id derivation: `link_id_from_lr_packet` strips trailing signalling bytes before hashing (per §6.3), so this in-place rewrite doesn't change the link_id even though it does change the wire bytes.

The initiator reads `confirmed_mtu` back via `mtu_from_lp_packet` during LRPROOF validation (`RNS/Link.py:404-408`), accepts it as `link.mtu`, and the link's `mdu` (max data unit per packet for §3.1 link-derived Token traffic) is recomputed via `update_mdu()`.

#### 6.6.4 Presence detection — length only

Both directions detect the optional signalling slot **purely by packet body length**:

| Packet | Body length without signalling | Body length with signalling |
|---|---|---|
| LINKREQUEST | `ECPUBSIZE = 64` | `ECPUBSIZE + LINK_MTU_SIZE = 67` |
| LRPROOF     | `SIGLENGTH//8 + ECPUBSIZE//2 = 96` | `... + LINK_MTU_SIZE = 99` |

Where `ECPUBSIZE = 64` is the combined initiator ephemeral X25519 + Ed25519 public key (`Link.py:70`), and `SIGLENGTH//8 = 64` is the responder's Ed25519 signature.

Receivers MUST handle both forms. `validate_request` at `RNS/Link.py:186-190` checks `len(data) == ECPUBSIZE` OR `len(data) == ECPUBSIZE+LINK_MTU_SIZE` and rejects anything else. The same length-dispatch is in `validate_proof` for the LRPROOF side at `RNS/Link.py:404-410`. There is no flag bit signalling presence — wire length is the only signal.

#### 6.6.5 Inclusion in LRPROOF signed_data

Per §6.2, the LRPROOF's signed_data when signalling is present is:

```
signed_data = link_id || responder_X25519_pub || responder_long_term_Ed25519_pub || signalling
```

A clean-room implementation that omits the signalling bytes when present (or includes them when absent) computes a different signed_data than the responder did, fails signature validation, and the link never establishes. This is the most common interop break in this area; cross-check against `RNS/Link.py:373` (signer) and `:417` (validator).

#### 6.6.6 Disabling MTU discovery

The `[reticulum]` config option `link_mtu_discovery = No` makes `Reticulum.link_mtu_discovery()` return False, so the initiator skips signalling on outbound LINKREQUESTs (`RNS/Link.py:311-314`). In that case the link uses `Reticulum.MTU` (default 500 bytes) globally, no per-link MTU clamping happens, and all four lengths fall back to the no-signalling sizes in §6.6.4.

A receiver doesn't need its own copy of the disable switch — it just stops seeing trailing signalling bytes from peers that have it disabled. Its own MTU reporting on the LRPROOF return path runs unaffected for peers that send it.

### 6.7 KEEPALIVE and link teardown

A Link goes through five states (`RNS/Link.py:110-114`): `PENDING → HANDSHAKE → ACTIVE → STALE → CLOSED`. `KEEPALIVE` and `LINKCLOSE` are the two control-plane packet types that drive transitions out of `ACTIVE`.

#### 6.7.1 KEEPALIVE (`context = 0xFA`)

Cadence (`RNS/Link.py:844-846`):

```python
def __update_keepalive(self):
    self.keepalive = max(min(self.rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MAX), KEEPALIVE_MIN)
    self.stale_time = self.keepalive * STALE_FACTOR
```

with constants `KEEPALIVE_MAX = 360s`, `KEEPALIVE_MIN = 5s`, `KEEPALIVE_MAX_RTT = 1.75s`, `STALE_FACTOR = 2`. The interval is `RTT × 205.7` clamped to `[5, 360]` seconds. Before the first RTT is measured (set in `validate_proof`), the link uses `KEEPALIVE = KEEPALIVE_MAX = 360s`.

The watchdog (`Link.__watchdog_job`, line 751-821) fires on every active link. When `now >= last_inbound + keepalive` AND the local node is the **initiator**, it emits a KEEPALIVE:

```python
def send_keepalive(self):
    keepalive_packet = RNS.Packet(self, bytes([0xFF]), context=RNS.Packet.KEEPALIVE)
    keepalive_packet.send()
```

Body is a single byte `0xFF` — the "ping" sentinel. The packet is Token-encrypted with the link's session key per §3.1 link-derived form, so the wire body is `iv(16) || ciphertext(...) || hmac(32)`; the decrypted plaintext is just `b'\xff'`.

The **responder** receives this in `Link.receive` at `RNS/Link.py:1149-1153` and answers with the "pong" sentinel:

```python
elif packet.context == RNS.Packet.KEEPALIVE:
    if not self.initiator and packet.data == bytes([0xFF]):
        keepalive_packet = RNS.Packet(self, bytes([0xFE]), context=RNS.Packet.KEEPALIVE)
        keepalive_packet.send()
```

So:
- **Ping** = initiator → responder, body `0xFF`.
- **Pong** = responder → initiator, body `0xFE`.
- Only the initiator originates KEEPALIVE traffic. The responder never spontaneously pings.

Both sentinel bytes are arbitrary; what actually matters for keep-alive purposes is that *any* inbound traffic on the link refreshes `last_inbound` (the watchdog's anchor for staleness decisions). KEEPALIVE packets, like all link DATA, also generate the mandatory PROOF receipt per §6.5, which is itself inbound traffic on the return path. So a successful ping/pong exchange resets the staleness clock on **both** sides via three round-trip artifacts: ping → pong → pong-proof.

A clean-room responder MUST emit the pong on inbound `0xFF`; without it the initiator's watchdog will declare the link stale on the next cycle.

#### 6.7.2 STALE → CLOSED transition

When `now >= last_inbound + stale_time` (= `2 × keepalive`), the watchdog moves the link from `ACTIVE` to `STALE` (line 796-800), then on its next pass emits a teardown packet and transitions to `CLOSED` (line 805-810):

```python
elif self.status == Link.STALE:
    sleep_time = 0.001
    self.__teardown_packet()                  # see §6.7.3
    self.status = Link.CLOSED
    self.teardown_reason = Link.TIMEOUT
    self.link_closed()
```

`teardown_reason` is set to `Link.TIMEOUT` (constant value `0x01`) so the application's `link_closed_callback` can distinguish "the peer went dark" from "the peer cleanly closed".

There is also an explicit-cleanup path: after a STALE-induced teardown the watchdog adds a final grace period of `RTT × KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE` (= `RTT × 4 + 5s`) at line 797 to allow a delayed reply to bring the link back into ACTIVE before final teardown — but in upstream RNS 1.2.0 the `STALE → CLOSED` transition runs immediately on the next watchdog pass without consulting that grace period. The grace constant lives in case a future revision restores the soft-stale window.

#### 6.7.3 LINKCLOSE (`context = 0xFC`)

Either side can cleanly tear down a link by calling `Link.teardown()` (line 699-708), which sends a single LINKCLOSE packet and transitions the local state to `CLOSED`:

```python
def __teardown_packet(self):
    teardown_packet = RNS.Packet(self, self.link_id, context=RNS.Packet.LINKCLOSE)
    teardown_packet.send()
```

Wire form:
- `packet_type = DATA (0)`, `context = 0xFC`, `dest_hash = link_id`.
- Body is the **16-byte link_id**, Token-encrypted by the link's session key.

The peer's receiver path at `RNS/Link.py:1061-1063` calls `teardown_packet(packet)` (line 710-722):

```python
def teardown_packet(self, packet):
    plaintext = self.decrypt(packet.data)
    if plaintext == self.link_id:                # auth check
        self.status = Link.CLOSED
        if self.initiator:
            self.teardown_reason = Link.DESTINATION_CLOSED
        else:
            self.teardown_reason = Link.INITIATOR_CLOSED
        self.link_closed()
```

The body's plaintext **MUST** equal `link_id` for the close to take effect — this is the on-link auth check. A peer that doesn't share the session key can't decrypt the body, and even if it could, the link_id check rejects bodies with arbitrary content. Combined with the Token HMAC, this gives both "encrypted" and "authenticated" guarantees on the teardown signal.

After `link_closed()` (line 724-743) runs:

- All `incoming_resources` and `outgoing_resources` are cancelled (cancels propagate into the §10 Resource state machine).
- The Link's session keys (`self.shared_key`, `self.derived_key`) are zeroed by reassignment to `None` — the upstream comment at line 700-702 notes this is the forward-secrecy property: "encryption keys are purged. New keys will be used if a new link to the same destination is established."
- The `link_closed_callback` registered via `set_link_closed_callback` fires.
- The Link is removed from its destination's `links` list (responders only — initiators don't have a destination-list entry).

#### 6.7.4 Teardown reason codes

`Link.teardown_reason` is set to one of (`RNS/Link.py:116-118`):

| Constant | Hex | Meaning |
|---|---|---|
| `TIMEOUT` | `0x01` | Watchdog STALE → CLOSED transition. No LINKCLOSE was received. |
| `INITIATOR_CLOSED` | `0x02` | This side is the responder; the initiator sent a LINKCLOSE. |
| `DESTINATION_CLOSED` | `0x03` | This side is the initiator; the responder sent a LINKCLOSE. |

These are local-state values, not on the wire — the LINKCLOSE packet itself doesn't carry a reason code. The recipient just infers whether the close came from the other side based on whether they're initiator or responder.

#### 6.7.5 Receiver responsibilities (minimum)

For a clean-room implementation that wants links to survive idle periods longer than a few seconds:

1. Keep a per-link `last_inbound` timestamp updated on every inbound packet on the link (DATA, PROOF, KEEPALIVE — anything).
2. On the **initiator** side, run a watchdog that emits a `0xFF` KEEPALIVE every `link.keepalive` seconds since `last_inbound`. Default `link.keepalive = 360s` is fine until you measure RTT.
3. On the **responder** side, reply to every `0xFF` KEEPALIVE with a `0xFE` KEEPALIVE. Don't originate.
4. On both sides, transition to `CLOSED` if `last_inbound + 2*keepalive` elapses with no traffic, AND emit a `LINKCLOSE` packet so the peer doesn't have to wait for its own watchdog to time out.
5. On every inbound `LINKCLOSE`, decrypt, verify body equals `link_id`, transition to `CLOSED`.
6. On `CLOSED`, zero the session keys and cancel any in-progress Resources.

### 6.8 Channel mode (`CHANNEL = 0x0E`)

A Channel is a **continuous, bi-directional, message-typed stream** on top of an established Link. Distinct from §11 REQUEST/RESPONSE (single-shot, client-server) and §10 Resources (large unidirectional transfers): Channel messages are short, can flow in either direction at any time, and carry an application-defined type byte the receiver dispatches on. NomadNet uses it for its "channel" API (live chat over a Link), and any application can register custom message types via `RNS.Channel.Channel.register_message_type`.

#### 6.8.1 Wire form

A Channel message rides as a single Link DATA packet with `context = CHANNEL (0x0E)`. The body is **6-byte fixed-prefix header + variable-length payload** (`RNS/Channel.py:192-198`):

```
msgtype(2)  ||  sequence(2)  ||  length(2)  ||  data(length bytes)
```

All three header fields are **big-endian unsigned 16-bit integers** (Python `struct.pack(">HHH", msgtype, sequence, length)`):

| Field | Width | Meaning |
|---|---|---|
| `msgtype` | uint16 BE | Application-defined message type. Distinguishes the payload schema. |
| `sequence` | uint16 BE | Per-direction sequence number, starting at 0 and incrementing each emission. Wraps at 65536. |
| `length` | uint16 BE | Length in bytes of the payload that follows. |

The whole 6-byte header + payload is the Link DATA packet's **plaintext**, which is then Token-encrypted by the link's session key (§3.1 link-derived form, no eph_pub prefix) before transmission.

#### 6.8.2 Reserved system message types

`RNS/Channel.py:45-46`:

```python
class SystemMessageTypes(enum.IntEnum):
    SMT_STREAM_DATA = 0xff00
```

`0xff00` is reserved for upstream's stream-over-channel implementation. Application-defined message types should stay in the `0x0000..0xfeff` range to avoid collisions with reserved system types. There's no centralized registry — each Link's `Channel` instance maintains its own `message_factories` dict mapping `msgtype` to a constructor.

#### 6.8.3 MSGTYPE registration

Both endpoints of a Link must register matching message types via `Channel.register_message_type(message_class)` before they can send or receive that type. The constructor must implement:

```python
class MyMessage(MessageBase):
    MSGTYPE = 0x1234           # uint16 in [0x0000, 0xfeff]
    def pack(self) -> bytes: ...
    def unpack(self, raw: bytes): ...
```

A receiver that gets a `msgtype` it didn't register raises `ChannelException(ME_NOT_REGISTERED)` and drops the message. A sender that tries to send a class without `MSGTYPE` defined raises `ChannelException(ME_NO_MSG_TYPE)`.

#### 6.8.4 Reliable delivery

Channel uses the standard §6.5 mandatory PROOF receipt mechanism for each message — every Channel DATA packet generates a PROOF, and the sender's `Channel` retries on timeout up to a per-packet limit. Reliability is the main reason to use Channel over plain Link DATA: the application doesn't need to implement its own retransmit logic.

The receiver-side `Channel` uses a **sliding window** with the same window-growth dynamics as §10 Resources (`Channel.WINDOW = 2` initial, with rate-thresholded growth/shrink). Sequence numbers in the channel header let the receiver detect gaps and request retransmits; out-of-order arrivals are buffered until the gap fills.

#### 6.8.5 When to use Channel vs the alternatives

| Use case | Best mechanism |
|---|---|
| One-shot small request → one-shot small response | §11 REQUEST/RESPONSE |
| One-shot large transfer (file, page) | §10 Resource |
| Continuous bi-directional small messages (chat, telemetry stream, command/event flow) | §6.8 Channel |
| Continuous bi-directional large transfers | §10 Resources sequenced in time, OR Channel with `SMT_STREAM_DATA` chunks |

A clean-room client that only implements opportunistic LXMF can ignore Channel entirely. NomadNet-aware clients need it for the channel API; custom-RPC applications may prefer it over §11 for its bi-directional nature.

#### 6.8.6 Source map

| File | What |
|---|---|
| `RNS/Channel.py:174-211` | `Envelope` — wire-form pack/unpack |
| `RNS/Channel.py:214-...` | `Channel` — windowed reliable delivery on a Link |
| `RNS/Channel.py:45-46` | `SMT_STREAM_DATA = 0xff00` reserved system type |
| `RNS/Channel.py:317-325` | `register_message_type` — per-Link MSGTYPE dispatch table |
| `RNS/Packet.py:86` | `CHANNEL = 0x0E` context constant |

### 6.9 Source

`RNS/Link.py`, `RNS/Packet.py::prove`, `RNS/Identity.py::prove`, `RNS/PacketReceipt.py::validate_proof`, `RNS/Channel.py`. The webclient's `reference/js-reference/link.js` is a faithful port.

---

## 7. Transport behavior — the parts that bite

### 7.1 Path requests: peers send `path?` before opportunistic LXMF when no path is known

The path-request preamble in upstream LXMF is **conditional, not unconditional** (verified by `tools/verify_path_request.py` against LXMF 0.9.6):

```python
# LXMF/LXMRouter.py::handle_outbound, ~line 1672
if not RNS.Transport.has_path(destination_hash) and lxmessage.method == LXMessage.OPPORTUNISTIC:
    RNS.log("Pre-emptively requesting unknown path for opportunistic ...", RNS.LOG_DEBUG)
    RNS.Transport.request_path(destination_hash)
    lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
```

In other words: a `path?` is sent before the LXM **only when no entry exists in `Transport.path_table`** for the target — `has_path()` is just a key-presence check (`RNS/Transport.py:2570-2576`). Existing-but-stale path entries are NOT replaced by this preamble; LXMF instead leans on the periodic `Transport.jobs` cycle to evict expired path entries (`stale_paths` accumulator at `RNS/Transport.py:747+`), after which the next outbound LXM rediscovers the unknown-path branch and triggers the `request_path`. A second `request_path` is issued from the retry path (`LXMRouter.py:2571+`) once `lxmessage.delivery_attempts >= MAX_PATHLESS_TRIES`, so on a flaky path peers can see multiple `path?` retransmits without intervening DATA — that matches BLE-trace observations.

A `path?` request itself is a regular DATA packet (verified by `tools/verify_path_request.py`):

- `dest_hash = SHA256(SHA256("rnstransport.path.request")[:10])[:16] = 6b9f66014d9853faab220fba47d02761`
- `dest_type = PLAIN`, `transport_type = BROADCAST`, `header_type = HEADER_1`, `context = CTX_NONE`
- payload (`RNS/Transport.py::request_path`):
  - **leaf clients** (transport disabled): `target_dest_hash(16) || random_tag(16)` — 32 bytes
  - **transport-enabled originators**: `target_dest_hash(16) || transport_id(16) || random_tag(16)` — 48 bytes — so the responding announce can be routed back along the request's reverse path

### 7.2 Responding to path requests

**Every node — including non-transport leaf clients — that knows the requested target MUST respond by re-announcing.** This is the only way the requester learns a path back. If you implement only the "send a path request" half but not the "respond to incoming requests for our own destination" half, peers can never message you after the path expires (typically within minutes after your last announce).

#### 7.2.1 Path-request packet parse rules

The path-request handler at `RNS/Transport.py:2800-2843` parses inbound packets addressed to `path_request_destination` (the dest_hash in §7.1). The handler is registered as the destination's `packet_callback` at `Transport.py:237-240`, so any DATA packet to that dest_hash flows through it.

```python
def path_request_handler(data, packet):
    if len(data) >= 16:
        destination_hash = data[:16]                                  # mandatory 16B target
        if len(data) > 32:
            requesting_transport_instance = data[16:32]               # optional 16B transport_id
        else:
            requesting_transport_instance = None

        # tag bytes — required, anything past the fixed prefix
        tag_bytes = data[32:] if len(data) > 32 else (data[16:] if len(data) > 16 else None)
        if tag_bytes is None:                                         # tagless requests are dropped
            return
        if len(tag_bytes) > 16:
            tag_bytes = tag_bytes[:16]                                # cap to 16B
```

Three observations that matter for interop:

1. **Tagless requests are dropped.** A path? packet with exactly 16 bytes payload (just `target_dest_hash`, no tag) is logged at DEBUG level and discarded. The tag is what makes the request unique enough to dedup — without it, a relay would loop forever on retransmits of the same packet. A clean-room implementation MUST emit at least one tag byte; the upstream emitter (`RNS.Transport.request_path`) uses 16 random bytes.
2. **The transport_id field is optional and detected by length.** If the payload is exactly 32 bytes the second 16B slot is the tag; if it's >32 bytes the second 16B is `transport_id` and the rest is the tag. This is consistent with the §7.1 description (leaf: 32B; transport: 48B) but the boundary case `len == 32` lands in the leaf-client interpretation.
3. **The tag is capped at 16 bytes.** Any tail beyond that is silently truncated. Senders may emit longer tags but receivers normalize to 16B for dedup table keys.

#### 7.2.2 Tag-based deduplication

The handler builds `unique_tag = destination_hash || tag_bytes` and consults `Transport.discovery_pr_tags` (`Transport.py:2829-2839`):

```python
unique_tag = destination_hash + tag_bytes

with Transport.discovery_pr_tags_lock:
    if not unique_tag in Transport.discovery_pr_tags:
        Transport.discovery_pr_tags.append(unique_tag)
        Transport.path_request(destination_hash,
                               from_local_client(packet),
                               packet.receiving_interface,
                               requestor_transport_id=requesting_transport_instance,
                               tag=tag_bytes)
    else:
        # ignore duplicate path request
```

`discovery_pr_tags` is bounded at `Transport.max_pr_tags = 32000` entries (`Transport.py:126`); older entries are aged out by the periodic `Transport.jobs` cycle. **Every node — leaf or transport — that wants to respond to path requests MUST maintain this dedup table** or it will respond to every retransmit, and a transport-enabled node will additionally re-forward to all other interfaces, generating a broadcast storm.

The `unique_tag = dest_hash || tag` format means the same tag bytes against different destination_hashes are distinct — so two different requesters racing for the same target with happenstance-identical random tags don't suppress each other. Senders MUST use a fresh random tag per fresh request (the upstream emitter calls `Identity.get_random_hash()`); reusing tags across requests for the same destination_hash makes the second request appear to be a duplicate.

#### 7.2.3 The five-way dispatch in `Transport.path_request`

`RNS/Transport.py:2846-2973`. After dedup, the handler calls into `path_request()` which decides how to respond. Five mutually-exclusive branches in priority order:

1. **`destination_hash` is local** (i.e. it's one of our own registered destinations, line 2873-2875):
   ```python
   local_destination.announce(path_response=True, tag=tag,
                              attached_interface=attached_interface)
   ```
   We answer by emitting a path-response announce (§7.2.4 below) on the interface the request arrived on. **This is the only branch a leaf client must implement** — the others are transport-mode behaviours.

2. **Path is known via the path_table AND `(transport_enabled OR is_from_local_client)`** (line 2877-2938): retrieve the cached announce packet from the path table, set its hops to the cached value, and queue it for retransmit. If the next hop happens to be the requestor itself (path-loop indicator), drop instead. This is the transport-mode path-resolver: a relay that already knows where the destination lives answers on its behalf, saving the requester from another hop of broadcast.

3. **Request is from a local-client interface, no path known** (line 2940-2947): forward the request to every OTHER interface so the broader mesh can answer. Generates a fresh random tag for the forwarded request to avoid loop-back through the same dedup table.

4. **`transport_enabled` AND no path known AND interface allows discovery** (line 2949-2963): record a `discovery_path_requests` entry (capped at `PATH_REQUEST_TIMEOUT = 15s`) and forward the request to every other interface, **preserving the original tag** to prevent loops. This is recursive transport-mode discovery — we don't know the destination but we'll go ask the rest of the mesh.

5. **No path known and not transport-enabled** (line 2972-2973): log "no path known" and drop. Leaf clients hit this branch when they receive a path? for someone else's destination.

Branch 1 is the only MUST for any node that wants to be reachable. Branches 2-4 are transport-node behaviours; a leaf client safely ignores them by never being in `transport_enabled` mode.

#### 7.2.4 Path-response announce wire format

When branch 1 fires, `Destination.announce(path_response=True, tag=tag, ...)` runs. The wire bytes are **identical to a regular announce (§4.1)** except the outer Reticulum packet's context byte is set to `PATH_RESPONSE = 0x0B` instead of `NONE = 0x00` (`RNS/Destination.py:307-308`):

```python
if path_response: announce_context = RNS.Packet.PATH_RESPONSE
else:             announce_context = RNS.Packet.NONE
```

The body — public_key || name_hash || random_hash || [ratchet_pub] || signature || app_data — is built identically; the random_hash carries a fresh emission timestamp, the signature is computed over the same signed_data per §4.2. A receiver running the validation flow in §4.5 can't tell from the announce body that this is a response to a query rather than a periodic re-announce; only the context byte distinguishes them.

A `tag` argument hands a previously-built path-response announce body back unchanged when the same tag is requested twice within `Destination.PR_TAG_WINDOW = 30s` (`RNS/Destination.py:260-278`). This is what prevents a flood of identical path-response announces when several relays simultaneously forward the same path? request to a leaf — the leaf serves the cached body to all of them with the same wire bytes, lining up dedup decisions on every transit relay.

#### 7.2.5 Timing: `PATH_REQUEST_GRACE` and roaming

When branch 2 fires (transit relay answering on behalf of a remote destination), the rebroadcast is delayed by `PATH_REQUEST_GRACE = 0.4s` (`Transport.py:80, 2917`) — extra grace to let directly-reachable peers respond first if they're in earshot. On `MODE_ROAMING` interfaces an additional `PATH_REQUEST_RG = 1.5s` is added on top (`Transport.py:81, 2922-2923`) so well-connected fixed nodes get a chance to answer before mobile ones.

Branch 1 (local destination answers) fires immediately with no grace, since the leaf is the authoritative source for its own destination — there's no point waiting for someone else to potentially answer faster.

Local-client originators also bypass the grace period (`Transport.py:2909-2910`): a relay answering for a destination that lives on a local-client interface can send back the cached announce instantly because the answer doesn't need to compete with peer-mesh announces.

#### 7.2.6 Minimum responsibility for a leaf

The minimum path-request response logic for a non-transport leaf, in protocol terms:

1. Receive a DATA packet with `dest_hash == 6b9f66014d9853faab220fba47d02761`.
2. Parse `target_dest_hash = data[:16]` and `tag_bytes = data[16:32]` (or `data[32:48]` if `len(data) > 32`).
3. Drop if `len(tag_bytes) == 0` (tagless requests).
4. Drop if `(target_dest_hash, tag_bytes)` already in the dedup table.
5. If `target_dest_hash == our_destination_hash` for any of our registered destinations: emit a path-response announce (§7.2.4) on the receiving interface, with the request's tag passed through to allow caching.
6. Otherwise: do nothing — leaves can't fulfill path requests for destinations they don't OWN.

Steps 4 and 5 are both required. Skipping the dedup table makes the leaf storm the network with redundant announces; skipping the local-destination check means peers can never message you after the path expires.

For a chronological walk-through of the full request → response → path-table cycle, see [`flows/path-discovery.md`](flows/path-discovery.md).

### 7.3 Ratchet rotation per announce

The 32-byte `ratchet_pub` field in announces is intended to rotate. Most transit nodes deduplicate announces on `(destination_hash, ratchet_pub)` tuples — if both are unchanged from a recent prior announce, the relay treats it as a duplicate and drops it instead of forwarding.

If your client generates one ratchet at identity creation and never rotates, every announce after the first one in a session is dropped at the first transit node. Your destination becomes invisible to the mesh.

**Required behavior:** generate a fresh X25519 keypair at the start of each `sendAnnounce()`, persist it (so subsequent sessions can decrypt messages still in flight to the previous ratchet — see also section 7.4), and use it for the announce body's `ratchet_pub` field.

The long-term encryption / signing keys and the `identity_hash` / `destination_hash` MUST stay stable across rotations. Otherwise contacts have to re-add you on every rotation.

### 7.4 Ratchet ring (inbound decrypt tolerance)

Senders cache the most recent ratchet they've seen for each destination. If you rotate your ratchet faster than relays propagate the announce, in-flight messages may arrive encrypted to your *previous* ratchet. To decrypt these, keep a ring of recent ratchet privkeys and try each in order during decrypt. The fallback to the long-term identity privkey is the ultimate safety net.

Upstream's default ring size is **`Destination.RATCHET_COUNT = 512`** (`RNS/Destination.py:85` in RNS 1.2.0), with a minimum rotation interval of `RATCHET_INTERVAL = 30*60` seconds (line 90) and per-ratchet `RATCHET_EXPIRY = 60*60*24*30` seconds (`RNS/Identity.py:69`). A new ratchet is generated on each `rotate_ratchets()` call and prepended to the in-memory list; `_clean_ratchets` truncates back to `RATCHET_COUNT`. The 512 figure is generous and not a hard interop requirement — it's an in-memory bound on the inbound-decrypt try-list.

A minimal client may keep just the current ratchet privkey, accepting that the brief window between rotation and announce-propagation will lose some messages. Mention the trade-off in your implementation notes.

### 7.5 Periodic re-announce

Transport node path tables expire entries after a few minutes. Clients should re-announce on a 5–15 minute cadence as a baseline so cached paths stay fresh. Without this, even peers who saw your initial announce will be unable to reach you after path TTLs lapse.

### 7.6 `TCPServerInterface.OUT` is True by default in practice

`RNS/Interfaces/TCPInterface.py` line 522 sets `self.OUT = False` in the constructor. This is overridden to `True` by `RNS/Reticulum.py` post-init at line 771-772 for any interface declared in the rnsd config:

```python
if "outgoing" in c and c.as_bool("outgoing") == False: interface.OUT = False
else:                                                  interface.OUT = True
```

Spawned client interfaces (one per connecting TCP client) inherit `OUT` from their parent. So in practice, every TCPServerInterface CAN forward unless the operator explicitly opted out. Do not waste time chasing the constructor's `OUT = False` default; it doesn't hold post-init.

### 7.7 Source

`RNS/Transport.py` `outbound`, `inbound`, `request_path`, `announce`. `RNS/Reticulum.py` `interface_post_init` for the OUT-flag override.

---

## 8. Transport framing

### 8.1 KISS (BLE / serial / RNode link)

```
FEND  = 0xC0    // frame delimiter
FESC  = 0xDB    // escape
TFEND = 0xDC    // escaped FEND  → 0xDB 0xDC
TFESC = 0xDD    // escaped FESC  → 0xDB 0xDD

frame = FEND || cmd_byte || escaped(data) || FEND
```

`cmd_byte` for received/transmitted Reticulum packets is `CMD_DATA = 0x00`. RNode firmware prefixes each received CMD_DATA frame with `CMD_STAT_RSSI = 0x23` (one byte payload, signed value = byte − 157) and `CMD_STAT_SNR = 0x24` (one byte payload, signed Q6.2 → divide by 4 for dB).

Over BLE, KISS frames are split across BLE notifications. A streaming parser MUST accumulate bytes across notifications and emit complete frames only on FEND boundaries.

### 8.2 HDLC (TCP / `rnsd TCPServerInterface`)

```
FLAG = 0x7E
ESC  = 0x7D
ESC_MASK = 0x20

frame = FLAG || escaped(data) || FLAG
escape: 0x7E → 0x7D 0x5E   (FLAG ^ ESC_MASK)
        0x7D → 0x7D 0x5D   (ESC  ^ ESC_MASK)
```

No command byte, no RSSI/SNR sidecar — the HDLC payload IS the raw Reticulum packet. Source: `RNS/Interfaces/TCPInterface.py::HDLC`.

### 8.3 RNode air-frame header and split-packet protocol

The 1-byte header described here lives **between RNodes on the LoRa air-frame**, not on the KISS host channel. The upstream RNode firmware adds it on every TX and strips it on every RX before forwarding the payload to the host as `CMD_DATA`. KISS hosts (RNS, NomadNet, Sideband, etc.) NEVER see this byte. Two RNodes that talk LoRa to each other use it to glue two LoRa frames into one Reticulum packet of up to 508 bytes; an alternative implementation that talks LoRa to an RNode (e.g. a clean-room repeater firmware) MUST construct and parse this header bit-exactly, or its TX will be invisible and its RX will mistake the header byte for the first payload byte.

#### Header byte layout

From `markqvist/RNode_Firmware/Framing.h:105-108`:

```
bit 7..4 : seq         (NIBBLE_SEQ   = 0xF0) — random sequence id, set on each TX
bit 3..1 : reserved    (currently always 0)
bit 0    : FLAG_SPLIT  (NIBBLE_FLAGS = 0x0F, FLAG_SPLIT = 0x01)
SEQ_UNSET = 0xFF                            — sentinel: "no first half buffered"
```

Helpers (`Utilities.h:1218-1224`):

```c
inline bool    isSplitPacket(uint8_t h) { return (h & FLAG_SPLIT); }   // 0x01 mask
inline uint8_t packetSequence(uint8_t h){ return h >> 4; }             // 0..15
```

Constants (`Config.h:59-61`):

```c
#define MTU         508    // max reassembled Reticulum packet payload (2 × 254)
#define SINGLE_MTU  255    // max LoRa frame size (header + up to 254 payload bytes)
#define HEADER_L    1      // header overhead per LoRa frame
```

#### Transmit (`RNode_Firmware.ino:716-742`)

```c
uint8_t header = random(256) & 0xF0;                      // fresh random seq nibble
if (size > SINGLE_MTU - HEADER_L) header |= FLAG_SPLIT;   // split iff payload > 254
LoRa->beginPacket();
LoRa->write(header);
for (i=0; i < size; i++) {
    LoRa->write(tbuf[i]);
    if (written == 255 && isSplitPacket(header)) {        // first frame full
        LoRa->endPacket();
        LoRa->beginPacket();
        LoRa->write(header);                              // SAME header byte on frame 2
        written = 1;
    }
}
LoRa->endPacket();
```

Behavioral facts that matter for interop:

1. **Sequence nibble is randomized on every fresh TX**, not incremented. Two consecutive split packets from the same node will have different (random) seq nibbles. This is the trick a memory-fading reader might recall as "the header rotates between transmissions" — it's per-packet randomization, not a per-retransmit byte rotation. There is no retransmit-driven byte rotation or rechunk; LoRa transmission is fire-and-forget at this layer, and a higher-layer retransmit (e.g. an RNS PROOF timeout firing again) just re-enters this function and gets a fresh random seq nibble.
2. **Both frames of a split share the same header byte byte-for-byte** — same seq nibble, same FLAG_SPLIT bit. The receiver pairs them by exact equality of the seq nibble.
3. **The split point is at exactly 255 bytes total in the LoRa frame** (1 header + 254 payload). The second frame is `header || remainder`, where `remainder` is whatever is left after 254 bytes of payload have been emitted. Maximum reassembled packet payload is `2 × 254 = 508` bytes — Reticulum's `HW_MTU` for the RNode interface is set to match.
4. **Single-frame packets (payload ≤ 254)** still carry the 1-byte header but with `FLAG_SPLIT == 0`. The seq nibble is still random per TX.

#### Receive / reassembly (`RNode_Firmware.ino:359-446`)

State on the receiver: `seq` (default `SEQ_UNSET = 0xFF`) tracks the seq nibble of any buffered first-half. Per inbound LoRa frame:

| Inbound `FLAG_SPLIT` | Buffered `seq` state | Inbound seq | Action |
|---|---|---|---|
| 1 | `SEQ_UNSET` (none) | any | Buffer this frame as the first half. Store its seq. |
| 1 | matches inbound seq | == buffered | Append. **Reassembly complete**. Reset buffer. |
| 1 | doesn't match | != buffered | Discard buffered first-half. Replace with this frame as a new first-half. |
| 0 | `SEQ_UNSET` (none) | n/a | Deliver this single-frame packet directly. |
| 0 | first-half present | n/a | Discard the buffered first-half; deliver this single-frame packet. |

In other words: the receiver holds **at most one** in-progress first-half, keyed by its random seq nibble. Any inbound frame that doesn't match (different seq, or non-split, or simply a long enough silence) replaces or discards it.

#### Reassembly timeout — implementation-defined

Upstream RNode firmware does **not** have an explicit time-based timeout for a buffered first-half — it relies on subsequent traffic (any inbound frame) to clear stale state via the table above. The clean-room repeater at `thatSFguy/reticulum-lora-repeater/src/Radio.cpp:189-194` adds a defensive **500 ms** timeout: if no second half arrives within that window, the buffered first-half is discarded. This is implementation-private: a packet that takes longer than 500 ms to fully transmit (very low SF + large payload) would be lost on a repeater following the clean-room timeout but would survive against an unbounded upstream RNode receiver as long as no other LoRa traffic landed in between.

A new alternative implementation should either match upstream's "no explicit timeout" or pick a value tied to the worst-case airtime of two `SINGLE_MTU` frames at the configured SF/BW, not a flat 500 ms.

#### Sequence-collision airtime ceiling

Because the seq nibble is 4 bits of randomness chosen per TX, two unrelated split packets from the same sender that overlap in time at any receiver will collide with probability 1/16 per pair. At sane LoRa duty cycles this is a non-issue, but it bounds the protocol — a sender that emits split packets back-to-back faster than the air can ferry them risks a reassembled packet that mixes halves of two distinct senders' outputs. The receiver has no way to detect this short of validating the resulting Reticulum packet (which a corrupt mix would fail at the HMAC step). Don't burst.

#### Source map

| File | What it pins down |
|---|---|
| `RNode_Firmware/Framing.h:105-108` | `NIBBLE_SEQ`, `NIBBLE_FLAGS`, `FLAG_SPLIT`, `SEQ_UNSET` constants |
| `RNode_Firmware/Config.h:59-61` | `MTU`, `SINGLE_MTU`, `HEADER_L` |
| `RNode_Firmware/Utilities.h:1218-1224` | `isSplitPacket`, `packetSequence` accessors |
| `RNode_Firmware/RNode_Firmware.ino:716-742` | TX-side header construction and split logic |
| `RNode_Firmware/RNode_Firmware.ino:359-446` | RX-side reassembly state machine |
| `reticulum-lora-repeater/src/Radio.cpp:35-45, 188-316, 351-405` | Clean-room reimplementation; adds 500 ms reassembly timeout |

### 8.4 RNode KISS configuration handshake

§8.1 covers the KISS framing between a host and an RNode. This section covers the **commands** a host issues over that framing to bring up an RNode and configure its radio. Before any Reticulum DATA packet can flow, every command listed here must succeed in approximately the order listed.

The canonical reference is `RNS/Interfaces/RNodeInterface.py` (the Python host driver) plus `RNode_Firmware/Framing.h` (the firmware-side command codes).

#### 8.4.1 Command-byte inventory

Each KISS frame is `FEND || cmd_byte || escaped_payload || FEND` (§8.1). The cmd_byte values used during configuration:

| Hex | Name | Direction | Purpose |
|---|---|---|---|
| `0x00` | `CMD_DATA` | both | Reticulum packet payload (the steady-state command after configuration is done) |
| `0x01` | `CMD_FREQUENCY` | host → RNode | Set radio frequency in Hz; payload is 4-byte big-endian uint32 |
| `0x02` | `CMD_BANDWIDTH` | host → RNode | Set radio bandwidth in Hz; payload is 4-byte big-endian uint32 |
| `0x03` | `CMD_TXPOWER` | host → RNode | Set TX power in dBm; payload is 1 byte |
| `0x04` | `CMD_SF` | host → RNode | Set spreading factor; payload is 1 byte (typically 7..12) |
| `0x05` | `CMD_CR` | host → RNode | Set coding rate denominator; payload is 1 byte (typically 5..8 for `4/5`..`4/8`) |
| `0x06` | `CMD_RADIO_STATE` | host → RNode | `0x00 = OFF`, `0x01 = ON` (turn the modem on after config) |
| `0x07` | `CMD_RADIO_LOCK` | host → RNode | Lock the radio against further config changes |
| `0x08` | `CMD_DETECT` | both | Hardware detect ping/pong (see §8.4.3 below) |
| `0x09` | `CMD_IMPLICIT` | host → RNode | Toggle implicit-header LoRa mode (advanced) |
| `0x0A` | `CMD_LEAVE` | host → RNode | Tell the RNode the host is disconnecting; payload `0xFF` |
| `0x0B` | `CMD_ST_ALOCK` | host → RNode | Short-term airtime limit; payload is 2 bytes big-endian uint16 of (limit × 100) |
| `0x0C` | `CMD_LT_ALOCK` | host → RNode | Long-term airtime limit; same encoding as ST_ALOCK |
| `0x0F` | `CMD_READY` | RNode → host | Boot complete signal |
| `0x21` | `CMD_STAT_RX` | RNode → host | RX-counter status |
| `0x22` | `CMD_STAT_TX` | RNode → host | TX-counter status |
| `0x23` | `CMD_STAT_RSSI` | RNode → host | RSSI sidecar for the next CMD_DATA frame; `dBm = byte − 157` |
| `0x24` | `CMD_STAT_SNR` | RNode → host | SNR sidecar; signed Q6.2 → `dB = byte / 4` |
| `0x26` | `CMD_STAT_PHYPRM` | RNode → host | Reports current frequency/bandwidth/SF/CR back; used for verification |
| `0x40` | `CMD_RANDOM` | both | Get random bytes from the RNode's hardware RNG |
| `0x47` | `CMD_BOARD` | RNode → host | Reports board model code |
| `0x48` | `CMD_PLATFORM` | RNode → host | Reports MCU platform code |
| `0x49` | `CMD_MCU` | RNode → host | Reports MCU variant code |
| `0x50` | `CMD_FW_VERSION` | RNode → host | Reports firmware version (2 bytes: major, minor) |
| `0x55` | `CMD_RESET` | host → RNode | Hard-reset the RNode; payload `0xF8` (`CMD_RESET_BYTE`) |

Full inventory in `RNode_Firmware/Framing.h:24-95`. The configuration handshake uses the bolded subset.

#### 8.4.2 Bring-up sequence

Adapted from `RNodeInterface.initRadio` (`RNS/Interfaces/RNodeInterface.py:470-481`):

```
1. Open serial port (or BLE GATT, or whatever bearer)
2. Optionally: hard_reset()           — CMD_RESET 0xF8 (2.25s wait afterwards)
3. detect()                            — CMD_DETECT + CMD_FW_VERSION + CMD_PLATFORM + CMD_MCU
4. (RNode replies asynchronously with CMD_DETECT 0x46, CMD_FW_VERSION, CMD_PLATFORM,
    CMD_MCU, CMD_BOARD over multiple frames — host correlates by command byte)
5. setFrequency()                      — CMD_FREQUENCY + 4B big-endian Hz
6. setBandwidth()                      — CMD_BANDWIDTH + 4B big-endian Hz
7. setTXPower()                        — CMD_TXPOWER + 1B dBm
8. setSpreadingFactor()                — CMD_SF + 1B
9. setCodingRate()                     — CMD_CR + 1B
10. setSTALock() / setLTALock()        — optional airtime limits
11. setRadioState(RADIO_STATE_ON)      — CMD_RADIO_STATE + 0x01
12. (RNode now in operational state; CMD_DATA frames flow in both directions)
```

The order matters: most firmwares accept config commands only while the radio is OFF (steps 5-10 must precede step 11). Setting parameters after `RADIO_STATE_ON` either silently fails or requires a `RADIO_STATE_OFF` round-trip first depending on firmware version. A clean-room driver should always set the radio OFF (or be in initial-boot state where it's OFF by default) before reconfiguring.

#### 8.4.3 The `CMD_DETECT` exchange

```
host → RNode :  FEND CMD_DETECT(0x08) DETECT_REQ(0x73) FEND
RNode → host :  FEND CMD_DETECT(0x08) DETECT_RESP(0x46) FEND
```

`DETECT_REQ = 0x73` and `DETECT_RESP = 0x46` are at `RNode_Firmware/Framing.h:99-100`. The two-byte exchange tells a host "yes, this thing on the other end of the serial port is an RNode and it's awake". The host follows up immediately with `CMD_FW_VERSION`, `CMD_PLATFORM`, `CMD_MCU` queries — those queries each have a single `0x00` placeholder byte payload (per `RNodeInterface.detect()` line 484) and the RNode replies asynchronously with the same command code carrying the actual answer.

A host driver should accumulate replies for ~1-2 seconds after sending `detect()` before assuming detection failed. The replies arrive in unpredictable order because the firmware fires them off as it produces each value.

`CMD_FW_VERSION`'s payload format is 2 bytes: `[major, minor]`. RNS rejects RNode firmware older than its `REQUIRED_FW_VER_MAJ` / `REQUIRED_FW_VER_MIN` constants and aborts the bring-up. A clean-room driver should at minimum log the version for diagnostics.

#### 8.4.4 4-byte big-endian numerics

`CMD_FREQUENCY` and `CMD_BANDWIDTH` payloads are unsigned 32-bit integers in big-endian byte order:

```python
c1 = self.frequency >> 24
c2 = self.frequency >> 16 & 0xFF
c3 = self.frequency >> 8  & 0xFF
c4 = self.frequency       & 0xFF
data = KISS.escape(bytes([c1, c2, c3, c4]))
```

The byte values are KISS-escaped before transmission per §8.1 (e.g. a frequency of `0xC0...` would have its leading `0xC0` byte escaped to `0xDB 0xDC`).

`CMD_TXPOWER`, `CMD_SF`, `CMD_CR`, `CMD_RADIO_STATE` payloads are single bytes, also subject to KISS escaping.

#### 8.4.5 Receive sidecar metadata

Every CMD_DATA frame from the RNode is preceded by two short metadata frames in the same byte stream (§8.1 already mentions this; the encoding):

```
FEND CMD_STAT_RSSI(0x23) <rssi_byte>  FEND
FEND CMD_STAT_SNR(0x24)  <snr_byte>   FEND
FEND CMD_DATA(0x00)      <data...>    FEND
```

Decode:

- `RSSI in dBm = rssi_byte - 157` (e.g. `rssi_byte = 50` means `-107 dBm`).
- `SNR in dB = (signed)snr_byte / 4` — `snr_byte` is interpreted as signed two's-complement Q6.2 fixed-point. So `0x10 (16) = 4 dB`, `0xF0 (-16) = -4 dB`, etc.

A host driver must cache the most recent RSSI/SNR pair and apply it to the next CMD_DATA frame. If it processes CMD_DATA before the sidecars arrive (e.g. the byte stream re-ordered them across an unreliable link), RSSI/SNR will be from the *previous* packet. In practice the firmware emits them in a tight sequence within microseconds, so reordering is only a concern over BLE notification boundaries (§8.1 closing paragraph).

### 8.5 RNode CSMA / airtime accounting

Real LoRa networks need carrier-sense and airtime budgets to avoid stepping on each other. The RNode firmware implements both server-side; the host is mostly told what's happening via `CMD_STAT_CHTM` (channel-time-metric, `0x25` in `Framing.h:45`) and chooses whether to inform the application.

#### 8.5.1 Airtime caps (`CMD_ST_ALOCK` / `CMD_LT_ALOCK`)

The host can set per-channel airtime limits via:

- **`CMD_ST_ALOCK`** (`0x0B`): short-term airtime lock. Payload is 2 bytes big-endian uint16 of `(limit_percent × 100)` — so `0x0B B8 = 3000 = 30.00%`. Default in `RNS/Reticulum.py` is `Reticulum.ANNOUNCE_CAP = 2.0` (= 2% airtime cap on transmissions, encoded as `0x00C8`).
- **`CMD_LT_ALOCK`** (`0x0C`): long-term version, same encoding. Long-term window length is firmware-private (typically 1 hour).

Once the cap is exceeded the firmware simply refuses to transmit and reports `CMD_ERROR ERROR_QUEUE_FULL (0x04)` if the host queues additional packets. A clean-room driver should treat these errors as backpressure and queue at the application layer rather than retry-spinning at the KISS layer.

#### 8.5.2 Pre-TX carrier sense

Before transmitting, RNode firmware listens on the configured frequency for a short window and aborts the TX if it detects an in-progress LoRa preamble — Listen-Before-Talk. The exact CSMA windowing is firmware-private; a clean-room implementation that talks LoRa via RadioLib (rather than via an RNode) needs to implement its own LBT to avoid stepping on RNodes and other peers. The reference implementation in `markqvist/RNode_Firmware/RNode_Firmware.ino:683-712` (the `add_airtime` accumulator and channel-utilisation tracking) is the canonical algorithm.

For host-side use cases — i.e. a Reticulum client driving an RNode — the firmware handles all CSMA invisibly and the host should not attempt its own. Host-side rate limiting at the announce-cap layer (§4.5 SHOULD-rule for ingress, and `Reticulum.ANNOUNCE_CAP` for outbound) is sufficient.

### 8.6 AutoInterface multicast discovery (LAN auto-detect)

`AutoInterface` is the IPv6-multicast-based protocol Reticulum nodes use to discover each other on a LAN with zero configuration. Drop a node on any IPv6-capable network, configure `[[Default Interface]] type = AutoInterface`, and it finds peers automatically — no static IPs, no rendezvous server.

The reference implementation is `RNS/Interfaces/AutoInterface.py` (~700 lines). This section specifies the wire-visible bits a clean-room implementation needs.

#### 8.6.1 IPv6 multicast group derivation

`AutoInterface.py:202-212`. Each AutoInterface mesh is identified by a `group_id` (default `b"reticulum"`); the actual multicast address is derived from a SHA-256 of the group_id:

```python
group_hash = SHA256(group_id)                     # 32 bytes

# Build the lower 7 hextets from group_hash bytes [2..14]:
gt  = "0"
gt += ":" + f"{(g[3]+(g[2]<<8)):02x}"            # bytes [2:4]
gt += ":" + f"{(g[5]+(g[4]<<8)):02x}"            # bytes [4:6]
gt += ":" + f"{(g[7]+(g[6]<<8)):02x}"            # bytes [6:8]
gt += ":" + f"{(g[9]+(g[8]<<8)):02x}"            # bytes [8:10]
gt += ":" + f"{(g[11]+(g[10]<<8)):02x}"          # bytes [10:12]
gt += ":" + f"{(g[13]+(g[12]<<8)):02x}"          # bytes [12:14]

mcast_discovery_address = "ff" + multicast_address_type + discovery_scope + ":" + gt
```

Where:

| Field | Default | Value bits |
|---|---|---|
| `multicast_address_type` | `"1"` (temporary) — alt `"0"` (permanent) | 4 bits, `RFC 4291` flags |
| `discovery_scope` | `"2"` (link-local) | 4 bits, IPv6 scope: `"2"=link, "4"=admin, "5"=site, "8"=org, "e"=global` |

So with the default `group_id = b"reticulum"`, default `multicast_address_type = "1"`, default `discovery_scope = "2"`, and `SHA256(b"reticulum")[2:14]` filling the lower hextets, every default-config Reticulum node on the same link-local subnet finds the same multicast address.

#### 8.6.2 UDP ports

`AutoInterface.py:47-48`:

| Port | Default | Use |
|---|---|---|
| `discovery_port` | `29716` (UDP) | Periodic discovery announces from each peer; receivers learn other peers' link-local IPv6 addresses by their incoming source addr. |
| `unicast_discovery_port` | `discovery_port + 1` = `29717` | Per-interface unicast probes, used to disambiguate which physical interface a peer is on. |
| `data_port` | `42671` (UDP) | Once peers know each other's addresses, actual Reticulum packets flow as plain UDP datagrams between them on this port. |

A clean-room implementation MUST listen on the discovery port for inbound multicast packets and the data port for inbound unicast packets, and emit periodic announces to the multicast address+port.

#### 8.6.3 Discovery cadence

`AutoInterface.py:61-64`:

| Constant | Value | Meaning |
|---|---|---|
| `ANNOUNCE_INTERVAL` | `1.6s` | Each AutoInterface emits a discovery announce on this cadence. |
| `PEERING_TIMEOUT` | `22.0s` | A peer not heard from within this window is dropped. |
| `PEER_JOB_INTERVAL` | `4.0s` | Cadence of the per-interface peer-management job (eviction, rediscovery). |
| `MCAST_ECHO_TIMEOUT` | `6.5s` | If our own multicast emissions are not echoed back within this window on a given physical interface, the multicast routing on that interface is presumed broken. |

The 1.6s + 22s pairing means a new node is discovered within ~1.6s of join (as soon as one announce cycle completes from any existing peer); a departing node is forgotten within ~22s of last contact. Both bounds are implementation-private, but a clean-room with radically different values may have visible interop quirks (peer flap if you announce too rarely; bandwidth waste if too often).

#### 8.6.4 Discovery announce body format

The discovery announce is a plain UDP datagram on the multicast address. The body is implementation-private — upstream uses a small msgpack blob containing the peer's `group_hash` (so peers from a different group on the same link don't accidentally peer), interface MTU, and an optional IFAC seal (Interface Authentication Code; if present, peers without the matching IFAC key reject the announce). Specific bytes of the discovery announce body aren't part of the wire spec for **Reticulum**; they're part of the wire spec for **AutoInterface peering**, and a clean-room AutoInterface implementation needs to mirror upstream's format. Read `AutoInterface.py::announce_handler` and `AutoInterface.peer_jobs` for the full layout.

#### 8.6.5 Once peers are discovered

After the discovery handshake establishes that two nodes are in the same Reticulum group on the same physical link, all subsequent Reticulum packet traffic flows as **plain UDP datagrams** on the data port (`42671` by default), unicast between the discovered link-local IPv6 addresses. There's no per-packet framing beyond the UDP envelope — each datagram body is one complete Reticulum packet (§2). Out-of-order delivery is handled by Reticulum's normal dedup and (where present) Link sequencing; UDP packet loss is masked by Reticulum's PROOF receipts and Resource sliding-window retransmits.

Effective HW_MTU is `1196` bytes (`AutoInterface.HW_MTU`, line 44) — chosen to fit comfortably within standard Ethernet MTU minus IPv6/UDP overhead.

#### 8.6.6 IFAC integration

If the AutoInterface is configured with an `ifac_identity` (out-of-band-shared key), every Reticulum packet on the data port is IFAC-sealed and unmasked using the standard Transport-level IFAC mechanism (`RNS/Transport.py:1338-1387`). Peers with mismatched IFAC keys can see each other's discovery announces but can't decode each other's data — a pragmatic privacy boundary on a shared LAN.

#### 8.6.7 Source map

| File | What |
|---|---|
| `RNS/Interfaces/AutoInterface.py:43-72` | Default ports, group_id, scope/address-type constants, intervals |
| `RNS/Interfaces/AutoInterface.py:202-212` | Multicast address derivation from `SHA256(group_id)` |
| `RNS/Interfaces/AutoInterface.py:108+` | Per-interface socket setup (multicast join, unicast bind) |
| `RNS/Interfaces/AutoInterface.py::announce_handler` | Discovery announce emission |
| `RNS/Interfaces/AutoInterface.py::peer_jobs` | Peer aging, multicast-echo loop, IFAC sealing |

---

## 9. Implementation gotchas

The findings here cost the most debugging hours per insight ratio. They're not in the upstream manual.

### 9.1 LXMF `source_hash` is the destination hash, not the identity hash

The 16-byte `source_hash` field in an LXMF body is the sender's destination hash (`SHA256(name_hash || identity_hash)[:16]`), NOT the raw 16-byte identity hash. Sending the identity hash here means the recipient can't look you up in their contacts (which are keyed by destination hash) and the conversation gets orphaned.

### 9.2 Web Crypto and JCA AES-CBC auto-pad PKCS#7 — do not pad manually

Both browser `window.crypto.subtle.encrypt({name:"AES-CBC", iv}, key, plaintext)` and JCA's `Cipher.getInstance("AES/CBC/PKCS5Padding")` apply PKCS#7 padding automatically. Manually padding before calling them produces double-padded ciphertext (16 garbage bytes added) that decrypts to plaintext + a trailing PKCS#7 block which the receiver can't strip cleanly.

### 9.3 RNS bundles `umsgpack` — encode display names as `bytes`, not `str`

`RNS/vendor/umsgpack.py` is locked to behaviors regardless of system msgpack:

- `_pack_string` (Python `str`) → `0xa0|len`/`0xd9`/`0xda`/`0xdb` (fixstr/str8/str16/str32)
- `_pack_binary` (Python `bytes`) → `0xc4`/`0xc5`/`0xc6` (bin8/bin16/bin32)
- `_unpack_string` decodes to Python `str` via `bytes.decode("utf-8")`
- `_unpack_binary` returns raw Python `bytes`

The downstream parser at `LXMF/LXMF.py:131` does `dn.decode("utf-8")` on the unpacked first element. This works only when `dn` is `bytes`. If a producer wrote a `str`-encoded name (fixstr), umsgpack returns Python `str`, `.decode()` raises `AttributeError`, the parser swallows it and returns `None` → no display name.

**Implementation rule:** encode the display name field as msgpack `bin` (Python `bytes` equivalent), never `str`. Upstream LXMRouter does this correctly via `display_name.encode("utf-8")` before packing.

### 9.4 Display name preservation across re-announces

Inbound announce ingestion code that uses

```
new_name = extracted ?? known_label ?? ""
merged   = (new_name).ifBlank { existing.name ?? "" }
```

clobbers a real cached name with the placeholder `known_label` (e.g. "LXMF delivery") whenever a minimal re-announce arrives without `app_data`. The next full announce restores it. Symptom: contacts blink to placeholder names briefly during/after activity.

Correct priority order: `extracted ?? existing ?? known_label ?? ""`. The known label fallback is for completely unknown destinations only.

### 9.5 Self-announce echo

If the operator runs both an originating client and a transport node on the same machine (or the same RNode loops back its own emissions), a client will receive its own announce and may add itself to the contact list. Filter announces whose `dest_hash == our_dest_hash` before ingestion.

### 9.6 Clockless sender timestamps

LoRa devices without an RTC will populate the LXMF `timestamp` field with seconds-since-boot (small integers like 30, 90720). Treat any timestamp before 2020-01-01 (`1577836800`) as "no clock" and substitute the local receive time. Otherwise messages from clockless devices appear at January 1 1970 in the inbox.

### 9.7 Periodic re-announce is non-optional

Even after a successful initial announce, paths in the mesh expire within minutes. Without a 5–15 minute re-announce loop, the second message any peer tries to send you will fail because the relay's path table has aged out. (See also §7.5.)

### 9.8 The destination hash uses the bare app-name string

An earlier-vintage bug in several implementations was to include the identity's hex hash in the `name_hash` input. `expand_name` in upstream Python takes an `identity` parameter and conditionally appends the identity hex IF the identity is non-None — but the Destination construction path passes `identity = None`. The `name_hash` MUST be `SHA256(plain_app_name_string)[:10]`, nothing more. (See also §1.2.)

### 9.9 Diagnostic: rx-log every inbound packet at the engine entry

A single line of the form

```
rx <size>B H<1|2> <PT> dest=<hex> ctx=0x<hex> hops=<n>
```

logged before any filtering converts hours of "messages aren't arriving" debugging to seconds. Without it, packets dropped by `if (dest != ours) return` vanish silently and look identical to "the bytes never arrived". Symmetric `tx` logging on outbound is similarly cheap insurance.

### 9.10 microReticulum `random_hash` lacks the timestamp half

Real interop bug to plan around: `attermann/microReticulum`'s `Destination::announce` emits 10 fully-random bytes for the announce `random_hash` field rather than the upstream Python form of `5 random bytes || big-endian uint40 unix_seconds` (see §4.1). The Python form is preserved as a comment in the C++ source with a `TODO add in time to random hash` next to it; the timestamp half was never implemented.

Effect on a mixed-vendor mesh: a Python RNS receiver parses `random_hash[5:10]` of a microReticulum announce as a far-future timestamp (median ~year 19403 AD because the random uint40 is uniformly distributed across `0..2^40-1`). The path-table replacement rule at `RNS/Transport.py:1721-1745` rejects subsequent real-timestamped announces from Python sources as "stale" until the path TTL expires.

Symptom: a microReticulum repeater works fine when it's the only path; in a mesh that also has Python relays, paths "stick" to the microReticulum side even when shorter / fresher Python paths come up, until natural TTL expiry. First-contact path-table population is unaffected — the bug only surfaces on path replacement.

Workarounds when building a clean-room implementation that talks to a microReticulum mesh:
- Emit the upstream form yourself (you have a clock — even seconds-since-boot is preferable to random bytes; the path-table comparison only cares about ordering, not absolute time).
- If you receive a uint40 timestamp that's more than, say, 24 hours in the future, treat it as suspect — but be cautious because legitimate Python senders with skewed clocks could trip this.

The repeater repo's `pre_build.py` patches several other microReticulum protocol bugs (ratchet announce parsing, identity hash length 16→32, DATA/PROOF forwarding) but does not patch this one. Filing an upstream issue against `attermann/microReticulum` to land the original Python timestamp form is the durable fix.

---

## 10. Resource fragmentation protocol

A **Resource** transfers a payload that exceeds the per-packet content limit of an established Reticulum Link. It is the only way to carry an LXMF body, NomadNet page, or file larger than ~360 bytes (`LINK_PACKET_MAX_CONTENT`) over a Link. Resource is built **on top of** an active Link — it relies on the Link's session key for encryption (§3.1 link-derived form) and on the Link's bidirectional DATA channel for control traffic.

The complete reference is `RNS/Resource.py` (1383 lines in RNS 1.2.0); `RNS/Packet.py:72-78` defines the context constants. This section describes the wire-level invariants a clean-room implementation must respect; many implementation choices (window sizing heuristics, watchdog timers, EIFR computation) are private and listed only when their absence would cause an interop break.

### 10.1 When Resource runs

Three triggers in upstream:

1. **`LXMessage.send()` for `DIRECT` method with `representation == RESOURCE`.** Set automatically when the encrypted-form LXMF body exceeds `LINK_PACKET_MAX_CONTENT` (`LXMF/LXMessage.py:415-421`).
2. **NomadNet page request fulfillment** — a server returning a page whose body exceeds the link MTU.
3. **Direct file transfers** via `rncp` and similar utilities.

### 10.2 Initiator-side preparation

Given input data and an `RNS.Link` in `ACTIVE` state (`RNS/Resource.py:248-478`):

1. **Optional metadata prefix.** If the caller supplied a `metadata` dict, msgpack-pack it and prepend `length(3 bytes, big-endian uint24) || packed_metadata` to the body. The `has_metadata` (`x`) flag in the advertisement signals this. Receivers strip the prefix during reassembly (line 699-707).
2. **Optional bz2 compression.** If `auto_compress` is true and the data fits within `auto_compress_limit` (default 64 MiB), the body is bz2-compressed and the `compressed` (`c`) flag is set. If compression doesn't shrink the data, the uncompressed form is sent and `c` is cleared.
3. **Random hash prefix.** A 4-byte (`Resource.RANDOM_HASH_SIZE`) random hash is prepended to the (compressed-or-not) body. This is the `r` field in the advertisement and is part of the input to `hash` and `expected_proof`.
4. **Link encryption.** The full `random_hash || (compressed?) data` blob is encrypted using `link.encrypt(...)` — i.e. the link-derived Token form (§3.1), no ephemeral_pub prefix. The `encrypted` (`e`) flag is set.
5. **Hash and proof material.**
   - `data_with_random = random_hash || (compressed?) plaintext`
   - `hash = SHA256(data_with_random || random_hash)` (32 bytes)
   - `truncated_hash = hash[:16]`
   - `expected_proof = SHA256(data_with_random || hash)` (32 bytes) — what the receiver will eventually return in the RESOURCE_PRF packet.
6. **Part split.** The encrypted body is sliced into parts of size `SDU = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE`. Each part becomes a packed `RNS.Packet(link, part_data, context=RESOURCE)`; the packed wire bytes are stored in `parts[i]` for later sending.
7. **Hashmap.** Each part is fingerprinted to `MAPHASH_LEN = 4 bytes`. The full hashmap is `b"".join(map_hashes)`. **Hash collisions within the COLLISION_GUARD_SIZE = 2 × WINDOW_MAX + HASHMAP_MAX_LEN window are detected at construction time** — if two parts hash to the same 4-byte map_hash within that window, the random hash is regenerated and the whole hashmap is recomputed. Without this guard, the receiver can't disambiguate which part it just received from a part-request that named a colliding map_hash.

After preparation: `total_parts = ceil(size / SDU)`; `total_size` includes metadata; `total_segments = ceil(total_size / MAX_EFFICIENT_SIZE)` where `MAX_EFFICIENT_SIZE = 1 MiB - 1 = 1_048_575`.

### 10.3 Wire packet contexts used during a Resource transfer

All of these are sent on the established Link and use the Link's session key for encryption (or are unencrypted PROOF-type, depending on context):

| Context | Direction | Type | Body |
|---|---|---|---|
| `RESOURCE_ADV (0x02)` | initiator → receiver | DATA | msgpack dict (§10.4) |
| `RESOURCE (0x01)` | initiator → receiver | DATA | one part of the encrypted body, raw |
| `RESOURCE_REQ (0x03)` | receiver → initiator | DATA | request bytes (§10.5) |
| `RESOURCE_HMU (0x04)` | initiator → receiver | DATA | hashmap continuation (§10.7) |
| `RESOURCE_PRF (0x05)` | receiver → initiator | PROOF | `resource_hash(32) || full_proof(32)` |
| `RESOURCE_ICL (0x06)` | initiator → receiver | DATA | resource_hash(32) — initiator cancel |
| `RESOURCE_RCL (0x07)` | receiver → initiator | DATA | resource_hash(32) — receiver reject/cancel |

### 10.4 RESOURCE_ADV — the advertisement

The first packet in the transfer. Body is `umsgpack.packb(dict)` with these keys (`RNS/Resource.py:1336-1358`):

| Key | Type | Meaning |
|---|---|---|
| `t` | int | **Transfer size** — encrypted byte length on the wire |
| `d` | int | **Data size** — original uncompressed plaintext byte length |
| `n` | int | **Number of parts** in this segment |
| `h` | bytes(32) | **Resource hash** — `SHA256(data || random_hash)` |
| `r` | bytes(4) | **Random hash** prefix |
| `o` | bytes(32) | **Original hash** of the first segment (= `h` if single-segment) |
| `i` | int | **Segment index** (1-based) |
| `l` | int | **Total segments** |
| `q` | bytes(?) or None | **Request id** if this Resource carries the response to a Link REQUEST |
| `f` | int | **Flags byte** (see below) |
| `m` | bytes | **Hashmap fragment** for THIS advertisement segment — up to `HASHMAP_MAX_LEN = ⌊(LINK_MDU - 134)/4⌋` 4-byte map_hashes |

The flags byte `f` packs six booleans (`Resource.py:1310, 1377-1382`):

```
bit 0 : e — encrypted
bit 1 : c — compressed
bit 2 : s — split (multi-segment)
bit 3 : u — is_request (this Resource is the body of a Link REQUEST)
bit 4 : p — is_response (this Resource is the body of a Link RESPONSE)
bit 5 : x — has_metadata
```

`HASHMAP_MAX_LEN` matters: the entire hashmap may not fit in one ADV. If `n > HASHMAP_MAX_LEN`, the receiver reconstructs subsequent map segments via RESOURCE_HMU packets after exhausting the first slice (§10.7).

The advertisement is sent once on `Resource.advertise()`; if no part requests arrive within the watchdog timeout, it is retransmitted up to `MAX_ADV_RETRIES = 4` times before the resource is cancelled (`Resource.py:573-590`).

### 10.5 RESOURCE_REQ — receiver requests parts

Sent by the receiver to ask for a window's worth of specific parts (`Resource.py:934-983`). Body layout:

```
hashmap_exhausted_flag(1)  || [last_map_hash(4) if exhausted]
|| resource_hash(32)
|| requested_map_hashes(N × 4 bytes)
```

Where:

- `hashmap_exhausted_flag` is `0x00 (HASHMAP_IS_NOT_EXHAUSTED)` if the receiver still has unrequested map_hashes from the most-recently-known hashmap segment, or `0xFF (HASHMAP_IS_EXHAUSTED)` if it has consumed all of them and needs the next hashmap segment.
- If `exhausted == 0xFF`, the request continues with the **last** map_hash the receiver knows from the current segment (4 bytes). The sender uses this to determine which segment of the hashmap to send back via RESOURCE_HMU.
- `resource_hash` is the 32-byte `h` from the advertisement.
- The trailing `requested_map_hashes` is a concatenation of `N` × 4-byte map_hashes the receiver wants delivered. `N` is at most `WINDOW` (initial 4, dynamically grown — see §10.10).

Receivers who already have the part for a requested map_hash don't issue requests for it; the request is constructed only from `parts[search_start:search_start+window]` where `parts[i] is None` (`Resource.py:944-960`).

### 10.6 RESOURCE part packets

For each map_hash in a RESOURCE_REQ, the sender locates the matching pre-packed part within `parts[receiver_min_consecutive_height : receiver_min_consecutive_height + COLLISION_GUARD_SIZE]` and emits it as a regular Link DATA packet with `context = RESOURCE (0x01)` (`Resource.py:1011-1023`). The body is just the part's encrypted data — no metadata, no sequence number. The receiver matches the inbound part to its hashmap by recomputing its 4-byte map_hash and inserting it into `parts[i]` at the position where `hashmap[i]` matches (`Resource.py:866-885`).

Two interop traps:

1. **Map_hashes are not guaranteed unique across the whole resource** — only within `COLLISION_GUARD_SIZE` of any sliding-window position. A receiver that searches the entire hashmap for a matching part-hash can mis-place a part if two distant parts collide. The reference receiver searches only `hashmap[consecutive_completed_height : consecutive_completed_height + window]`.
2. **Parts are link-encrypted but otherwise opaque** — the receiver has no way to validate a part beyond its 4-byte map_hash until the whole resource assembles and the SHA-256 over the reassembled data matches `h`.

### 10.7 RESOURCE_HMU — hashmap update

When the sender receives a RESOURCE_REQ with `exhausted == 0xFF` and a `last_map_hash`, it locates the position of `last_map_hash` in its full hashmap, advances to the **next** `HASHMAP_MAX_LEN` window, and emits the hashmap continuation (`Resource.py:1030-1064`):

```
body = resource_hash(32) || umsgpack.packb([segment_index(int), hashmap_segment_bytes])
```

The segment_index is `part_index // HASHMAP_MAX_LEN`. The receiver applies this with `Resource.hashmap_update(segment, hashmap)` to extend its known hashmap and continues issuing RESOURCE_REQ for the new range.

If the part_index doesn't land on a `HASHMAP_MAX_LEN` boundary, the sender treats it as a sequencing error and cancels the resource (`Resource.py:1043-1046`).

### 10.8 RESOURCE_PRF — final proof

When the receiver has assembled the full resource (`received_count == total_parts`), it runs `assemble()` (`Resource.py:672-726`):

1. Concatenate `parts[0..n]` to a single buffer.
2. `link.decrypt(...)` to plaintext.
3. Strip the 4-byte `random_hash` prefix.
4. If `compressed`: bz2-decompress.
5. Recompute `SHA256(plaintext_with_random || random_hash)` and compare to `h`.
6. If match: peel off metadata if `x` is set, write `data` to the destination; status = `COMPLETE`.
7. If mismatch: status = `CORRUPT`; cancel.

On `COMPLETE`, the receiver emits the proof:

```
proof_data = resource_hash(32) || full_proof(32)
where full_proof = SHA256(data_with_random || resource_hash)
```

sent as `RNS.Packet(link, proof_data, packet_type=PROOF, context=RESOURCE_PRF)` (`Resource.py:755-766`). The `full_proof` is exactly what the initiator pre-computed as `expected_proof` in §10.2 step 5 — it can validate the proof bytewise without re-running the SHA-256.

The initiator's `validate_proof` (`Resource.py:785-824`) checks `proof_data[32:] == self.expected_proof` and transitions status to `COMPLETE`. If the resource is multi-segment (`s == True`), the next segment's advertisement is sent immediately upon proof of the current segment.

### 10.9 RESOURCE_ICL / RESOURCE_RCL — cancellation

Either side can cancel; the body is just `resource_hash(32)`:

- **`RESOURCE_ICL (0x06)`** — initiator cancel. Sent when the initiator decides to abort (e.g. the user kills the upload, the link MTU shrinks below the resource's pre-packed parts, the watchdog gives up after `MAX_RETRIES = 16`).
- **`RESOURCE_RCL (0x07)`** — receiver reject / cancel. Sent on advertisement reject (`Resource.reject(adv_packet)` at line 155-163, e.g. resource too large per app callback) or on receiver-side abort.

Either form transitions the resource to `FAILED`, releases the parts, and notifies the link's resource-concluded callback.

### 10.10 Sliding window and rate adaptation

The receiver controls request-pacing via a sliding window:

```
WINDOW          = 4    # initial outstanding requests
WINDOW_MIN      = 2
WINDOW_MAX_SLOW = 10   # default cap
WINDOW_MAX_FAST = 75   # cap once link is observed to be fast
WINDOW_MAX_VERY_SLOW = 4
WINDOW_FLEXIBILITY = 4
```

After each successful round (every requested part arrived), `window += 1` up to `window_max`; `window_min += 1` once `window - window_min > WINDOW_FLEXIBILITY - 1` (`Resource.py:902-906`). The window cap is promoted to `WINDOW_MAX_FAST` after `FAST_RATE_THRESHOLD` consecutive rounds at observed throughput > `RATE_FAST = 50 kbps / 8`, and demoted to `WINDOW_MAX_VERY_SLOW` after `VERY_SLOW_RATE_THRESHOLD = 2` rounds below `RATE_VERY_SLOW = 2 kbps / 8` (`Resource.py:917-927`). These are receiver-private — they're not negotiated, so two implementations with different rate-detection cutoffs interop fine but may emerge with different effective throughput on the same channel.

### 10.11 Multi-segment resources

For payloads larger than `MAX_EFFICIENT_SIZE = 1 MiB - 1`, the resource is split into multiple segments at `MAX_EFFICIENT_SIZE` boundaries (`Resource.py:299-314`). Each segment is its own Resource with its own RESOURCE_ADV; the `i` (segment_index) and `l` (total_segments) fields disambiguate. The `o` (original_hash) field carries the first segment's `h` so the receiver can correlate segments belonging to the same logical transfer.

The sender doesn't pre-prepare every segment up front — it builds segment N+1 in `__prepare_next_segment` while segment N is still being delivered, and sends segment N+1's advertisement only after it has received the proof for segment N (`Resource.py:768-783, 822-824`). This caps memory usage; a 100 MiB transfer doesn't materialize 100 segments simultaneously.

The 3-byte big-endian uint24 metadata length encoding (§10.2 step 1) is what limits per-resource metadata to `METADATA_MAX_SIZE = 16 MiB - 1`.

### 10.12 Compression and encryption layering

Encryption layering is **outermost** — the wire bytes look like:

```
plaintext           = data_with_random || random_hash    # SHA-256 input
data_with_random    = random_hash(4) || maybe_compressed_body
maybe_compressed    = compressed_body iff `c` flag, else uncompressed
parts[i]            = link.encrypt( data_with_random[i*SDU : (i+1)*SDU] )
```

Critically, **the link encryption is applied to the WHOLE concatenated data first, then sliced into parts** — not to each part individually. This means part boundaries don't align with cipher block boundaries; a missing part can't be decrypted in isolation. The receiver must accumulate all parts before calling `link.decrypt()` (`Resource.py:676-679`).

This also means swapping in a new link session key mid-transfer would break decryption — the encryption happened with the link's key as it was when the resource was constructed.

### 10.13 Source map for §10

| File | What it pins down |
|---|---|
| `RNS/Resource.py:43-156` | Class header, constants, state machine values, `reject` / `accept` |
| `RNS/Resource.py:248-478` | `Resource.__init__` — preparation, hashmap construction, collision guard |
| `RNS/Resource.py:520-596` | `__advertise_job`, watchdog, advertisement retransmit |
| `RNS/Resource.py:672-726` | `assemble` — receiver reassembly, decrypt, decompress, hash-match |
| `RNS/Resource.py:755-829` | `prove` and `validate_proof` |
| `RNS/Resource.py:831-932` | `receive_part` — receiver-side part insertion + window adjust |
| `RNS/Resource.py:934-983` | `request_next` — receiver-side RESOURCE_REQ construction |
| `RNS/Resource.py:985-1064` | `request` — initiator-side fulfillment + RESOURCE_HMU emission |
| `RNS/Resource.py:1237-1383` | `ResourceAdvertisement` — pack/unpack of the ADV msgpack dict |
| `RNS/Packet.py:72-78` | RESOURCE_* context constants |

---

## 11. REQUEST/RESPONSE protocol (NomadNet pages, propagation `/get`, custom RPC)

A generic over-Link RPC mechanism. NomadNet uses it for page fetches; LXMF propagation uses it for offline-message retrieval; any application can register handlers for arbitrary paths. There is no separate "NomadNet wire format" — NomadNet is just one consumer of this protocol.

This section specifies the wire bytes; the application-layer paths (e.g. NomadNet's `/page/index.mu`) are caller-defined.

### 11.1 Wire form — REQUEST (initiator → server)

`RNS/Link.py::request` line 478-527. After an active Link is established (§6), the initiator builds:

```python
request_path_hash = SHA256(path.encode("utf-8"))[:16]
unpacked_request  = [time.time(), request_path_hash, data]
packed_request    = umsgpack.packb(unpacked_request)
```

Then dispatches based on size:

| `len(packed_request)` | Wire form |
|---|---|
| `≤ link.mdu` | One Link DATA packet, `context = REQUEST (0x09)`, body = `packed_request` |
| `> link.mdu`  | Resource transfer (§10), with `request_id = SHA256(packed_request)[:16]`, `is_response = False` (sets `u = True` in the Resource advertisement flags per §10.4) |

The msgpack array layout:

```
[0]  timestamp            float (seconds since unix epoch, requester's clock)
[1]  request_path_hash    bytes(16) — SHA-256 of the requested path string, truncated
[2]  data                 application-defined bytes (often msgpack itself, or None)
```

`request_id` is the 16-byte truncated hash of `packed_request` — used by the receiver to correlate the inbound RESPONSE with this REQUEST. For single-packet REQUESTs the request_id is computed receiver-side from the packet body bytes; for Resource REQUESTs the request_id is carried explicitly in the advertisement's `q` field (§10.4).

### 11.2 Wire form — RESPONSE (server → initiator)

`RNS/Link.py::handle_request` line 853-904. The server's response generator returns a value, and the dispatcher picks the wire form by size:

```python
packed_response = umsgpack.packb([request_id, response])

if len(packed_response) <= link.mdu:
    RNS.Packet(link, packed_response, DATA, context = RESPONSE).send()
else:
    response_resource = RNS.Resource(packed_response, link,
                                     request_id=request_id, is_response=True,
                                     auto_compress=auto_compress)
```

| Wire form | Trigger |
|---|---|
| Link DATA packet, `context = RESPONSE (0x0A)`, body = `umsgpack([request_id, response])` | response fits in `link.mdu` |
| Resource transfer, `request_id` field set, `is_response = True` (advertisement flag `p`) | response too large |

The `request_id` in element [0] of the response msgpack lets the initiator match the response to the original outbound REQUEST in `Link.pending_requests` even when several requests are in flight on the same Link (`Link.handle_response` line 906-925).

#### File responses

If the server's response generator returns a `(file_handle, metadata)` tuple, the response goes out as a Resource carrying the file's bytes with optional msgpack metadata in the Resource advertisement's `metadata` slot — `RNS/Link.py:888-895`:

```python
if type(response) == tuple and isinstance(response[0], io.BufferedReader):
    file_handle = response[0]
    metadata    = response[1] if len(response) > 1 else None
    response_resource = RNS.Resource(file_handle, link,
                                     metadata=metadata, request_id=request_id,
                                     is_response=True, auto_compress=auto_compress)
```

This is how NomadNet ships large pages with attached MIME-type / size hints — the file goes through the §10 Resource pipeline; the metadata hits the advertisement's `m` slot reserved for the resource hashmap **but** also gets a separate metadata-prefix slot per §10.2 step 1 (the 3-byte length-prefixed msgpack-packed metadata blob inserted before the random_hash).

### 11.3 Path hash collision avoidance

`request_path_hash` is the 16-byte truncation of `SHA256(path)` — collision space is 2^128, effectively no collisions in practice. The server's `request_handlers` dict is keyed by this hash:

```python
# RNS/Destination.py::register_request_handler
request_path_hash = SHA256(path.encode("utf-8"))[:16]
self.request_handlers[request_path_hash] = (path, response_generator, allow, allowed_list, auto_compress)
```

A server registers a path string; clients hash the path and look it up. The path string itself is not on the wire — only its hash. This means the server can publish opaque path tokens that resist enumeration: a client must already know the path string to fetch the resource at it. NomadNet uses human-readable paths like `/page/index.mu` because the clients (Sideband, the NomadNet client) need them to be discoverable; a private file-server use case can use random tokens for security-by-obscurity.

### 11.4 Authorization (`allow` modes)

Registered via `Destination.register_request_handler(path, response_generator, allow=...)`:

| Mode | Constant | Effect |
|---|---|---|
| `ALLOW_NONE` | `0x00` | Reject every request (handler is a stub for testing). |
| `ALLOW_LIST` | `0x01` | Accept iff the requester has identified themselves on the link (via `link.identify(identity)`) AND their identity_hash is in `allowed_list`. |
| `ALLOW_ALL` | `0x02` | Accept any request that arrives on this Link, regardless of caller identity. |

`Link.identify(identity)` runs `LINKIDENTIFY (context = 0xFB)` packets; this is how the requester proves which long-term identity is making the request without re-running a fresh Link handshake. Most public NomadNet pages use `ALLOW_ALL`; private pages and propagation-node operator commands use `ALLOW_LIST`.

### 11.5 RequestReceipt — initiator-side state machine

`RNS/Link.py:1348-1448`. When `Link.request()` returns a `RequestReceipt`, the initiator can attach:

- `response_callback(receipt)` — fires when the response has fully arrived (single packet OR resource concluded).
- `failed_callback(receipt)` — fires on timeout or link teardown.
- `progress_callback(receipt)` — fires each time more bytes arrive (for Resource responses; reports `receipt.progress` 0.0..1.0).

Default timeout is `link.rtt × link.traffic_timeout_factor + Resource.RESPONSE_MAX_GRACE_TIME × 1.125` — typically a few seconds plus a generous response-side grace. Caller can override via the `timeout=` kwarg.

### 11.6 NomadNet specifics (informational, not normative)

NomadNet pages are served over this protocol with these conventions:

- Path format: `/page/foo.mu` — the `.mu` extension marks "micron"-formatted pages (NomadNet's lightweight markup).
- Request data: optional msgpack dict of form-field values (e.g. `{"username": "alice"}`).
- Response: either inline page bytes (for static pages) or a file handle + metadata (for large pages or downloads).

None of these are wire-spec — they're caller conventions on top of §13. A Reticulum client that can't render micron markup can still fetch pages and display the raw bytes; the protocol layer doesn't care about content.

### 11.7 Source map

| File | What |
|---|---|
| `RNS/Link.py:478-527` | `Link.request()` — initiator-side packing and dispatch by size |
| `RNS/Link.py:853-904` | `Link.handle_request()` — server-side path lookup + auth + response dispatch |
| `RNS/Link.py:906-925` | `Link.handle_response()` — initiator-side response correlation |
| `RNS/Link.py:1348-1448` | `RequestReceipt` — callback machinery |
| `RNS/Destination.py::register_request_handler` | Server-side handler registration |
| `RNS/Destination.py:35-40` | `ALLOW_NONE/ALLOW_LIST/ALLOW_ALL` constants |
| `RNS/Packet.py:81-82` | `REQUEST = 0x09`, `RESPONSE = 0x0A` context constants |

---

## 12. Transport-relay behaviour

Everything in §1-§11 applies to both leaf clients and transport-mode nodes. This section covers what additionally runs on a node configured with `enable_transport = Yes` in the `[reticulum]` config — i.e. a node whose role is to forward traffic for others. Reticulum's relay is host-routed (no broadcast flooding except for path-discovery), keyed by the `path_table` populated from announces.

A leaf client can ignore §12 entirely. Implementations that target the rnsd-replacement or repeater use case need every sub-section.

### 12.1 The `transport_enabled` toggle

`Reticulum.transport_enabled()` returns the value of the `enable_transport` config option (default `False`). Setting it to `True`:

- Allows the node to populate `path_table`, `announce_table`, `link_table`, `reverse_table`, and `tunnels` for non-local destinations (a leaf only populates path entries it personally needs).
- Enables the §12.2 DATA forwarding branches in `Transport.inbound`.
- Enables the §12.3 ANNOUNCE rebroadcast branch.
- Enables `Transport.identity` — the transport node's own identity, used for `transport_id` insertion in HEADER_2 packets (§2.3) and as the `requesting_transport_instance` field in path requests (§7.1).

A clean-room implementation testing forwarding without operating as a real transport node SHOULD respect the same flag: ignoring the toggle and unconditionally forwarding turns every implementation into a network-flooding hazard.

### 12.2 DATA forwarding rules

For an inbound DATA packet (`packet_type == DATA`, `destination_type` not LINK) where:

- `packet.transport_id == Transport.identity.hash` (the originator picked us as the next hop), AND
- `packet.destination_hash` is in `Transport.path_table`,

the relay rewrites the wire bytes according to `path_table[dest][HOPS]` and re-transmits on `path_table[dest][RVCD_IF]`. From `RNS/Transport.py:1497-1573`, three cases by `remaining_hops`:

#### 12.2.1 `remaining_hops > 1` — forward as HEADER_2

Increment hops (already done by `Transport.inbound` line 1395), replace the transport_id with the next-hop transport_id from the path table, keep the rest of the packet:

```
new_raw = packet.raw[0:1]                        # flags byte unchanged
new_raw += struct.pack("!B", packet.hops)        # incremented hops byte
new_raw += next_hop                              # 16B transport_id (new next hop)
new_raw += packet.raw[18:]                       # original dest_hash + ctx + body
```

The flags byte high nibble is unchanged — the packet stays HEADER_2 with the TRANSPORT bit set. Final wire form is `flags(1) || hops+1(1) || new_transport_id(16) || dest_hash(16) || ctx(1) || body`.

#### 12.2.2 `remaining_hops == 1` — strip transport headers, forward as HEADER_1 broadcast

The destination is one hop away on the next-hop interface; no further transport_id is needed. Convert to HEADER_1 with BROADCAST transport type:

```
new_flags = (HEADER_1 << 6) | (BROADCAST << 4) | (packet.flags & 0x0F)
new_raw = struct.pack("!B", new_flags)
new_raw += struct.pack("!B", packet.hops)
new_raw += packet.raw[18:]                       # original dest_hash + ctx + body (transport_id stripped)
```

This is the inverse of the §2.3 originator HEADER_1→HEADER_2 conversion: the relay strips the transport_id when the packet has reached its last hop.

#### 12.2.3 `remaining_hops == 0` — local destination, just bump hops

The destination is registered on the relay itself (it's both our path-table next-hop AND a local destination). Just increment hops and pass through unchanged for local processing — the standard `Destination.receive` path takes over from there.

#### 12.2.4 LINKREQUEST forwarding extras

When the forwarded packet is a `LINKREQUEST`, the relay also writes a `link_table` entry keyed by the link_id (computed via §6.3's `link_id_from_lr_packet`). Entry contents (`Transport.py:1553-1561`):

```
[ now,                            # 0  IDX_LT_TIMESTAMP
  next_hop,                       # 1  IDX_LT_NH_ID — next-hop transport_id
  outbound_interface,             # 2  IDX_LT_NH_IF
  remaining_hops,                 # 3  IDX_LT_REM_HOPS
  packet.receiving_interface,     # 4  IDX_LT_RCVD_IF
  packet.hops,                    # 5  IDX_LT_TAKEN_HOPS
  packet.destination_hash,        # 6  IDX_LT_DSTHASH
  False,                          # 7  IDX_LT_VALIDATED
  proof_timeout ]                 # 8  IDX_LT_PROOF_TMO
```

This entry is what lets the relay forward the eventual LRPROOF back to the initiator on the reverse path (§12.5) and forward subsequent Link DATA in both directions.

The relay also performs the §6.6 MTU clamp at this point: if the LINKREQUEST carries signalling and the next-hop interface's HW_MTU is smaller than the requested value, the signalling bytes in `new_raw` are rewritten in place with the clamped MTU before transmission.

#### 12.2.5 Non-LINKREQUEST DATA — reverse_table entry

For any other forwarded DATA (the much-more-common opportunistic LXMF case), the relay writes a `reverse_table` entry keyed by `packet.getTruncatedHash()` (`Transport.py:1567-1571`):

```
[ packet.receiving_interface,    # 0  IDX_RT_RCVD_IF — interface to send PROOF back through
  outbound_interface,            # 1  IDX_RT_OUTB_IF — interface forward was sent on
  time.time() ]                  # 2  IDX_RT_TIMESTAMP
```

The reverse_table is what lets the eventual PROOF receipt (§6.5) trace its way back to the originator without consulting the path_table again — see §12.5.

### 12.3 ANNOUNCE rebroadcasting

When an inbound ANNOUNCE validates (per §4.5) AND the destination is non-local AND `transport_enabled OR is_from_local_client`, the relay queues a rebroadcast. From `Transport.py:1810-1890`:

```python
if (Reticulum.transport_enabled() or is_from_local_client) and packet.context != PATH_RESPONSE:
    if not rate_blocked:
        Transport.announce_table[packet.destination_hash] = [
            now, retransmit_timeout, retries,
            received_from, announce_hops, packet,
            local_rebroadcasts, block_rebroadcasts, attached_interface,
        ]
```

The `announce_table` entry queues a delayed retransmit; the actual emission happens in the periodic `Transport.jobs` cycle which scans the table for entries whose `retransmit_timeout` has elapsed and fires them on each suitable interface.

#### 12.3.1 Announce cap (`ANNOUNCE_CAP`)

`Reticulum.ANNOUNCE_CAP = 2.0` (default 2% of airtime, configurable via `[reticulum] announce_cap`). Each interface tracks its outbound announce airtime and when the rolling-window utilization exceeds the cap, further announces are queued in `interface.announce_queue` rather than transmitted immediately. `process_announce_queue` (`RNS/Interfaces/Interface.py:232-272`) drains the queue at a rate the cap permits, picking the lowest-hop-count entry first.

The cap is per-interface, not global — a relay with multiple interfaces budgets each one independently, which lets a fast TCP backbone interface announce freely while the same node throttles announces on a slow LoRa interface. Without per-interface caps, a single high-rate interface would starve every other.

#### 12.3.2 `random_blob` replay defence

§4.5 step 6.3 already documents this from the receiver's perspective; for the rebroadcast logic, the relay only queues an announce if the new `random_blob` (the 10-byte `random_hash` field, treated as an opaque blob for routing purposes) is **not** already in the cached `random_blobs` list for this destination. The list is capped at `Transport.MAX_RANDOM_BLOBS` (default 32) entries, sliding-window. This prevents an announce from looping through a multi-relay topology because each relay only forwards each unique blob once.

#### 12.3.3 Path-response announces don't rebroadcast

`packet.context == PATH_RESPONSE` short-circuits the rebroadcast branch (line 1822). Path-response announces travel back along the reverse path from the responder to the requester (see §7.2 and `flows/path-discovery.md`), and the relay's job is to forward them on a single specific interface (`attached_interface`), not re-broadcast to the whole mesh. Mishandling this would multiply path-response traffic by the relay fanout.

### 12.4 Path table management

`Transport.path_table[destination_hash]` entry shape (`Transport.py:3439-3446`):

```
[ timestamp,                # 0  IDX_PT_TIMESTAMP — when last refreshed
  next_hop,                 # 1  IDX_PT_NEXT_HOP — 16B transport_id of next hop
  hops,                     # 2  IDX_PT_HOPS — distance to destination
  expires,                  # 3  IDX_PT_EXPIRES — unix-seconds eviction time
  random_blobs,             # 4  IDX_PT_RANDBLOBS — sliding window of recent blobs
  receiving_interface,      # 5  IDX_PT_RVCD_IF — interface to forward on
  packet ]                  # 6  IDX_PT_PACKET — cached announce packet for path-? response
```

#### 12.4.1 TTLs

Three different expiry constants based on the `attached_interface.mode`:

| Mode | TTL constant | Default seconds | Used for |
|---|---|---|---|
| `MODE_ACCESS_POINT` | `Transport.AP_PATH_TIME` | 1 hour | Hub-and-spoke topologies (TCP servers, BLE gateways) |
| `MODE_ROAMING` | `Transport.ROAMING_PATH_TIME` | 4 hours | Mobile devices that disappear and reappear |
| (default) | `Transport.PATHFINDER_E` | 30 days | Stable backbone interfaces |

The wide spread of defaults reflects expected churn rates: AP-mode interfaces have many short-lived clients; roaming devices come and go; backbone TCP relays are essentially permanent.

#### 12.4.2 Eviction

`Transport.jobs` runs a `stale_paths` accumulator that walks `path_table` and pops entries whose `expires` timestamp has passed (`Transport.py:747-769`). Eviction is silent — no notification to the application; the next outbound message to the destination just re-discovers it via `request_path` per §7.1.

A relay also evicts path entries whose underlying interface has been removed (`receiving_interface not in Transport.interfaces`). This handles the case where a TCP client disconnects.

#### 12.4.3 Persistence

If `[reticulum] persist_paths = Yes`, the path_table is serialized to `{storagepath}/paths` (a pickled dict in upstream RNS) so it survives restarts. The repeater repo's `pre_build.py` adds a "skip redundant path writes" patch to avoid hammering the on-board flash on nRF52 — for clean-room implementations, the persistence cadence is implementation-private.

### 12.5 Reverse-table link transport

Once a Link's LINKREQUEST has been forwarded by a relay (§12.2.4 wrote the `link_table` entry), every subsequent Link packet — DATA, KEEPALIVE, PROOF, LINKCLOSE — must be forwarded by the same relay in the appropriate direction. `Transport.inbound` uses `link_table` and `reverse_table` for this:

#### 12.5.1 LRPROOF forwarding

When an LRPROOF arrives whose `dest_hash` (= link_id) is in the relay's `link_table` AND the proof arrives on the next-hop interface (`packet.receiving_interface == link_entry[IDX_LT_NH_IF]`), the relay validates the signature against the destination's known long-term public key (recalled via `Identity.recall(link_entry[DSTHASH])`) and forwards on the receive interface (`Transport.py:2110-2138`):

```python
new_raw = packet.raw[0:1] + struct.pack("!B", packet.hops) + packet.raw[2:]
Transport.transmit(link_entry[IDX_LT_RCVD_IF], new_raw)
link_table[packet.destination_hash][IDX_LT_VALIDATED] = True
```

After validation, the link_table entry is marked `validated`, and from now on the relay forwards Link DATA in both directions transparently.

#### 12.5.2 Link DATA forwarding

For a `DATA` packet with `destination_type == LINK` whose `dest_hash` is in `link_table`, the relay forwards on the appropriate direction's interface. The link_table entry remembers both sides via `IDX_LT_NH_IF` (toward initiator end) and `IDX_LT_RCVD_IF` (toward responder end); the relay picks based on which interface the inbound packet arrived on.

#### 12.5.3 PROOF receipt forwarding via `reverse_table`

`Transport.py:2196-2205`. When a PROOF arrives whose `dest_hash` is in `reverse_table` (i.e. an opportunistic-DATA proof being routed back to its originator), the relay pops the entry, checks the proof arrived on the correct outbound interface (`receiving_interface == reverse_entry[IDX_RT_OUTB_IF]`), and forwards on the originally-receiving interface:

```python
new_raw = packet.raw[0:1] + struct.pack("!B", packet.hops) + packet.raw[2:]
Transport.transmit(reverse_entry[IDX_RT_RCVD_IF], new_raw)
```

Reverse_table entries are popped on use (one-shot routing) and aged out by `Transport.jobs` after `Transport.REVERSE_TIMEOUT` (default `30s`). This bounds the relay's memory regardless of whether the proof ever arrives.

### 12.6 Tunnels and shared-instance protocol

Two related state mechanisms a transport node maintains:

#### 12.6.1 `discovery_path_requests`

When a transport-enabled relay receives a path? for a destination it doesn't know AND doesn't have a local client to forward to, it records a `discovery_path_requests[dest_hash]` entry (`Transport.py:2949-2963`):

```python
pr_entry = {
    "destination_hash": destination_hash,
    "timeout": time.time() + PATH_REQUEST_TIMEOUT,    # 15s
    "requesting_interface": attached_interface,
}
Transport.discovery_path_requests[destination_hash] = pr_entry
```

Then forwards the path? to every other interface preserving the original tag. This is recursive transport-mode discovery — the relay is acting as a search proxy. When the response announce eventually arrives back, the relay forwards it on `requesting_interface` (the one the original path? came from), and the entry is aged out.

#### 12.6.2 `tunnels`

A tunnel is an interface-level path mechanism for handling temporarily-disconnected interfaces (e.g. a mobile peer that comes and goes). The `tunnels[interface_tunnel_id]` state lets the relay reconstruct paths through the interface when it reconnects, without requiring all paths to be re-discovered from scratch. The shape (`Transport.py:783-832`):

```
[ now,                                       # 0  IDX_TT_TIMESTAMP
  expires,                                   # 1  IDX_TT_EXPIRES — TUNNEL_TIMEOUT
  paths_dict,                                # 2  IDX_TT_PATHS — dest_hash → path-entry
  ... ]
```

Each path inside the tunnel's `paths_dict` mirrors a `path_table` entry. When the tunnel's interface returns, the relay re-installs every path from the tunnel into the active `path_table`, jump-starting connectivity. Without this, every reconnection would require a full announce flood across the mesh.

`TUNNEL_TIMEOUT` defaults to substantially longer than path TTLs because tunnels persist across interface flap.

#### 12.6.3 Shared-instance protocol

When multiple processes on one host share a single Reticulum stack (via `share_instance = Yes` in the rnsd config), one process owns `Transport` and the others connect to it as **local clients** via a small TCP loopback interface. The shared instance treats local-client traffic specially:

- `from_local_client` and `for_local_client` are computed on every inbound packet (`Transport.py:1450-1454`).
- Path-table entries with `IDX_PT_HOPS == 0` mean "destination is a local client" — the §2.3 originator-side HEADER_1 conversion applies for hops==1 too, so the shared instance gets a transport_id-tagged packet (`Transport.py:1094-1105`).
- Local-client originated path? requests are forwarded to every external interface, fanning out the search across the shared mesh (§7.2 dispatch branch 3).

The wire protocol for shared-instance loopback is just the same Reticulum packets over a TCP loopback interface — no special framing or commands. What's "shared" is the path_table and announce dispatch, not the wire format.

### 12.7 Source map for §12

| File | What |
|---|---|
| `RNS/Transport.py:1497-1573` | DATA forwarding (HEADER_1↔HEADER_2 conversion for relay) |
| `RNS/Transport.py:1553-1561` | `link_table` entry shape |
| `RNS/Transport.py:1567-1571` | `reverse_table` entry shape |
| `RNS/Transport.py:1810-1969` | ANNOUNCE rebroadcast queue and per-interface dispatch |
| `RNS/Transport.py:2110-2138` | LRPROOF forwarding via `link_table` |
| `RNS/Transport.py:2196-2205` | PROOF receipt forwarding via `reverse_table` |
| `RNS/Transport.py:3439-3446` | `path_table` entry shape (IDX_PT_*) |
| `RNS/Transport.py:747-832` | stale-path / stale-tunnel eviction |
| `RNS/Transport.py:2949-2963` | `discovery_path_requests` recursive search |
| `RNS/Interfaces/Interface.py:232-272` | per-interface `announce_queue` and `ANNOUNCE_CAP` enforcement |

---

## 13. Threading and concurrency model

The wire spec is silent on threading, but a clean-room client built single-threaded mostly works for opportunistic LXMF and starts breaking on Resource transfers and Link keepalives. This is consistently the #1 cause of "my client compiles and almost works but is flaky." Everything below is **implementation-private** — there's no wire requirement to use threads, only to satisfy the timing guarantees that upstream's threading provides. But the upstream Python implementation is highly concurrent; an alternative implementation that wants to interop has to provide the same guarantees, however it achieves them.

### 13.1 Long-running threads

Upstream RNS spawns the following persistent daemon threads at `Transport.start()`:

| Thread | Source | Cadence | Purpose |
|---|---|---|---|
| **`Transport.jobloop`** | `RNS/Transport.py:280, 483-486` | every `job_interval = 0.250s` | Runs `Transport.jobs()` — the catch-all maintenance pass: link state checks, announce-queue drain, stale-path eviction, hashlist cleanup, reverse-table cleanup, tunnels housekeeping. |
| **`Transport.count_traffic_loop`** | `RNS/Transport.py:281, 449-480` | every 1s | Snapshots per-interface RX/TX byte counters into rolling-window deques for bandwidth/airtime accounting. |
| **`Link.__watchdog_job`** | `RNS/Link.py:746-821` | per-link, RTT-driven | One per active Link. Drives keepalive emission (initiator side), STALE→CLOSED transitions, and link-establishment timeouts. Sleeps `min(WATCHDOG_MAX_SLEEP=5s, RTT-derived)` between iterations. |
| **`Resource.__watchdog_job`** | `RNS/Resource.py:564-642` | per-resource | One per in-progress Resource. Detects retransmit timeouts, advertisement retries, and PRF-wait timeouts. |
| **`AnnounceHandler` callbacks** | `RNS/Transport.py:1995-2016` | per inbound announce | Each accepted announce fires its registered handler **on a fresh daemon thread** — the dispatcher does not serialize. Two announces from the same destination back-to-back run two handler threads concurrently. |
| **Per-interface RX threads** | `RNS/Interfaces/*Interface.py` | always | Each interface (TCP, KISS, RNode, AutoInterface) has its own blocking-read RX thread that calls `Transport.inbound(raw, self)` on each complete frame. |
| **`process_announce_queue`** | `RNS/Interfaces/Interface.py:266-267` | one-shot timer per drain | Per-interface `announce_queue` drain uses `threading.Timer` to schedule the next emission at the airtime-cap-derived wait time. Not a long-running thread but a chain of one-shots. |
| **`Resource.__advertise_job`** | `RNS/Resource.py:520-541` | per-resource | One-shot daemon thread that performs the resource hashmap construction (which can take seconds on a large body) so the calling thread doesn't block. |

A clean-room implementation with cooperative scheduling (e.g. asyncio, embedded RTOS task model) needs to provide equivalent behavior for each row. The key invariants — not the exact thread inventory — are what matter for interop:

- The watchdog must run independently of the calling code, or links go stale silently when the application is busy.
- Announce-handler callbacks must NOT block subsequent inbound packet dispatch. If your handler runs synchronously on the receive thread, a slow handler stalls every other inbound traffic.
- The job loop must run regardless of inbound traffic; otherwise `path_table` doesn't evict stale entries, `discovery_path_requests` doesn't time out, and the announce_table doesn't drain its queued retransmits.

### 13.2 Lock inventory

Upstream uses about 30 named locks. The shared-state ones a clean-room implementation must guard equivalently (or substitute single-threaded equivalent):

| Lock | Guards |
|---|---|
| `Transport.path_table_lock` | `Transport.path_table` reads and writes |
| `Transport.announce_table_lock` | `Transport.announce_table` reads and writes |
| `Transport.link_table_lock` | `Transport.link_table` (transit-relay link forwarding state) |
| `Transport.reverse_table_lock` | `Transport.reverse_table` (PROOF reverse-routing state) |
| `Transport.active_links_lock` | `Transport.active_links` list |
| `Transport.pending_links_lock` | `Transport.pending_links` list |
| `Transport.tunnels_lock` | `Transport.tunnels` |
| `Transport.destinations_map_lock` | `Transport.destinations_map` (local destinations registered for receive) |
| `Transport.announce_handler_lock` | `Transport.announce_handlers` list |
| `Transport.path_requests_lock` | `Transport.path_requests` rate-limiting cache |
| `Transport.discovery_pr_tags_lock` | `Transport.discovery_pr_tags` dedup |
| `Transport.jobs_lock` | held for the entire `jobs()` body — long-held, blocking |
| `Identity.known_destinations_lock` | `Identity.known_destinations` dict reads/writes |
| `Identity.ratchet_persist_lock` | ratchet persistence file I/O |
| `Link.watchdog_lock` | per-link gate; the watchdog `wait`s on this when the link is in the middle of a state change |
| `Link.receive_lock` | per-link inbound packet processing |
| `Resource.assembly_lock` | per-resource gate around assemble() |
| `Destination.ratchet_file_lock` | per-destination ratchet file I/O |

`Transport.jobs_lock` is the most aggressive — it's held for the **entire** `jobs()` execution (which can include I/O for path persistence, announce queue draining, etc.). This is what bounds how often `jobs()` can run; you can't pile up parallel jobs() invocations even if `job_interval` elapses while one is running.

### 13.3 Callback-thread guarantees (and lack thereof)

What upstream **guarantees** to application-level callbacks:

- **`Destination.set_packet_callback`** — fires once per inbound DATA, on the receive thread. **Synchronous.** A slow callback stalls subsequent inbound packet dispatch on the same interface.
- **`Link.set_link_established_callback`** — fires once when a link transitions PENDING → ACTIVE. On the receive thread.
- **`Link.set_link_closed_callback`** — fires once when a link transitions to CLOSED, regardless of cause (timeout, peer close, local teardown). On the watchdog thread or the receive thread depending on which path triggered the close.
- **`PacketReceipt.set_delivery_callback`** — fires once when a PROOF arrives matching this receipt. On the receive thread.
- **`AnnounceHandler.received_announce`** — fires once per accepted announce, **on a fresh daemon thread**. This is the only callback that's NOT on the receive thread (`Transport.py:1995-2016`).
- **`Resource.callback`** — fires once on resource conclude, on the assembly thread.

Implications for a clean-room implementation:

1. **Don't block on the receive thread.** A `set_packet_callback` that does I/O or PoW work blocks every other inbound packet on the same interface until it returns. The standard pattern is: copy the data out, hand it to a worker queue, return immediately.
2. **Announce handlers race.** Two callbacks for the same destination can run concurrently; if your handler mutates shared state (a contacts list, a UI), use a lock or single-thread the writes.
3. **Link-closed can fire from two paths.** Watchdog timeout or peer LINKCLOSE both call `link_closed_callback`. Make the callback idempotent.

### 13.4 Implementation-private constants

These are not on the wire but affect timing-sensitive interop. A client that uses radically different values may diverge from upstream's behavior in subtle ways:

| Constant | Default | Notes |
|---|---|---|
| `Transport.job_interval` | `0.250s` | Quarter-second cadence of `jobs()`. |
| `Transport.links_check_interval` | `1.0s` | Throttles inside `jobs()`; links are scanned at most every 1s. |
| `Transport.tables_cull_interval` | `5.0s` | Throttles path/reverse/link table eviction inside `jobs()`. |
| `Transport.hashlist_maxsize` | `1000000` | Packet-hash dedup ring; once full, half is purged on next `jobs()`. |
| `Link.WATCHDOG_MAX_SLEEP` | `5s` | Cap on link watchdog sleep regardless of RTT. |
| `Resource.WATCHDOG_MAX_SLEEP` | `1s` | Resource watchdog cadence cap. |
| `Resource.PROCESSING_GRACE` | `1.0s` | Grace before a resource is considered timed out. |
| `Resource.SENDER_GRACE_TIME` | `10.0s` | End-of-transfer grace if some parts haven't been requested. |

A client running on a constrained device (less RAM, slower CPU) can scale all of these up — at the cost of slower path-table responsiveness and slightly later timeout decisions. Don't scale them down unless you've actually measured your platform; below ~100 ms `job_interval` upstream Python burns measurable CPU just on the bookkeeping passes.

### 13.5 Source map

| File | What |
|---|---|
| `RNS/Transport.py:280-281` | top-level thread spawn at startup |
| `RNS/Transport.py:128-148` | the lock inventory (Transport-side) |
| `RNS/Transport.py:172, 175, 186` | `job_interval`, `links_check_interval`, `tables_last_culled` |
| `RNS/Transport.py:483-486` | `jobloop` — the periodic driver |
| `RNS/Transport.py:489+` | `jobs()` body (held under `jobs_lock`) |
| `RNS/Transport.py:1995-2016` | announce-handler dispatch (fresh thread per callback) |
| `RNS/Link.py:746-821` | per-link `__watchdog_job` |
| `RNS/Resource.py:564-642` | per-resource `__watchdog_job` |
| `RNS/Resource.py:520-541` | one-shot `__advertise_job` |
| `RNS/Interfaces/*Interface.py` | per-interface RX thread |

---

## 14. Failure modes — symptom → root cause

§9 lists gotchas keyed by *cause* ("here's a thing that's true"). This section is the inverse index, keyed by *symptom* — what you're observing, and where to look. Each entry names the symptom, points at the section that explains why, and (where useful) names a `tools/verify_*.py` script that locks in the fix.

### Identity / announce

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Generated identity files don't load on upstream `rnsd` | §1.3 — on-disk byte order is `X25519_priv \|\| Ed25519_priv` (NOT the opposite as some old docs claim) | `tools/verify_destination_hash.py` round-trips `to_file`/`from_file` |
| Sideband shows you as "Anonymous" or random hex instead of your display name | §9.3 — display name was msgpack-encoded as `str` instead of `bytes`. Upstream's `dn.decode("utf-8")` raises silently | `tools/verify_msgpack_quirk.py` |
| Announces validate locally but upstream peers reject as "Destination mismatch" | §1.2 — `name_hash` recipe wrong; the `identity=None` branch of `expand_name` does NOT include the identity hex in the hash input | `tools/verify_destination_hash.py` |
| Upstream announces with ratchets get rejected by my validator | §4.5 step 1 — body parser didn't branch on `context_flag` bit; ratchet-bearing announces shift `signature` 32 bytes deeper | §4.5 step 1 |
| First contact with a peer works, but path table never refreshes from a Python source after a microReticulum announce arrives | §4.1 / §9.10 — microReticulum emits 10 fully-random bytes for `random_hash` instead of 5-random + 5-uint40-timestamp. Python receivers parse `random_hash[5:10]` as far-future and lock the path against fresher Python announces | §9.10 |
| Periodic re-announce works locally but peers can't reach me after a few minutes | §7.5 / §9.7 — re-announce loop isn't running. Transit relays evict path entries within minutes regardless of TTL | §9.7 |
| Announces propagate fine but my client populates its contact list with itself | §9.5 / §4.5 step 8 — self-announce echo. Filter `dest_hash == our_dest_hash` before ingesting any inbound announce | §4.5 step 8 |

### Token crypto / opportunistic LXMF

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Decrypted plaintext is correct but has 16 garbage bytes appended | §9.2 — manual PKCS#7 padding on top of platform's automatic padding (Web Crypto / JCA `AES/CBC/PKCS5Padding`) | §9.2 |
| HMAC validates but AES decrypt produces gibberish | §3.2 — HKDF salt is wrong. Salt MUST be the recipient's 16-byte `identity_hash`, not the destination hash, not the ratchet pub | `tools/verify_token_crypto.py` |
| Decrypt works for the first message after announce but fails for subsequent ones | §3.3 / §7.4 — recipient rotated their ratchet, you're still using the cached `ratchet_pub`. Re-fetch the latest announce or use the long-term encryption key as fallback | §3.3 |
| Tampered packets are accepted as valid | §3.3 — verifying HMAC AFTER AES decrypt (or not at all). Encrypt-then-MAC: verify HMAC FIRST | `tools/verify_token_crypto.py` |
| LXMF decrypts cleanly but signature validation fails | §5.6 — try both raw `packed_payload` AND a stripped-and-re-encoded form (with the optional 5th `stamp` element removed) | §5.6 |
| `source_hash` lookup returns nothing even though I just received an announce from that peer | §9.1 / §5.4 — `source_hash` is the SENDER's destination hash (`SHA256(name_hash \|\| identity_hash)[:16]`), NOT the raw 16-byte identity hash | §9.1 |

### Link establishment / proof receipts

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| LINKREQUEST goes out but no LRPROOF arrives | §6.1 — body length wrong. 64 (no signalling) or 67 (with §6.6 signalling); anything else is rejected | `tools/verify_link_handshake.py` |
| LRPROOF arrives but signature validation fails | §6.2 — body order wrong. Actual upstream is `signature \|\| responder_X25519_pub \|\| signalling`; the `link_id` is in the packet header, not the body | `tools/verify_link_handshake.py` |
| Link handshake fails specifically when MTU signalling is present on one side but not the other | §6.6.5 — signalling bytes (when present) are part of the LRPROOF `signed_data`. A mismatch means signed_data differs and signature fails | §6.6.5 |
| Link establishes but tears down within 5 minutes of inactivity | §6.7 — KEEPALIVE not implemented. Initiator sends `0xFF` ping every `keepalive` seconds; responder replies with `0xFE` pong | §6.7.1 |
| Sender sees DATA bursts repeatedly retransmitted, link dies | §6.5 — receiver isn't emitting the mandatory PROOF receipt for each CTX_NONE Link DATA packet | `tools/verify_proof_packet.py` |
| Some peers work, others reject every PROOF I send | §6.5.2 — wrong proof body length. Upstream default emits 64-byte implicit proofs (`signature` only) but your peer expects 96-byte explicit (`packet_hash \|\| signature`). Validator dispatches on length | `tools/verify_proof_packet.py` |

### Resource transfers (large bodies)

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Resource advertisement arrives, but my receiver never asks for parts | §10.5 — RESOURCE_REQ shape: `exhausted_flag(1) [\|\| last_map_hash(4)] \|\| resource_hash(32) \|\| requested_map_hashes(N×4)` | §10.5 |
| Resource transfers but assemble fails with hash mismatch | §10.12 — encryption is applied to the WHOLE concatenated body BEFORE part splitting. Accumulate all parts, then run `link.decrypt()` once | §10.12 |
| Resource hash collisions during construction | §10.2 step 9 — collision-guard must regenerate `random_hash` and recompute the hashmap when any 4-byte map_hash collides within `COLLISION_GUARD_SIZE` window | §10.2 step 9 |
| `ADV` for >1MiB body never resolves | §10.11 — multi-segment cutover at `MAX_EFFICIENT_SIZE = 1 MiB - 1`. Each segment is a separate Resource; sender only sends segment N+1's ADV after PRF for segment N | §10.11 |

### Path discovery

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Path? requests sent but no announce response | §7.2.1 — tagless requests are dropped. Body must be `target_dest_hash(16) [\|\| transport_id(16)] \|\| tag(≥1)` | `tools/verify_path_request.py` |
| Path? requests accepted by responder but I get no announce back | §7.2.6 — leaf clients only respond when `target_hash == our_destination_hash`. Don't respond for destinations you don't OWN | §7.2.6 |
| Spurious double-announces in response to one path request | §7.2.2 — `discovery_pr_tags` dedup table missing on responder. Without it, every retransmitted path? produces another announce | §7.2.2 |
| Sending opportunistic LXMF triggers a path? on every send, never converges | §7.1 — path? is gated by `not has_path() AND method == OPPORTUNISTIC`. If your `has_path()` always returns False, you're storming the network | §7.1 |

### Transport / framing

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| LoRa packets > 254 bytes drop entirely on RNode | §8.3 — RNode air-frame split protocol not implemented. Random seq nibble + FLAG_SPLIT bit; both halves share the same header byte | `tools/verify_rnode_split.py` |
| RNode receives correctly but TX is silent | §8.4.2 — KISS configuration handshake incomplete. CMD_RADIO_STATE = 0x01 must be the LAST step | §8.4.2 |
| Received RSSI/SNR values are garbage | §8.4.5 — wrong sidecar decode. `RSSI = byte - 157`, `SNR = signed Q6.2 / 4`. Sidecar frames precede each `CMD_DATA` frame | §8.4.5 |
| Multi-hop packets arrive but local-destination packets don't | §2.3 — originator HEADER_1→HEADER_2 conversion not applied for hops > 1. Originators must do this conversion themselves when path table reports `hops > 1` | `tools/verify_packet_header.py` |
| Sending to multi-hop peers fails silently after path table populated | §7.6 — `TCPServerInterface.OUT` is True by default in practice (constructor's `False` is overridden at runtime). Don't waste time chasing a stuck OUT flag | §7.6 |

### LXMF specifics

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Messages from clockless devices appear at January 1, 1970 | §9.6 — substitute. Treat any timestamp before `1577836800` (2020-01-01) as "no clock"; substitute local receive time | §9.6 |
| Modern Sideband marks my messages as spam / drops them | §5.7 — recipient requires a stamp (announced via `stamp_cost` in app_data) and your client doesn't compute one. PoW is 3000-round HKDF over `message_id`, target_cost leading zero bits | §5.7 |
| Display name disappears after a re-announce | §9.4 — wrong name-priority order. Use `extracted ?? existing ?? known_label ?? ""`, NOT `extracted ?? known_label ?? existing ?? ""` | §9.4 |
| Propagation node accepts messages but my client never retrieves them | §5.8.3 — `/get` request needs the link to be `identify()`-d first; otherwise it returns `ERROR_NO_IDENTITY` | `flows/receive-propagated-lxmf.md` |
| Custom propagation node implementation rejects all client `/offer` requests | §5.8.5 — element [5] of the propagation announce app_data is a 3-element list `[stamp_cost, stamp_cost_flexibility, peering_cost]`, NOT a single integer | §5.8.5 |

### Concurrency

| Symptom | Likely cause | Fix |
|---|---|---|
| Links go stale even though my application is actively using them | §13.1 — your watchdog runs on the same thread as your application. Move it to a daemon thread | §13.1 |
| Slow announce handler stalls subsequent inbound packets | §13.3 — packet callback runs synchronously on the receive thread. Queue and return; don't do I/O or PoW on the receive thread | §13.3 |
| `link_closed_callback` fires twice for one link | §13.3 — callback fired from both watchdog timeout AND inbound LINKCLOSE paths. Make idempotent | §13.3 |
| Two announces from the same destination produce duplicate UI rows | §13.3 — handler callbacks race on fresh threads. Lock or single-thread the writes to your contacts list | §13.3 |

### When all else fails

§9.9 — add a single one-line `rx <size>B H<1\|2> <PT> dest=<hex> ctx=0x<hex> hops=<n>` log at the top of your `Transport.inbound` equivalent. The number of debugging hours this saves is hard to overstate. Symmetric `tx` logging on outbound is similarly cheap.

---

## 15. Time and clock requirements

Reticulum has time-sensitive behaviour scattered across many sections. This is the consolidated reference for what kind of clock you need where, what tolerance the protocol gives you, and what fails on a no-RTC device (Faketec, RAK4631 stock, Heltec_T114, generic nRF52 LoRa boards).

### 15.1 Three clock kinds

| Kind | What it tells you | Typical embedded availability |
|---|---|---|
| **Absolute wall time** | Current Unix-seconds (e.g. `1714780800`) | Only with NTP sync, GPS, or hand-set clock |
| **Boot-relative monotonic seconds** | Seconds since the device booted | Always, via `millis()` / `time.monotonic()` |
| **High-resolution monotonic** | Sub-second timing for RTT and watchdog | Always, but precision varies |

Most upstream Python code assumes wall time is available because it runs on hosts with NTP. Embedded clean-room implementations need to be careful about which kind each call site needs.

### 15.2 Required: monotonic seconds (every implementation)

These break a single-clock implementation if missing. All can be satisfied by **boot-relative seconds** — they only need order, not absolute value.

| Use | Section | What fails without it |
|---|---|---|
| Link RTT measurement | §6.7.1 | `keepalive` interval can't adapt; defaults to `KEEPALIVE_MAX = 360s` worst case |
| Link watchdog (last_inbound, last_outbound, last_keepalive timestamps) | §6.7 | Link can't detect staleness; lingers forever or tears down spuriously |
| Resource transfer watchdog (last_activity, advertisement retry timing) | §10 | Resource transfers stall without retry; SENDER_GRACE_TIME never triggers |
| `Transport.path_requests` rate-limit (`PATH_REQUEST_MI = 20s` minimum interval) | §7.1 | Path? storms — repeats faster than rate limit allows |
| `Transport.tables_last_culled` periodic eviction trigger | §13.4 | Path/reverse/link tables grow without bound |
| `Transport.discovery_pr_tags` aging (`PATH_REQUEST_GATE_TIMEOUT = 120s`) | §7.2.2 | Path-request dedup table never evicts old entries |
| `Interface.ic_burst_freq` rolling deque for ingress rate limiting | §4.5 step 8 | Per-interface ingress limiter can't compute Hz |

### 15.3 Recommended: monotonic-with-no-skew across announces (timestamp encoding)

The §4.1 `random_hash` carries a 5-byte big-endian uint40 timestamp:

```python
random_hash = get_random_hash()[:5] + int(time.time()).to_bytes(5, "big")
```

Transit relays read `random_hash[5:10]` as a unix-seconds value and use it for path-table replay-ordering decisions (§4.5 step 6.3). Two requirements:

1. **Monotonic across announces from the same destination.** A new announce should have a higher timestamp than older ones from the same destination, or relays will reject it as "older than what we have cached" in the equal-or-greater-hop branch.
2. **Comparable to other peers' timestamps.** If all your announces always look like "year 1970" (boot-relative seconds presented as unix), you'll consistently lose path-replay comparisons against peers with real wall time. That's actually fine — your announces just won't replace cached entries from real-time peers — but the inverse case is the §9.10 microReticulum bug: random `random_hash[5:10]` looks "far future" and freezes the path table.

**No-RTC strategy:** emit boot-relative seconds. You'll always look stale to wall-time peers (their announces win in path-replace decisions, which is correct because their data is fresher), and you'll get monotonic-from-boot ordering between your own announces (correct).

**Wrong strategy:** emit fully-random bytes (the §9.10 microReticulum bug). Locks you in as "latest" forever.

### 15.4 Recommended: wall time (LXMF-level)

These use absolute Unix-seconds. A device without wall time can substitute, with caveats:

| Use | Section | Substitution if no wall time |
|---|---|---|
| LXMF body `timestamp` (`payload[0]`) | §5.3 | Use boot-relative seconds. Recipients per §9.6 should treat any timestamp before `1577836800` (2020-01-01) as "no clock" and substitute their local receive time. |
| Outgoing message `LXMessage.timestamp` for sender-side ordering | §5.3 | Same as above. |
| Stamp ticket expiry (`fields[FIELD_TICKET][0]`) | §5.7.3 | **You can't substitute here.** Tickets you issue with boot-relative seconds will appear to have already-expired-or-already-distant-future expiries to recipients. If your device has no wall time, don't issue tickets — fall back to PoW stamps (§5.7.2). |
| Propagation node `timebase` field in `/offer` requests | §5.8.5 | Same as random_hash strategy: boot-relative is fine; you'll appear "stale" but your peers' state stays consistent. |

### 15.5 Optional: high-resolution monotonic for diagnostics

These are nice-to-have; missing them just degrades observability:

- Per-packet RX timestamp for RTT decomposition.
- Airtime accounting (sub-second precision improves `ANNOUNCE_CAP` enforcement; integer seconds is fine).
- Resource transfer `establishment_rate` calculation.

Use whatever monotonic source your platform provides; even 1 ms resolution from `millis()` is plenty.

### 15.6 What fails on a no-RTC, no-NTP-sync device

A device that boots with no clock at all (`time.time()` returns a small integer, RTC chip absent or empty) and never syncs:

- ✅ **Sending and receiving opportunistic LXMF** works fine. The §9.6 receiver-side fix-up (substitute local receive time when timestamp < 2020) handles your "year 1970" timestamps cleanly.
- ✅ **Receiving propagated LXMF** works. The propagation node tags messages with its own timestamp; you don't need yours.
- ✅ **Establishing Links** works. RTT is measured locally and only used for relative cadences.
- ⚠️ **Periodic re-announces** work, but your `random_hash[5:10]` will always look stale to wall-time peers. Your announces propagate fine; they just don't win path-table replacement races against fresher peers (which is correct — they ARE fresher).
- ⚠️ **Path-table updates from your own announces** work the first time (no cached entry to compare against), but subsequent re-announces may not replace stale cache entries on transit relays. Practical effect: your destination is reachable but transit relays keep trying older paths longer than ideal.
- ❌ **Issuing LXMF tickets** doesn't work — the expiry timestamp in `FIELD_TICKET` is meaningless without wall time. Don't issue tickets; rely on PoW stamps.
- ❌ **Sending propagated LXMF with ticket-based stamp shortcuts** doesn't work for the same reason.

A single one-time clock sync (BLE config, web flasher, manual button-press at known time, GPS, `rnstatus` peer query) flips most of the ⚠️ items to ✅. The repeater repo's BLE config protocol can carry a clock value in the connection handshake; that's the simplest fix.

### 15.7 Source map

| Section | What relies on time |
|---|---|
| §4.1 | `random_hash[5:10]` emission timestamp |
| §4.5 step 6.3 | Path-table replacement using `random_blob` timestamps |
| §5.3 | LXMF body timestamp |
| §5.7.3 | LXMF ticket expiry |
| §5.8.5 | Propagation node timebase field |
| §6.7.1 | Link KEEPALIVE / RTT cadence |
| §7.1 | `Transport.path_requests` rate limit |
| §7.2 | `discovery_pr_tags` aging |
| §7.5 | Periodic re-announce cadence |
| §9.6 | Clockless sender LXMF timestamp fix-up |
| §10 | Resource watchdog timeouts |
| §13.4 | All `Transport.jobs` periodic intervals |

---

## 16. Test vectors

See [`test-vectors/`](test-vectors/). Currently populated:

- **`identities.json`** — Alice and Bob private-key inputs plus their derived `public_key`, `identity_hash`, and `lxmf.delivery` `destination_hash`. Verified by `tools/verify_destination_hash.py`; regenerated by `tools/regen_identities.py`. Covers SPEC.md §1.1 and §1.2.

> ⚠️ **UNVERIFIED:** The remaining vector categories — signed announce packets, encrypted opportunistic LXMF DATA, and Link handshake (LINKREQUEST + LRPROOF + derived session keys) — are not yet populated. See [`agent.md`](agent.md) §5 and [`todo.md`](todo.md) for the remaining bootstrap work.

An implementation that round-trips every test vector — both directions — should be wire-compatible with upstream Reticulum and LXMF for the covered operations.

---

## 17. Source map

Upstream Python sources, in rough order of frequency-of-reference:

| File | What lives here |
|---|---|
| `RNS/Identity.py` | Key generation, `to_file`/`from_file`, `validate_announce`, `recall` |
| `RNS/Destination.py` | `expand_name`, `name_hash`, destination hash construction |
| `RNS/Packet.py` | Header pack/unpack, packet types, contexts, `prove` |
| `RNS/Transport.py` | `outbound`, `inbound`, `request_path`, path table, HEADER_1↔2 |
| `RNS/Link.py` | Link establishment, LRPROOF, session-key derivation |
| `RNS/Cryptography/Token.py` | The Fernet-style Token format |
| `RNS/vendor/umsgpack.py` | The bundled msgpack with locked bin/str semantics |
| `RNS/Interfaces/TCPInterface.py` | TCPClient/TCPServer, including HDLC framing |
| `LXMF/LXMessage.py` | LXMF body pack/unpack, opportunistic vs link methods |
| `LXMF/LXMF.py` | `display_name_from_app_data`, `stamp_cost_from_app_data`, etc. |
| `LXMF/LXMRouter.py` | Delivery destination registration, announce-app-data assembly |

When upstream code changes such that this document drifts, please open a PR.
