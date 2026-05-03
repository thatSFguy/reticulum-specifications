# Reticulum Wire Specifications

A byte-level reference for implementing Reticulum-compatible clients. This document focuses on what implementations need to interop with the canonical Python implementation ([`markqvist/Reticulum`](https://github.com/markqvist/Reticulum) and [`markqvist/LXMF`](https://github.com/markqvist/LXMF)) plus the existing client ecosystem (Sideband, Nomadnet, MeshChat, the various firmware projects).

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

The Python serializer writes private-key bytes as `Ed25519_priv(32) || X25519_priv(32)` — Ed25519 first, X25519 second. This is the **opposite** of the public_key concatenation order (`RNS/Identity.py:from_file` and `to_file`). Implementations that store/load identities to disk in a Python-compatible format must respect this.

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

### 5.7 Source

`LXMF/LXMessage.py` for pack/unpack; `LXMF/LXMF.py` for the app_data extraction helpers.

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

### 6.7 Source

`RNS/Link.py`, `RNS/Packet.py::prove`, `RNS/Identity.py::prove`, `RNS/PacketReceipt.py::validate_proof`. The webclient's `reference/js-reference/link.js` is a faithful port.

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

## 11. Test vectors

See [`test-vectors/`](test-vectors/). Currently populated:

- **`identities.json`** — Alice and Bob private-key inputs plus their derived `public_key`, `identity_hash`, and `lxmf.delivery` `destination_hash`. Verified by `tools/verify_destination_hash.py`; regenerated by `tools/regen_identities.py`. Covers SPEC.md §1.1 and §1.2.

> ⚠️ **UNVERIFIED:** The remaining vector categories — signed announce packets, encrypted opportunistic LXMF DATA, and Link handshake (LINKREQUEST + LRPROOF + derived session keys) — are not yet populated. See [`agent.md`](agent.md) §5 and [`todo.md`](todo.md) for the remaining bootstrap work.

An implementation that round-trips every test vector — both directions — should be wire-compatible with upstream Reticulum and LXMF for the covered operations.

---

## 12. Source map

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
