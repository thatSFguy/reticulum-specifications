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

| Hex | Name | Used for |
|---|---|---|
| `0x00` | CTX_NONE | Default; opportunistic LXMF DATA, regular packets |
| `0x09` | CTX_REQUEST | Link REQUEST (NomadNet page fetch, propagation /get) |
| `0x0a` | CTX_RESPONSE | Link RESPONSE matching a REQUEST |
| `0xfd` | CTX_KEEPALIVE | Link keepalive |
| `0xff` | LRPROOF | Link request proof |

Other context values exist (per `RNS/Packet.py`) — these are the most-used in the LXMF-via-Link path.

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

The 64-byte `public_key` is the X25519 || Ed25519 concat described in section 1.1. `random_hash` is 10 random bytes that vary per emission to keep the packet hash unique even across rapid re-announces. The optional 32-byte `ratchet_pub` (an X25519 public key) is present iff the packet header's `context_flag` bit is 1. Indexing through this layout accordingly is mandatory; see `RNS/Identity.py::validate_announce` for the canonical parser.

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

Both initiator-side keys are **fresh ephemeral keys** (not the initiator's long-term identity). The 3-byte signalling field is optional and encodes path-MTU and link-mode hints.

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

### 6.5 Mandatory packet receipts

After processing each `CTX_NONE` DATA packet on an active link, the receiver MUST send back a `PROOF` packet (no context byte specifics) whose payload is the 32-byte SHA-256 of the received packet's hashable part. Without this, the sender's retransmit queue fires and the same packet arrives repeatedly, eventually exceeding the link's KEEPALIVE budget and tearing down the link. This is `Packet.prove_packet` upstream — non-optional for any client that wants to receive content over a Link without spamming the sender.

### 6.6 Source

`RNS/Link.py`, `RNS/Packet.py::prove`. The webclient's `reference/js-reference/link.js` is a faithful port.

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

The minimum responsibility for a non-transport leaf:

1. Detect inbound DATA packets with `dest_hash == path_request_dest`.
2. Parse first 16 bytes of payload as `target_hash`.
3. If `target_hash == our_destination_hash`, immediately call `sendAnnounce()`.
4. Otherwise (target is some other destination), do nothing — leaf clients can't fulfill path requests for destinations they don't OWN.

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

---

## 10. Test vectors

See [`test-vectors/`](test-vectors/). Currently populated:

- **`identities.json`** — Alice and Bob private-key inputs plus their derived `public_key`, `identity_hash`, and `lxmf.delivery` `destination_hash`. Verified by `tools/verify_destination_hash.py`; regenerated by `tools/regen_identities.py`. Covers SPEC.md §1.1 and §1.2.

> ⚠️ **UNVERIFIED:** The remaining vector categories — signed announce packets, encrypted opportunistic LXMF DATA, and Link handshake (LINKREQUEST + LRPROOF + derived session keys) — are not yet populated. See [`agent.md`](agent.md) §5 and [`todo.md`](todo.md) for the remaining bootstrap work.

An implementation that round-trips every test vector — both directions — should be wire-compatible with upstream Reticulum and LXMF for the covered operations.

---

## 11. Source map

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
