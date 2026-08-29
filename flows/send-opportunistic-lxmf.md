# Flow: send a single-packet opportunistic LXMF message

What happens chronologically when an app calls `LXMRouter.handle_outbound(lxm)` for an `LXMessage` whose `desired_method == OPPORTUNISTIC` and whose payload fits in a single Reticulum packet.

Pinned against **RNS 1.5.2 / LXMF 1.1.1**. Line numbers below are from those versions.

Out of scope: messages that need a Reticulum Link (`DIRECT` method, larger payloads), propagation-node delivery (`PROPAGATED`), and paper messages (`PAPER`). Each gets its own flow document.

---

## Preconditions

- Sender has an `RNS.Identity` (X25519 + Ed25519 keypair) and a delivery `RNS.Destination` of name `lxmf.delivery` registered with the local `LXMRouter`. See [`../SPEC.md`](../SPEC.md) §1.1.
- Sender has at some point received a `lxmf.delivery` announce from the recipient, which populated `RNS.Identity.known_destinations` with the recipient's public key (X25519 || Ed25519, 64 bytes total) and possibly a current ratchet pubkey. See SPEC.md §4.
- Network has a path to the recipient — either present in `Transport.path_table`, or about to be discovered by the path-request preamble in step 4 below.

---

## Sequence

### 1. App constructs `LXMessage` and submits it

```python
lxm = LXMF.LXMessage(
    destination = recipient_destination,    # RNS.Destination, type SINGLE
    source      = my_lxmf_delivery_dest,    # my own SINGLE destination
    content     = b"hello",
    title       = b"",
    fields      = {},
    desired_method = LXMF.LXMessage.OPPORTUNISTIC,
)
router.handle_outbound(lxm)
```

`recipient_destination` does not need to be an `RNS.Destination` instance with the recipient's full identity — `RNS.Destination` accepts a 16-byte identity hash via `RNS.Identity.recall(...)` and looks the public key up from the announce cache. The router/library handles this; the app supplies a hash.

### 2. `LXMessage.pack()` builds the body and signs it

`LXMF/LXMessage.py:355-461` → `def pack(self, payload_updated=False)`. Runs once per message. Constructs the LXMF body that will eventually become the Reticulum packet payload after Token encryption.

```
payload      = msgpack.packb([timestamp_double, title_bytes, content_bytes, fields_dict])
hashed_part  = dest_hash(16) || src_hash(16) || payload
message_hash = SHA256(hashed_part)                                # = self.hash, also used as message_id
signed_part  = hashed_part || message_hash
signature    = Ed25519_sign(signed_part, src_identity.Ed25519_priv)
self.packed  = dest_hash(16) || src_hash(16) || signature(64) || payload
```

The dual `payload` packing (once for the hash, then again with optional `stamp` appended) is documented at SPEC.md §5.5. Wire-form layout for opportunistic delivery is SPEC.md §5.1: the dest_hash is **stripped** before transmission because it appears in the outer Reticulum packet header (`__as_packet` slices `self.packed[16:]` at step 6).

### 3. Method and representation are fixed

`LXMF/LXMessage.py:397-411` → `raise TypeError(f"LXMessage desired opportunistic delivery method`. With `desired_method == OPPORTUNISTIC`:

- If the payload size exceeds `ENCRYPTED_PACKET_MAX_CONTENT`, the router **silently downgrades** to `DIRECT` (Link) and the rest of this flow does not apply — see `send-link-lxmf.md` (TODO).
- Otherwise, `self.method = OPPORTUNISTIC`, `self.representation = PACKET`, `self.__delivery_destination = self.__destination`.

### 4. Path preamble (conditional)

`LXMF/LXMRouter.py::handle_outbound`, line 1746-1795 (verified by [`../tools/verify_path_request.py`](../tools/verify_path_request.py)):

```python
if not RNS.Transport.has_path(destination_hash) and lxmessage.method == LXMessage.OPPORTUNISTIC:
    RNS.Transport.request_path(destination_hash)
    lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
```

Only fires when **no entry exists** in `Transport.path_table`. Stale-but-present entries are not refreshed by this preamble — they are evicted by the periodic `stale_paths` accumulator in `RNS/Transport.py:780+`, after which the next outbound attempt rediscovers the unknown-path branch and triggers `request_path`. The path-request packet itself (well-known dest hash `6b9f66014d9853faab220fba47d02761`, payload `target_dest_hash || [transport_id ||] tag`) is described in SPEC.md §7.1.

When this preamble fires the message is queued, not sent — control returns; sending resumes at step 5 after `PATH_REQUEST_WAIT` elapses or an announce response populates the path table.

### 5. `LXMessage.send()` chooses the wire path

`LXMF/LXMessage.py:463-508` → `def send(self)`. For `OPPORTUNISTIC`:

```python
self.determine_transport_encryption()
self.determine_compression_support()
lxm_packet = self.__as_packet()                              # step 6
lxm_packet.send().set_delivery_callback(self.__mark_delivered)
self.state = LXMessage.SENT
```

`set_delivery_callback` arms the LXMF-level "delivered" notification, which fires when the underlying Reticulum `PacketReceipt` resolves (step 12).

### 6. `__as_packet()` constructs the `RNS.Packet`

`LXMF/LXMessage.py:626-638` → `def __as_packet(self)`:

```python
RNS.Packet(self.__delivery_destination, self.packed[LXMessage.DESTINATION_LENGTH:])
```

Note the slice `[16:]`: the recipient's dest_hash is removed because it is implicit in the outer Reticulum header (SPEC.md §5.1). What remains as the packet's `data` is `src_hash || signature || msgpack_payload` — still in plaintext at this point.

### 7. `RNS.Packet.pack()` encrypts and frames

`RNS/Packet.py:178-240` → `def pack(self)`. For a `SINGLE` destination, packet_type `DATA`, context `CTX_NONE`, header_type `HEADER_1`:

1. **Header bytes**: `flags(1) || hops(1) || dest_hash(16) || context(1)` — SPEC.md §2.1, §2.2.
2. **Encryption** (line 215): `self.ciphertext = self.destination.encrypt(self.data)` — calls `RNS.Destination.encrypt` which delegates to the Token construction (SPEC.md §3):

```
ephemeral_pub(32) || iv(16) || aes_ciphertext(...) || hmac_sha256(32)
```

   The recipient X25519 public key used for ECDH is the latest announced ratchet pub if known, else the recipient's long-term encPub (first 32 bytes of the 64-byte public_key). HKDF salt is the recipient's 16-byte identity hash, **not** the destination hash and **not** the ratchet hash.

3. **Final wire packet** = `header(19) || token_ciphertext`.

`packet.ratchet_id` is set from `destination.latest_ratchet_id` for later forensics if available.

### 8. `Transport.outbound(packet)` — path-table-aware framing

`RNS/Transport.py:1302-1552` → `def _outbound(packet)`. Verified by [`../tools/verify_packet_header.py`](../tools/verify_packet_header.py).

- If `path_table[dest][HOPS] > 1`: convert HEADER_1 → HEADER_2 (SPEC.md §2.3). The originator inserts `path_table[dest][NEXT_HOP]` (16-byte transport_id) at offset 2 and flips the flag bits to `HEADER_2 | TRANSPORT | (orig_low_nibble)`. Resulting wire packet is 35 + ciphertext bytes.
- If `path_table[dest][HOPS] == 1` AND the local node is connected to a shared instance: same conversion applies (lines 1094-1105).
- Otherwise (0 hops or destination not in path table): emit HEADER_1 unchanged. The 0-hop case relies on the receiving rnsd auto-filling the transport_id when the destination matches a local client (`for_local_client` branch at line 1451).

Then `Transport.transmit(interface, raw)` is called for the chosen `outbound_interface`.

### 9. Interface framing

The outbound interface wraps the raw packet bytes. SPEC.md §8:

- **TCP** (`TCPClientInterface` / `TCPServerInterface` / `AutoInterface`): HDLC. `0x7E` start/end, escape `0x7E → 0x7D 0x5E`, `0x7D → 0x7D 0x5D`. No command byte.
- **Serial / BLE / RNode** (`KISSInterface`, `RNodeInterface`, `LoRaInterface`, etc.): KISS. `0xC0` start/end, escape `0xC0 → 0xDB 0xDC`, `0xDB → 0xDB 0xDD`. Command byte for outbound Reticulum packets is `CMD_DATA = 0x00`.

For BLE specifically, the framed bytes may be split across multiple BLE notifications by the link-layer MTU; reassembly happens on the peer at the KISS-parser level.

### 10. Wire bytes leave

The interface driver writes the framed bytes to the underlying transport (socket, serial port, BLE GATT characteristic, etc.). After this step the sender has no further control over the bytes.

---

## What happens after the bytes go out

Strictly speaking, the flow above ends at step 10. Steps 11-13 are about **what the sender observes back** and are part of the same "send" cycle from the application's point of view.

### 11. Recipient processes the inbound DATA packet

Inverse of steps 7-9, in the order: deframe → optional HEADER_2 strip / hop-table lookup → packet enters `Transport.inbound` → handed to the destination → `RNS.Destination.decrypt` reverses the Token (HMAC verified **before** AES decrypt per SPEC.md §3.3) → LXMF body parsed → Ed25519 signature verified, with the dual-msgpack-variant tolerance described in SPEC.md §5.6 → message surfaced to the recipient's app.

The receive flow is its own document; see `receive-opportunistic-lxmf.md` (TODO) for the detailed step list.

### 12. PROOF receipt returns

`RNS/Transport.py:1369-1386` → `generate_receipt = True`. Because the packet is `DATA` for a non-PLAIN, non-LINK destination with `create_receipt == True`, `Transport.outbound` registered a `PacketReceipt` on the sender side. When the recipient calls `Packet.prove`, a PROOF packet flies back containing `SHA256(packet.hashable_part)`; the sender's `PacketReceipt` matches it, fires the delivery callback registered at step 5, and the LXMessage state advances `SENT → DELIVERED`.

If no proof arrives within the receipt timeout, `__link_packet_timed_out` runs on the receipt's timeout callback and the LXMessage state can drive a retry (see `LXMRouter.py::process_outbound` retry logic at `:2571+`, which may itself trigger a fresh `request_path` after `MAX_PATHLESS_TRIES`).

### 13. Background: ratchet rotation and re-announce

In parallel to the send, two timers run:

- **Re-announce** every 5-15 min (SPEC.md §7.5, §9.7). Without this, transit nodes' path tables age out and step 4's path preamble starts firing for every send.
- **Ratchet rotation** on each `sendAnnounce()` if `now > latest_ratchet_time + RATCHET_INTERVAL` (`RNS/Destination.py::rotate_ratchets`, line 227-235; `RATCHET_INTERVAL = 30*60` at line 90). The receiver's ratchet ring (`RATCHET_COUNT = 512` upstream default at line 85) lets it still decrypt in-flight messages encrypted to a recently-rotated-out ratchet.

Neither timer is part of *this* send, but both are required for the flow to keep working across the next send.

---

## Wire-byte summary

For a 0/1-hop opportunistic LXMF DATA send (`HEADER_1`, no transport_id insertion):

```
[ 1B flags ][ 1B hops=0 ][ 16B dest_hash ][ 1B context=0x00 ]
[ 32B ephemeral_X25519_pub ][ 16B iv ][ N×16B aes_ciphertext ][ 32B hmac_sha256 ]
                            └──── Token-encrypted LXMF body ─────────────────┘
                            plaintext is: 16B src_hash || 64B Ed25519_sig || msgpack_payload
```

After interface framing (KISS or HDLC) the byte sequence above gets escape-encoded and bracketed by the framing delimiters (`0xC0…0xC0` for KISS with a leading `0x00` cmd byte; `0x7E…0x7E` for HDLC).

For a >1-hop send with a known path the originator emits `HEADER_2` instead, with the 16-byte next-hop transport_id inserted at offset 2 (between the hops byte and the dest_hash). All other bytes are unchanged.

---

## Source map for this flow

| Step | File | Function / line |
|---|---|---|
| 1 | (app code) | constructs `LXMF.LXMessage` |
| 2 | `LXMF/LXMessage.py` | `pack`, line 355-461 |
| 3 | `LXMF/LXMessage.py` | method/representation gate, line 397-411 |
| 4 | `LXMF/LXMRouter.py` | `handle_outbound`, line 1746-1795 |
| 5 | `LXMF/LXMessage.py` | `send`, line 463-508 |
| 6 | `LXMF/LXMessage.py` | `__as_packet`, line 626-638 |
| 7 | `RNS/Packet.py` | `pack`, line 178-240; encrypt at line 217 |
| 7 | `RNS/Cryptography/Token.py` | Token encrypt |
| 8 | `RNS/Transport.py` | `_outbound`, line 1302-1552 |
| 9 | `RNS/Interfaces/*.py` | per-interface KISS or HDLC framing |
| 12 | `RNS/Transport.py` | `_outbound` receipt setup, line 1307-1324 |
| 12 | `RNS/Packet.py` | `prove` |
| 13 | `RNS/Destination.py` | `rotate_ratchets`, line 228-242 |
