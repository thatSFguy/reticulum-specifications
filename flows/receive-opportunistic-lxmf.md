# Flow: receive a single-packet opportunistic LXMF message

The inverse of [`send-opportunistic-lxmf.md`](send-opportunistic-lxmf.md). What happens chronologically on the recipient when wire bytes for an opportunistic LXMF DATA packet arrive at one of its interfaces.

Pinned against **RNS 1.2.4 / LXMF 0.9.7**. Line numbers below are from those versions.

Out of scope: receiving a packet over an established Reticulum Link (DIRECT method), receiving propagated messages from a propagation node, and receiving an announce / path-request / link-request. Each gets its own flow document.

---

## Preconditions

- Recipient has an `RNS.Identity` with the X25519 + Ed25519 private keys, plus a `lxmf.delivery` `RNS.Destination` registered with `LXMRouter.register_delivery_identity` — that registration calls `delivery_destination.set_packet_callback(self.delivery_packet)` at `LXMF/LXMRouter.py:340`, which is the hand-off point in step 7 below.
- Recipient has, at some point, been the target of one or more announces from the sender, so `RNS.Identity.known_destinations` knows the sender's full `public_key` (X25519 || Ed25519) under their `dest_hash`. Without this, signature validation in step 11 will fail with `unverified_reason = SOURCE_UNKNOWN`.

---

## Sequence

### 1. Wire bytes arrive at the interface

Per [`../SPEC.md`](../SPEC.md) §8, the bytes arrive escape-encoded inside KISS frames (BLE / serial / RNode), HDLC frames (TCP), or whatever framing the interface uses. The interface driver deframes and passes the raw Reticulum packet bytes to `RNS.Transport.inbound`.

For RNode KISS specifically, `CMD_STAT_RSSI = 0x23` and `CMD_STAT_SNR = 0x24` sidecar frames received just before the `CMD_DATA = 0x00` payload populate `interface.r_stat_rssi` and `interface.r_stat_snr`; these are attached to the packet at step 4 below.

### 2. `Transport.inbound(raw, interface)` entry point

`RNS/Transport.py:1330`. The single entry point for any inbound packet on any interface. The function is gated by `Transport.ready` — packets arriving before transport startup are dropped with a warning.

### 3. IFAC unmask (Interface Authentication Codes)

`RNS/Transport.py:1338-1390`. If the interface has an `ifac_identity` configured, the high bit of `raw[0]` must be set; the IFAC bytes at `raw[2:2+ifac_size]` are then used to derive an HKDF mask, the rest of the packet is unmasked in place, and the IFAC is verified against `ifac_identity.sign(unmasked_raw)[-ifac_size:]`. Mismatch drops the packet silently.

If the interface has no IFAC and the high bit IS set, the packet is dropped (an unexpected IFAC).

### 4. Packet parse and physical-layer stats

`RNS/Transport.py:1394-1398`:

```python
packet = RNS.Packet(None, raw)
if not packet.unpack(): return
packet.receiving_interface = interface
packet.hops += 1
```

`packet.unpack` reads the header byte fields per SPEC.md §2.1, sets `packet.header_type`, `packet.packet_type`, `packet.destination_type`, `packet.destination_hash`, `packet.context`, and slices `packet.data` from the remainder. Importantly, **hops is incremented by 1 here**, so even on a leaf-endpoint receive the local `packet.hops` is one more than what flew on the wire — flow logic that treats `packet.hops == 0` as "originator on this interface" must use the wire byte before this increment.

RSSI / SNR / Q link-quality stats are attached to `packet` if the interface exposed them (`RNS/Transport.py:1400-1420`).

### 5. Hop fix-up for shared-instance and local-client interfaces

`RNS/Transport.py:1422-1425`. If the receiving interface is to a local shared instance or a local-client TCP socket, the +1 increment from step 4 is undone — the shared-instance path doesn't count as a real network hop.

### 6. Dedup, then dispatch by packet_type / destination_type

`RNS/Transport.py:1427-1447`. `Transport.packet_filter` checks `packet.packet_hash` against `Transport.packet_hashlist` to drop replays. Hashes are added to the dedup list except for two cases that must be deferred:

- packet whose `destination_hash` is in `Transport.link_table` — the dedup decision is left to the link itself,
- LRPROOF packets — these may legitimately arrive on multiple interfaces during routing-fork chaos and the dedup list is updated only after the LRPROOF is validated.

Then the function fans out by `(packet_type, destination_type)`. For an opportunistic LXMF DATA packet — `packet_type == DATA`, `destination_type == SINGLE` — control reaches `RNS/Transport.py:2090-2106`:

```python
destination = Transport.destinations_map.get(packet.destination_hash)
if destination and destination.type == packet.destination_type:
    packet.destination = destination
    if destination.receive(packet):
        if destination.proof_strategy == RNS.Destination.PROVE_ALL:
            packet.prove()                                              # see step 12 below
        elif destination.proof_strategy == RNS.Destination.PROVE_APP:
            if destination.callbacks.proof_requested:
                if destination.callbacks.proof_requested(packet):
                    packet.prove()
```

If `destination_hash` does not match any locally-registered destination, this branch is not taken; the packet may still be **forwarded** by other branches in `Transport.inbound` (the routing-relay path) but that's a separate flow.

### 7. `Destination.receive(packet)` — decrypt and run packet callback

`RNS/Destination.py:403-450`:

```python
def receive(self, packet):
    if packet.packet_type == RNS.Packet.LINKREQUEST:
        self.incoming_link_request(packet.data, packet)        # see send-link-lxmf.md
    else:
        plaintext = self.decrypt(packet.data)
        packet.ratchet_id = self.latest_ratchet_id
        if plaintext == None: return False
        if packet.packet_type == RNS.Packet.DATA:
            self.callbacks.packet(plaintext, packet)
        return True
```

For `lxmf.delivery` destinations, `self.callbacks.packet` was set at `LXMF/LXMRouter.py:340` to the router's `delivery_packet` — see step 9.

### 8. `Destination.decrypt` → `Identity.decrypt` — Token decode with ratchet ring

`RNS/Destination.py:611-645` → `RNS/Identity.py:849-905`. The packet body is the Token form from SPEC.md §3.1: `ephemeral_pub(32) || iv(16) || aes_ciphertext || hmac_sha256(32)`.

```python
peer_pub_bytes = ciphertext_token[:32]                     # sender's ephemeral X25519 pub
ciphertext     = ciphertext_token[32:]                     # iv || aes || hmac

if ratchets:
    for ratchet in ratchets:                               # most-recent-first
        ratchet_prv = X25519PrivateKey.from_private_bytes(ratchet)
        shared_key  = ratchet_prv.exchange(peer_pub)
        plaintext   = self.__decrypt(shared_key, ciphertext)   # HMAC-then-AES via Token
        if plaintext: break

if plaintext is None and not enforce_ratchets:             # fallback to long-term key
    shared_key = self.prv.exchange(peer_pub)
    plaintext  = self.__decrypt(shared_key, ciphertext)
```

`Token.decrypt` (`RNS/Cryptography/Token.py`) verifies the HMAC **before** AES decryption per SPEC.md §3.3 — a bad HMAC simply means "wrong key, try the next one in the ring" rather than a padding-oracle exposure. If all ratchet keys + the long-term key fail, `plaintext` is `None` and the packet is silently dropped.

The matching ratchet's id is stored on the packet via `ratchet_id_receiver.latest_ratchet_id`, so `delivery_packet` can later annotate the LXMessage with which ratchet it arrived under.

If the destination has ratchets enabled but on-disk state has gone stale, `Destination.decrypt` retries once after `_reload_ratchets` (`RNS/Destination.py:631`), then gives up.

### 9. `LXMRouter.delivery_packet(data, packet)` — proof first, then async parse

`LXMF/LXMRouter.py:1822-1850`:

```python
def delivery_packet(self, data, packet):
    packet.prove()                                          # see step 12
    if packet.destination_type != RNS.Destination.LINK:
        method    = LXMessage.OPPORTUNISTIC
        lxmf_data = packet.destination.hash + data          # re-prepend stripped dest_hash
    else:
        method    = LXMessage.DIRECT
        lxmf_data = data

    threading.Thread(target=lambda: self.lxmf_delivery(lxmf_data, ...), daemon=True).start()
```

The PROOF receipt fires **before** the message is parsed — the sender's delivery callback resolves as soon as the bytes are decrypted and authenticated by the destination, not after the LXMF body is validated. This means a malformed LXMF body still produces a successful Reticulum-level delivery proof; LXMF-level rejection only manifests as the message never appearing in the recipient's inbox.

The opportunistic-form re-prepends `packet.destination.hash` because step 6 of the send flow sliced it off — SPEC.md §5.1 vs §5.2. After this prepend, both opportunistic and Link-delivered LXMessages share the same fixed-position body: `dest_hash || src_hash || signature || msgpack_payload`, so step 10 can use one parser.

### 10. `LXMessage.unpack_from_bytes(lxmf_data)` — body parse and signature validation

`LXMF/LXMessage.py:736-810`. Field slicing:

```
destination_hash = lxmf_data[ 0:16]
source_hash      = lxmf_data[16:32]
signature        = lxmf_data[32:96]
packed_payload   = lxmf_data[96:]
```

`packed_payload` is unpacked with `RNS.vendor.umsgpack` (the bundled msgpack — bin/str behavior locked per SPEC.md §9.3). The first 4 elements are `[timestamp_double, title_bytes, content_bytes, fields_dict]`; an optional 5th element is the LXMF stamp. **If a 5th element is present**, it is split off, `packed_payload` is **re-encoded** from the first 4 elements, and the new `packed_payload` is what's used to compute `message_hash` and feed signature validation. If only 4 elements are present, the as-received bytes are used unchanged.

```
hashed_part  = destination_hash || source_hash || (re-encoded-or-raw) packed_payload
message_hash = SHA256(hashed_part)
signed_part  = hashed_part || message_hash
```

Signature validation calls `source.identity.validate(signature, signed_part)`. The sender's identity is recalled from `RNS.Identity.known_destinations` via `RNS.Identity.recall(source_hash)` at line 765 — keyed by the sender's **destination hash**, not their identity hash, per SPEC.md §5.4 and §9.1. If the sender is unknown locally (no announce ever received), `unverified_reason = SOURCE_UNKNOWN` and `signature_validated = False`; the message is still surfaced to the app callback in step 12, but downstream UI should mark it untrusted.

Note: `unpack_from_bytes` does the stamp-strip-and-reencode variant but does **not** also try the as-received `packed_payload` if validation fails. SPEC.md §5.6 documents both raw and stripped-reencoded as valid receiver behavior; upstream LXMF 0.9.7 only does the stripped form (or the raw form when no stamp was present). The spec's stronger receiver tolerance is a recommendation for non-upstream implementers, not a description of upstream.

### 11. Stamp / ticket / dedup checks

`LXMF/LXMRouter.py:1741-1810`:

- **Ticket** (`message.fields[FIELD_TICKET]`): if present and non-expired, cached for outbound use.
- **Stamp**: if the local destination has a `stamp_cost`, `message.validate_stamp(required_cost, tickets=...)` runs; a missing/invalid stamp causes the message to be dropped when `_enforce_stamps` is true.
- **Phy stats**: RSSI / SNR / Q copied onto the LXMessage from `phy_stats`.
- **Ignore list**: messages from `source_hash in self.ignored_list` are dropped silently.
- **Dedup**: `self.has_message(message.hash)` checks `locally_delivered_transient_ids`; duplicates are dropped (the previously-seen `message.hash` was added on first delivery at line 1803).

### 12. `__delivery_callback` fires — message reaches the app

`LXMF/LXMRouter.py:1812-1820`. The router's caller (Sideband, NomadNet, MeshChat, …) sets `__delivery_callback` via `register_delivery_callback(...)`. It receives the validated `LXMessage` object and decides what to show in the inbox.

Important: the recipient's app should apply the SPEC.md §9.6 clockless-sender heuristic at this point — `if message.timestamp < 1577836800: message.timestamp = local_now()` — to keep clockless LoRa devices out of January 1970 in the inbox. Upstream `LXMessage.unpack_from_bytes` does **not** do this fix-up.

### 13. PROOF receipt back to the sender

Already triggered by `packet.prove()` at the top of step 9. `RNS/Packet.py::prove` constructs a PROOF packet whose body is `SHA256(received_packet.get_hashable_part())` (32 bytes), signed by the receiving destination's Ed25519 long-term private key (32 bytes signature appended in non-implicit mode). The PROOF travels back along the reverse path and resolves the sender's `PacketReceipt`, completing the SENT → DELIVERED transition on the sender side (send flow step 12).

For a destination with `proof_strategy == PROVE_ALL` this happens unconditionally; for `PROVE_APP` an app callback decides per-packet (step 6 above). Default `proof_strategy` is `PROVE_NONE`, but `LXMRouter.delivery_packet` calls `packet.prove()` directly so it works regardless of the destination's strategy.

### 14. Self-announce-echo guard (cross-cutting, not per-message)

SPEC.md §9.5: if the operator runs both an originator and a transport node on the same machine, the recipient may receive its own packets. For DATA packets specifically the `Transport.destinations_map` lookup in step 6 still resolves to a local destination, so the message is processed normally — opportunistic-LXMF delivered to oneself works. For announces (a different flow) the self-echo can populate the contacts list with one's own destination; that's what §9.5 warns about.

---

## Wire-byte summary (mirror of the send-flow summary)

What arrives at the recipient before deframing — assumes a 0-hop direct send (HEADER_1) or a >1-hop relayed packet that arrives as HEADER_2 with a transport_id at offset 2:

```
HEADER_1:
[ 1B flags ][ 1B hops ][ 16B dest_hash ][ 1B context=0x00 ]
[ 32B sender_ephemeral_X25519_pub ][ 16B iv ]
[ N×16B aes_ciphertext ][ 32B hmac_sha256 ]

HEADER_2 (after relay):
[ 1B flags ][ 1B hops ][ 16B transport_id ][ 16B dest_hash ][ 1B context=0x00 ]
[ 32B sender_ephemeral_X25519_pub ][ 16B iv ]
[ N×16B aes_ciphertext ][ 32B hmac_sha256 ]
```

After AES-CBC decryption with the matching ratchet (or long-term) key, the plaintext is the opportunistic LXMF body **without** the recipient's dest_hash (SPEC.md §5.1):

```
[ 16B src_hash ][ 64B Ed25519_signature ][ msgpack_payload ]
```

Step 9 re-prepends `packet.destination.hash` so step 10 can parse with the same field offsets used for Link-delivered LXMF (SPEC.md §5.2).

---

## Source map for this flow

| Step | File | Function / line |
|---|---|---|
| 1 | `RNS/Interfaces/*.py` | per-interface KISS / HDLC deframer |
| 2 | `RNS/Transport.py` | `inbound`, line 1327 |
| 3 | `RNS/Transport.py` | IFAC unmask, line 1338 |
| 4 | `RNS/Transport.py` | parse + hops, line 1391 |
| 4 | `RNS/Packet.py` | `unpack` |
| 5 | `RNS/Transport.py` | hop fix-up, line 1419 |
| 6 | `RNS/Transport.py` | dedup + dispatch, line 1424; DATA/SINGLE branch line 2087 |
| 7 | `RNS/Destination.py` | `receive`, line 403 |
| 8 | `RNS/Destination.py` | `decrypt`, line 611 |
| 8 | `RNS/Identity.py` | `decrypt`, line 818 |
| 8 | `RNS/Cryptography/Token.py` | `Token.decrypt` |
| 9 | `LXMF/LXMRouter.py` | `delivery_packet`, line 1819 |
| 10 | `LXMF/LXMessage.py` | `unpack_from_bytes`, line 736 |
| 11 | `LXMF/LXMRouter.py` | `lxmf_delivery`, line 1732 |
| 12 | `LXMF/LXMRouter.py` | delivery callback dispatch, line 1805 |
| 13 | `RNS/Packet.py` | `prove` |
