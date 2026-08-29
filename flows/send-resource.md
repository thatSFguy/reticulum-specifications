# Flow: send a Resource (large body) over a Link

What happens chronologically when an LXMF DIRECT message, NomadNet page, or `rncp` file transfer too big to fit in one Link DATA packet is sent as an `RNS.Resource`. Builds on top of an established Reticulum Link — a Link must already be `ACTIVE` before this flow starts (see [`send-link-lxmf.md`](send-link-lxmf.md) steps 3-4 for how the Link gets there).

Pinned against **RNS 1.5.2**. Wire-level details are in [`../SPEC.md`](../SPEC.md) §10; this document covers chronology and step ordering.

Out of scope: the receive side (`receive-resource.md` — TODO), Resource cancellation paths beyond a brief mention in step 9, and the watchdog / RTT estimation machinery (implementation-private).

---

## Preconditions

- The sender holds an `RNS.Link` to the recipient with `link.status == ACTIVE`. The Link's session key (§3.1 Link-derived form) is what encrypts the Resource body.
- The body to send is a `bytes` object (small payloads), or a file-like with a `.read()` method (large or streaming payloads — the constructor will spool to a temp file if needed).
- The Link's MTU is stable for the duration of the transfer. Resource part sizes are baked in at advertisement time; if the Link's MTU shrinks mid-transfer, the resource is cancelled rather than re-fragmented.

---

## Sequence

### 1. Caller constructs the `RNS.Resource`

For LXMF DIRECT/RESOURCE, this happens in `LXMessage.__as_resource` (`LXMF/LXMessage.py:654` → `RNS.Resource(self.packed, self.__delivery_destination`):

```python
RNS.Resource(self.packed, self.__delivery_destination,
             callback=self.__resource_concluded,
             progress_callback=self.__update_transfer_progress,
             auto_compress=self.auto_compress)
```

For other callers (NomadNet page server, `rncp`) the call site differs but the constructor signature is the same.

### 2. `Resource.__init__` runs the preparation pipeline

`RNS/Resource.py:248-476` → `def __init__(self, data, link, metadata=None`. In order:

1. **Metadata prefix** if `metadata=` was given: prepend `length(3 bytes BE uint24) || msgpack(metadata)` to the body. Sets `has_metadata = True`, `x` flag in the advertisement.
2. **Choose data backing.** If `data` is `bytes` and `len(data) + metadata_size > MAX_EFFICIENT_SIZE = 1 MiB - 1`, the constructor spools it to a `tempfile.TemporaryFile()` and switches to file-backed mode. Bytes-backed mode is single-segment; file-backed mode may be multi-segment per [`../SPEC.md`](../SPEC.md) §10.11.
3. **Optional bz2 compression.** If `auto_compress` and the body fits within `auto_compress_limit` (default 64 MiB): `bz2.compress(uncompressed)`. Keep the smaller of the two; set the `c` flag accordingly.
4. **Random hash prefix.** Prepend 4 random bytes (`Resource.RANDOM_HASH_SIZE`) to whatever body was selected.
5. **Compute hashes.**
   - `hash = SHA256(data || random_hash)` (note the random_hash appears at both the start of `data` and at the end of the SHA-256 input — this is intentional; the same random_hash bytes serve as both a per-resource salt for the wire and as a tail to break SHA-256 length-extension correlations between similar resources).
   - `truncated_hash = hash[:16]`
   - `expected_proof = SHA256(data || hash)` — what the receiver will return as the second 32 bytes of the RESOURCE_PRF body.
6. **Link encryption.** `data = link.encrypt(data)` — wraps the whole `random_hash || maybe_compressed_body` in the Link-derived Token form (§3.1: `iv(16) || ciphertext || hmac(32)`, no ephemeral_pub prefix). Sets `e = True`. The encryption is over the **whole** payload at once, not per-part — see SPEC.md §10.12.
7. **Part split.** Slice the encrypted blob into parts of `SDU = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE` bytes each. Each part is built into a `RNS.Packet(link, part_data, context=RESOURCE)` and pre-packed; the wire bytes live in `parts[i].raw`.
8. **Hashmap.** For each part, `map_hash = get_map_hash(part_data)` (4 bytes). The `hashmap` is the concatenation of all 4-byte map_hashes.
9. **Collision guard.** Walk the hashmap with a sliding `COLLISION_GUARD_SIZE = 2 * WINDOW_MAX + HASHMAP_MAX_LEN` window. If any duplicate map_hash appears within that window, **regenerate `random_hash`, recompute `hash` / `expected_proof`, re-pack every part, and rebuild the hashmap.** Loop until clean. This is what guarantees the receiver can search a windowed slice of the hashmap to disambiguate inbound parts (SPEC.md §10.6).

After step 9, `total_parts = len(parts)`, `total_segments = ceil((data_size + metadata_size) / MAX_EFFICIENT_SIZE)`, `total_size = data_size + metadata_size`, and the resource is ready to advertise.

### 3. `Resource.advertise()` sends RESOURCE_ADV

`RNS/Resource.py:508-550` → `def advertise(self)`. Runs in a daemon thread because the build above can take a noticeable time on a large resource.

```python
adv_packet = RNS.Packet(self.link,
                        ResourceAdvertisement(self).pack(),
                        context=RNS.Packet.RESOURCE_ADV)
adv_packet.send()
self.status = Resource.ADVERTISED
self.adv_sent = time.time()
```

`ResourceAdvertisement(self).pack()` returns msgpack bytes of the dict in SPEC.md §10.4 — the `m` field carries up to `HASHMAP_MAX_LEN ≈ ⌊(LINK_MDU - 134)/4⌋` map_hashes (i.e. enough for a moderate transfer; multi-segment hashmaps continue via RESOURCE_HMU in step 7 below).

The advertisement packet is sent as a regular Link DATA packet (so it is Token-encrypted by the Link's session key) and gets a Reticulum-level PROOF receipt back per SPEC.md §6.5.

### 4. Watchdog: retry advertisement up to MAX_ADV_RETRIES

`RNS/Resource.py:576-589` → `if self.status == Resource.ADVERTISED:`. While `status == ADVERTISED` and no RESOURCE_REQ has arrived, the watchdog retransmits the advertisement up to `MAX_ADV_RETRIES = 4` times. After the 4th retry without a request, the resource is cancelled with status `FAILED` and a callback to the caller.

Reasons the advertisement might not solicit a response:
- The receiver's app rejected it via `Resource.reject(adv_packet)` (returns `RESOURCE_RCL`).
- The Link's RTT is so long that the watchdog's `PROOF_TIMEOUT_FACTOR = 3` window expires before any reply.
- The Link torn down between advertisement and first request.

### 5. First RESOURCE_REQ arrives → fulfillment loop

`RNS/Resource.py:985-1079` → `def request(self, request_data)`. The receiver has parsed the advertisement, accepted it, and now requests an initial window's worth of parts via a RESOURCE_REQ packet:

```
body = hashmap_exhausted_flag(1) [|| last_map_hash(4) if exhausted]
       || resource_hash(32)
       || requested_map_hashes(N × 4 bytes)
```

Per SPEC.md §10.5. The initiator's `request(request_data)` handler:

1. Checks `request_data[0]` — exhausted flag.
2. Pad past the optional `last_map_hash` and the `resource_hash` to extract the variable-length tail of requested map_hashes.
3. **Search scope:** look only inside `parts[receiver_min_consecutive_height : receiver_min_consecutive_height + COLLISION_GUARD_SIZE]`. This is what makes the collision guard meaningful — the search range is bounded so the per-window uniqueness guarantee from step 2.9 is sufficient.
4. For each requested map_hash, find the matching part and call `part.send()` (or `part.resend()` if it was sent previously). Each fulfilled part is a single Link DATA packet with `context = RESOURCE (0x01)`.
5. Update `self.last_part_sent` and `self.last_activity` for the watchdog.

Each part packet is itself a Link DATA packet, so it gets a Reticulum-level PROOF receipt back from the receiver per SPEC.md §6.5 — meaning every part involves two round-trips: one for the part itself and one for its Reticulum-level proof.

### 6. Receiver requests next window

After the receiver has placed all the requested parts into its `parts[]` array, it sends another RESOURCE_REQ for the next window. The window may have grown (`window += 1` per successful round, capped at `window_max` per SPEC.md §10.10). This continues until the receiver has consumed every map_hash in the current hashmap segment.

### 7. RESOURCE_HMU — feeding the next hashmap segment

If the resource has more parts than fit in the original advertisement's `m` field (`n > HASHMAP_MAX_LEN`), the receiver eventually exhausts the known hashmap. It then sends a RESOURCE_REQ with `exhausted = 0xFF` and `last_map_hash = ` the last known map_hash.

The initiator's `request()` handler at `RNS/Resource.py:1030-1079` → `if wants_more_hashmap:`:

1. Locate the `last_map_hash` in `self.hashmap`. The position must land on a `HASHMAP_MAX_LEN` boundary; if not, treat it as a sequencing error and cancel the resource.
2. Compute `segment = part_index // HASHMAP_MAX_LEN`.
3. Slice the next hashmap segment: `hashmap[segment*HASHMAP_MAX_LEN : (segment+1)*HASHMAP_MAX_LEN]`.
4. Pack as `body = resource_hash(32) || msgpack([segment, hashmap_segment_bytes])`.
5. Send as `RNS.Packet(link, body, context=RESOURCE_HMU)`.
6. Receiver appends the segment to its known hashmap and resumes requesting parts.

This "lazy hashmap delivery" is what keeps the Resource format usable on small-MTU links — a 100k-part resource has a 400 KiB hashmap, which couldn't possibly fit in one ADV.

### 8. RESOURCE_PRF — final proof

After the receiver has assembled all parts (`received_count == total_parts`), it runs `assemble()` and on a successful hash check sends back:

```
body = resource_hash(32) || full_proof(32)
```

as `RNS.Packet(link, proof_data, packet_type=PROOF, context=RESOURCE_PRF)` — a PROOF-type packet, not DATA.

The initiator's `validate_proof(proof_data)` (`RNS/Resource.py:787-830` → `def validate_proof(self, proof_data)`):

1. Checks `len(proof_data) == 64` and `proof_data[32:] == self.expected_proof`.
2. On match, transitions `status = COMPLETE` and fires the resource callback.
3. If this is a multi-segment resource and `segment_index < total_segments`, **immediately advertise the next segment** — its preparation has been running in the background since step 6 of segment N (`__prepare_next_segment` at line 768).

If the proof is malformed or doesn't match, the resource is **NOT** retried — `validate_proof` simply returns and the watchdog will eventually time out and call `cancel()`.

### 9. Cancellation paths

Either side can cancel at any point with body = `resource_hash(32)`:

- **`RESOURCE_ICL (0x06)`** — initiator cancel. Causes: `MAX_RETRIES = 16` consecutive request rounds with no progress; Link torn down; explicit `Resource.cancel()` call.
- **`RESOURCE_RCL (0x07)`** — receiver cancel. Causes: app callback rejected the advertisement (`Resource.reject(adv_packet)`); `Resource.cancel()` from receiver side.

Both transition `status = FAILED` and notify `link.resource_concluded(self)` so the Link can free its tracking entry.

### 10. Watchdog and recovery

`RNS/Resource.py:564-674` → `def watchdog_job(self)`. The Resource owns a watchdog thread that runs through the lifecycle and adjusts timeouts based on observed link RTT. Key points for interop:

- **Per-part timeout:** `PART_TIMEOUT_FACTOR = 4` × (link RTT) before any part has arrived; drops to `PART_TIMEOUT_FACTOR_AFTER_RTT = 2` once RTT is calibrated.
- **Proof timeout:** `PROOF_TIMEOUT_FACTOR = 3` × link RTT after all parts have been sent.
- **HMU wait factor:** `HMU_WAIT_FACTOR = 3.5` × link RTT after sending RESOURCE_HMU before assuming it was lost.
- **Sender grace:** `SENDER_GRACE_TIME = 10s` — extra wait at end-of-transfer before declaring failure if some parts haven't been requested.

These are not negotiated — both sides use their own constants. Two implementations with different watchdog tuning interop fine, but may diverge in how aggressively they cancel a struggling transfer.

---

## Wire-byte summary

Three round-trips compose a Resource's lifetime on the wire (single-segment, hashmap-fits-in-ADV case):

```
                                         Initiator                   Receiver
1. RESOURCE_ADV (DATA, ctx=0x02)         ──────────────────────────►
   (msgpack dict, hashmap fragment,
    encrypted via Link Token)                                         (parses ADV, accepts)

   PROOF (LINKPROOF, ctx=0xFD)            ◄──────────────────────────  (Reticulum-level
                                                                        ack of ADV)

2. RESOURCE_REQ (DATA, ctx=0x03)          ◄──────────────────────────  (asks for parts)
   (exhausted_flag || resource_hash
    || requested_map_hashes)

   PROOF (LINKPROOF, ctx=0xFD)            ──────────────────────────►

3. RESOURCE × N (DATA, ctx=0x01)          ──────────────────────────►  (N = window size)
   (one part each, encrypted via
    Link Token)

   PROOF × N (LINKPROOF, ctx=0xFD)        ◄──────────────────────────

   ... loop steps 2-3 until all parts delivered ...

4. RESOURCE_PRF (PROOF, ctx=0x05)         ◄──────────────────────────  (resource complete)
   (resource_hash || full_proof)
```

Multi-segment resources insert a fresh RESOURCE_ADV after step 4 for each new segment. Multi-hashmap-segment resources insert a `RESOURCE_REQ` with `exhausted=0xFF` followed by a `RESOURCE_HMU` reply between steps 2 and 3 whenever the receiver runs out of hashmap.

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | `LXMF/LXMessage.py` | `__as_resource`, line 651 (LXMF caller) |
| 2 | `RNS/Resource.py` | `Resource.__init__`, line 248-478 |
| 3 | `RNS/Resource.py` | `Resource.advertise`, line 508; `__advertise_job`, line 520 |
| 3 | `RNS/Resource.py` | `ResourceAdvertisement.pack`, line 1336 |
| 4 | `RNS/Resource.py` | watchdog ADVERTISED branch, line 573-590 |
| 5 | `RNS/Resource.py` | `request`, line 985-1064 |
| 6 | `RNS/Resource.py` | `receive_part` window grow, line 902-906 |
| 7 | `RNS/Resource.py` | hashmap update emit, line 1030-1064 |
| 8 | `RNS/Resource.py` | `validate_proof`, line 785-829 |
| 9 | `RNS/Resource.py` | `Resource.reject`, line 155-163; `Resource.cancel` (search) |
| 10 | `RNS/Resource.py` | watchdog timeouts, line 126-137 |
