# Flow: receive a Resource (large body) over a Link

The inverse of [`send-resource.md`](send-resource.md). What happens chronologically on the receiver when an inbound Resource transfer arrives. Pinned against **RNS 1.5.2**; see [`../SPEC.md`](../SPEC.md) §10 for the wire bytes.

---

## Preconditions

- Link is `ACTIVE` (§6).
- Receiver registered a `resource_strategy` on the Link via `set_resource_strategy(...)` — `ACCEPT_NONE`, `ACCEPT_APP`, or `ACCEPT_ALL`. Default `ACCEPT_NONE` rejects every Resource on the link; LXMF and NomadNet flip this to `ACCEPT_APP` so an app callback can decide.

---

## Sequence

### 1. RESOURCE_ADV arrives

Inbound Link DATA packet with `context = RESOURCE_ADV (0x02)`. `Link.__receive` at `RNS/Link.py:1031-1101` → `elif packet.context == RNS.Packet.RESOURCE_ADV:` decrypts it and runs `RNS.ResourceAdvertisement.unpack` against the plaintext to extract the msgpack dict (§10.4).

### 2. Resource accept / reject decision

Branch by `resource_strategy`:

- **`ACCEPT_NONE`** → call `RNS.Resource.reject(adv_packet)` which sends `RESOURCE_RCL` back; resource is dropped.
- **`ACCEPT_APP`** → run the application callback `link.callbacks.resource(adv)`. If it returns truthy, `RNS.Resource.accept(...)`; otherwise reject.
- **`ACCEPT_ALL`** → unconditional `RNS.Resource.accept(...)`.

`Resource.accept` (`RNS/Resource.py:167-243` → `def accept(advertisement_packet`) constructs a receiver-side Resource object, copies fields from the advertisement, sets `status = TRANSFERRING`, and queues the first request.

### 3. Receiver issues the first RESOURCE_REQ

`Resource.request_next()` (`RNS/Resource.py:933-982` → `def request_next(self)`) builds the request body per §10.5:

```
exhausted_flag(1) [|| last_map_hash(4)] || resource_hash(32) || requested_map_hashes(N × 4)
```

`N = link.window` initially (default 4). Sent as Link DATA with `context = RESOURCE_REQ (0x03)`.

### 4. Sender fulfills with RESOURCE part packets

For each requested map_hash, the sender (per `flows/send-resource.md` step 5) emits one Link DATA packet with `context = RESOURCE (0x01)`, body = pre-encrypted part bytes. The receiver matches each arriving part to the hashmap by recomputing its 4-byte map_hash (`Resource.receive_part`, `RNS/Resource.py:842-939` → `def receive_part(self,`).

Successful match: `parts[i] = part_data`, `consecutive_completed_height` advances. The window grows by 1 each successful round (capped at `window_max`, with rate-detection upgrades to FAST or VERY_SLOW per §10.10).

### 5. Repeat steps 3-4 until `received_count == total_parts`

When the receiver has consumed every map_hash in the current segment, it issues another RESOURCE_REQ. If the hashmap is exhausted (`exhausted_flag = 0xFF`), the sender responds with a RESOURCE_HMU carrying the next hashmap segment (§10.7), and the loop continues.

### 6. `Resource.assemble()` reassembles, validates, decrypts

`Resource.py:676-753` → `def assemble(self)`:

1. `stream = b"".join(self.parts)` — concatenate every part.
2. `data = link.decrypt(stream)` — single Link Token decrypt of the whole blob (§10.12: encryption was applied to the whole concatenated body before splitting).
3. Strip the 4-byte `random_hash` prefix.
4. If `compressed`: bz2-decompress.
5. `calculated_hash = SHA256(data || random_hash)`. Compare to `self.hash` (= advertisement's `h` field). On match: `status = COMPLETE`. On mismatch: `status = CORRUPT`; cancel.
6. If `has_metadata`: peel off the 3-byte length-prefixed msgpack metadata blob, write to `meta_storagepath`.
7. Write the data to `storagepath` (file-backed) or hold in `self.data` (memory-backed).
8. Call the application callback (the one passed to `Resource.accept`).

### 7. RESOURCE_PRF emission

`Resource.prove()` (`RNS/Resource.py:765-777` → `def prove(self):`) sends back:

```
proof_data = resource_hash(32) || full_proof(32)
where full_proof = SHA256(data_with_random || resource_hash)
```

as a PROOF-type packet with `context = RESOURCE_PRF (0x05)`. The sender's `validate_proof` matches `proof_data[32:]` against its precomputed `expected_proof` and transitions to `COMPLETE` (§10.8).

### 8. Multi-segment continuation

If `segment_index < total_segments`, the sender prepares and sends the next RESOURCE_ADV after receiving this segment's PRF. The receiver loops back to step 1 for the next segment. Each segment is a fully independent Resource transfer; the only thing that ties them together is the `original_hash` field in the advertisement.

### 9. Cancellation paths

`RESOURCE_ICL` (sender cancel) → receiver pops the matching incoming Resource and discards accumulated parts (`Link.py:1112-1120` → `elif packet.context == RNS.Packet.RESOURCE_ICL:`).
`RESOURCE_RCL` (sender hears the receiver rejected) → already handled receiver-side at step 2.

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | `RNS/Link.py` | `Link.__receive` RESOURCE_ADV branch, line 1031 |
| 2 | `RNS/Resource.py` | `Resource.accept`, `Resource.reject`, lines 155-244 |
| 3 | `RNS/Resource.py` | `request_next`, line 942 |
| 4 | `RNS/Resource.py` | `receive_part`, line 842 |
| 5 | `RNS/Link.py` | RESOURCE_HMU branch, line 1103 |
| 6 | `RNS/Resource.py` | `assemble`, line 685 |
| 7 | `RNS/Resource.py` | `prove`, line 765 |
| 8 | `RNS/Resource.py` | `__prepare_next_segment`, line 779 |
| 9 | `RNS/Link.py` | RESOURCE_ICL branch, line 1112 |
