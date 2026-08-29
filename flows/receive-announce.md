# Flow: receive an announce

What happens chronologically on a node when an `ANNOUNCE` packet arrives on one of its interfaces. Without this flow working, nothing else does — no peer is ever known, every outbound message fails at `Identity.recall(dest_hash)`, and no path table entry exists for routing.

Pinned against **RNS 1.5.2**. Line numbers below are from that version.

This flow covers the **receive + ingest** path that every Reticulum node runs (leaf clients and transport nodes alike). The **rebroadcast** logic that transport nodes additionally run is covered separately in `forward-announce.md` (TODO — Tier 3 in `../todo.md`).

---

## Preconditions

- Receiver is initialised: `Transport.ready == True`, `Transport.identity` set.
- Receiver has at least one interface attached (otherwise `Transport.inbound` drops the packet at the IFAC check).
- Receiver may or may not have any prior knowledge of the announcing destination — the validation flow below populates `known_destinations` on first contact and refreshes / replay-checks on subsequent contacts.

---

## Sequence

### 1. Wire bytes arrive at the interface, deframe, classify

Steps 1-6 of [`receive-opportunistic-lxmf.md`](receive-opportunistic-lxmf.md) apply unchanged:

1. KISS / HDLC deframer (and RNode 2-frame split-packet reassembly per [`../SPEC.md`](../SPEC.md) §8.3 if applicable) hands the raw Reticulum packet bytes to `RNS.Transport.inbound(raw, interface)` (`RNS/Transport.py:1682-1686` → `def inbound(raw, interface=None, tc=None, ifac_handled=False)`, which delegates to `preprocess_inbound` at `:1753`).
2. IFAC unmask if the interface has `ifac_identity` configured.
3. `packet = RNS.Packet(None, raw); packet.unpack(); packet.hops += 1`.
4. RSSI / SNR / Q stats are attached to the packet.
5. `Transport.packet_filter(packet)` dedup check; the packet's hash is added to `Transport.packet_hashlist` unless it belongs to a link or is an LRPROOF.
6. Dispatch by `packet.packet_type`. For an announce: `packet_type == ANNOUNCE (1)`, `destination_type == SINGLE (0)`, `transport_type == BROADCAST (0)`. Control reaches `RNS/Transport.py:1670` → `if packet.packet_type == RNS.Packet.ANNOUNCE:`:

```python
if packet.packet_type == RNS.Packet.ANNOUNCE:
    ...
```

### 2. Quick signature-only validation (cheap pre-filter)

`RNS/Transport.py:1806` → `RNS.Identity.validate_announce(packet, only_validate_signature=True`:

```python
if interface != None and RNS.Identity.validate_announce(packet, only_validate_signature=True):
    interface.received_announce()
```

`validate_announce(only_validate_signature=True)` runs the full body-parse and Ed25519 signature verification (steps 1-2 of SPEC.md §4.5) but **skips** the destination_hash recomputation and the cache updates. If the signature is valid the call:

- Returns `True` so the wider dispatch can proceed.
- Calls `interface.received_announce()`, which appends `time.time()` to the per-interface `ia_freq_deque` (`RNS/Interfaces/Interface.py:304-308` → `self.ia_freq_deque.append(time.time())`; called from `RNS/Transport.py:1811`). This deque feeds `incoming_announce_frequency()` and is what drives ingress-limit decisions in step 3.

If the signature fails, the announce is silently dropped here without the deque update — a malformed sender can't burn through the receiver's ingress budget by spamming bad-sig announces. This is a sharp design choice and worth replicating in any clean-room implementation: **signature-checked-then-counted**, not "counted-then-validated".

### 3. Ingress rate limiting (defer-and-hold)

`RNS/Transport.py:1812-1825` → `announced_destination_known = packet.destination_hash in Transport.path_table`:

```python
if not packet.destination_hash in Transport.path_table:
    if (packet.destination_hash in Transport.path_requests
        or packet.destination_hash in Transport.discovery_path_requests):
        pass            # already-pending path? — bypass ingress limit
    elif interface.should_ingress_limit():
        interface.hold_announce(packet)
        return          # <-- announce is paused; will be released later
```

The check runs only for **unknown-destination** announces (already-known destinations are throttled by their own re-announce rate limiter, not the ingress limiter).

`should_ingress_limit()` (`RNS/Interfaces/Interface.py:168-191` → `def should_ingress_limit(self)`) trips into a "burst-active" state when `incoming_announce_frequency()` exceeds `IC_BURST_FREQ_NEW = 6 Hz` (interfaces younger than 2 hours, `IC_NEW_TIME`) or `IC_BURST_FREQ = 35 Hz` (older interfaces). Once in burst mode, every unknown-destination announce gets parked in the interface's `held_announces` dict until the rate drops below the threshold AND `IC_BURST_HOLD = 60s` has elapsed.

Held announces are released later by `Interface.process_held_announces()` (`RNS/Interfaces/Interface.py:257-280` → `def process_held_announces(self)`), which fires every `IC_HELD_RELEASE_INTERVAL = 2s`, picks the **lowest-hop-count** held announce, and re-injects it via `Transport.inbound(announce_packet.raw, announce_packet.receiving_interface)`. The re-injection re-enters this flow at step 1, so the rate-limiter doesn't get bypassed; the held announce takes its turn in line.

`held_announces` is bounded by `MAX_HELD_ANNOUNCES = 256` per interface; overflow simply drops the new announce instead of evicting an older one (`hold_announce` at `RNS/Interfaces/Interface.py:269-275`).

### 4. Local-destination short-circuit

`RNS/Transport.py:1765-1768`:

```python
local_destination = None
with Transport.destinations_map_lock:
    if packet.destination_hash in Transport.destinations_map:
        local_destination = Transport.destinations_map[packet.destination_hash]
```

If the announce's `destination_hash` matches one of our own registered destinations, this is our own announce echo — line 2176 gates the full validation pass on `local_destination == None`, so we skip both the validation and the path-table updates for self-announces. (SPEC.md §9.5 — the operator-runs-both-originator-and-transport scenario.)

### 5. Full announce validation

`RNS/Transport.py:2176`:

```python
if local_destination == None and announce_valid:
    ...
```

(`announce_valid` is set just above from `RNS.Identity.validate_announce(packet)`;
earlier revisions of this document inlined the call into the condition, which is
not what upstream reads.)

`validate_announce(only_validate_signature=False)` runs the full sequence per SPEC.md §4.5:

1. Branch body parse on `context_flag` to slice `public_key`, `name_hash`, `random_hash`, optional `ratchet_pub`, `signature`, `app_data`.
2. Reconstruct `signed_data = dest_hash || pub || name_hash || random_hash || ratchet || app_data` (with `ratchet = b""` when not present).
3. Verify the Ed25519 signature.
4. Blackhole-list check on the announced identity_hash.
5. Recompute `expected_hash = SHA256(name_hash || SHA256(public_key)[:16])[:16]` and compare to `packet.destination_hash`.
6. Public-key collision check against `known_destinations[dest_hash]`.
7. On success: `Identity.remember(packet_hash, dest_hash, public_key, app_data)` populates `known_destinations`; if `ratchet`, `Identity._remember_ratchet(dest_hash, ratchet)` populates `known_ratchets` and writes `{storagepath}/ratchets/{hexhash}` to disk.

If any check fails, the function returns `False` and the wider dispatch skips everything below. The cache updates happen **inside** `validate_announce` — by the time control returns to `Transport.inbound`, `known_destinations` and `known_ratchets` are already updated.

### 6. `random_blob` extraction and `received_from` resolution

`RNS/Transport.py:2217` → `random_blob  = packet.data[RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8:`. The 10-byte `random_hash` is re-extracted as `random_blob` (same bytes, different name in the routing-table code):

```python
random_blob = packet.data[64+10 : 64+10+10]   # bytes 74..84 of the announce body
```

The trailing 5 bytes of `random_blob` are the emission timestamp (SPEC.md §4.1). This blob is what the path table will store, dedupe against, and use for ordering decisions in step 7.

`received_from` is set to `packet.transport_id` if the announce arrived as `HEADER_2` with a transport_id (i.e. via at least one relay), else to `packet.destination_hash` itself.

### 7. Path table population

`RNS/Transport.py:2122-2214` → `should_add = False`. The full decision tree for whether and how to update `path_table[destination_hash]` is roughly:

```
local_and_hops_condition := (packet.hops < PATHFINDER_M+1)   # default 128
                            AND (dest_hash NOT in destinations_map)

if not local_and_hops_condition: skip path-table update entirely

else:
   announce_emitted = timebase_from_random_blob(random_blob)        # [5:10] big-endian
   existing = path_table.get(dest_hash)
   if existing:
       if packet.hops <= existing[HOPS]:
           if random_blob is new AND announce_emitted > timebase(existing.random_blobs):
               replace existing entry with this announce
       else:                                                         # more hops than cached
           if existing path expired OR announce_emitted > existing.timebase:
               replace existing entry
   else:
       insert fresh entry
```

The new (or refreshed) `path_table[dest_hash]` entry is:

```
[ recv_time,
  received_from,             # next-hop transport_id or dest_hash itself
  packet.hops,
  recv_time + path_ttl,
  random_blobs,              # capped at MAX_RANDOM_BLOBS, sliding window
  packet.receiving_interface,
  packet.packet_hash ]
```

`path_ttl` is `Transport.AP_PATH_TIME` for access-point destinations, `ROAMING_PATH_TIME` for roaming, otherwise `DESTINATION_TIMEOUT`. The leaf-client read side (§7.1, §7.5) uses this entry to decide whether `has_path(dest_hash)` is true and to populate the next-hop transport_id when constructing HEADER_2 packets (§2.3).

A leaf client that **doesn't** maintain a path table can still send opportunistic LXMF — `LXMRouter.handle_outbound` will call `request_path` whenever `has_path()` returns false, then defer the message and retry — but the round-trip cost on every send is high enough that all serious clients maintain the table.

### 8. Announce handler dispatch

`RNS/Transport.py:2486-2537` → `for handler in Transport.announce_handlers:`. With path-table updated, the receiver fans the announce out to any application-level listeners that registered via `RNS.Transport.register_announce_handler`:

```python
for handler in Transport.announce_handlers:
    announce_identity = RNS.Identity.recall(packet.destination_hash, _no_use=True)

    if handler.aspect_filter == None:
        execute_callback = True
    else:
        expected_hash = RNS.Destination.hash_from_name_and_identity(handler.aspect_filter, announce_identity)
        execute_callback = (packet.destination_hash == expected_hash)

    if packet.context == RNS.Packet.PATH_RESPONSE:
        execute_callback = getattr(handler, "receive_path_responses", False) and execute_callback

    if execute_callback:
        threading.Thread(target=handler.received_announce, kwargs=...).start()
```

Three details that bite implementers:

1. **`aspect_filter` is a name string, not a name_hash.** A handler that wants only `lxmf.delivery` announces sets `self.aspect_filter = "lxmf.delivery"` and Reticulum recomputes the expected dest_hash from `(name, announced_identity)` for each candidate. So a single handler can match across all peers' `lxmf.delivery` destinations without enumerating them.
2. **`PATH_RESPONSE` is filtered OUT by default.** A handler must opt in via `handler.receive_path_responses = True` to see path-response announces; otherwise it sees only periodic re-announces. The path-table update in step 7 still happens regardless.
3. **The handler is called in a fresh daemon thread.** A slow handler doesn't block subsequent inbound packets, but it also can't assume serialised execution — two announces from the same destination arriving back-to-back will run two handler threads concurrently. Handlers that mutate shared state need their own locks. (`RNS/Transport.py:2512` → `threading.Thread(target=job, daemon=True).start()`.)

LXMF registers two handlers at `LXMF/LXMRouter.py:226-227` → `RNS.Transport.register_announce_handler(LXMFDeliveryAnnounceHandler(self))`:

```python
RNS.Transport.register_announce_handler(LXMFDeliveryAnnounceHandler(self))   # aspect = "lxmf.delivery"
RNS.Transport.register_announce_handler(LXMFPropagationAnnounceHandler(self)) # aspect = "lxmf.propagation"
```

so any client built on the LXMF router gets contacts/propagation-node discovery for free. Custom clients (NomadNet pages, telemetry beacons, application-specific destinations) register their own handlers with the relevant aspect_filter.

### 9. Optional rebroadcast (transport nodes only)

If `RNS.Reticulum.transport_enabled() == True`, the same `Transport.inbound` dispatch then walks an additional code path that constructs a rebroadcast announce, queues it on each suitable interface (`announce_queue`), and emits it later subject to the per-interface `announce_cap` (default 2% of airtime). This entire path is skipped on a leaf client.

The rebroadcast logic is the bulk of `RNS/Transport.py:2300-2374` and is documented separately in `forward-announce.md` (TODO).

---

## Wire-byte summary

What arrives — same outer Reticulum header as any DATA packet, but `packet_type = ANNOUNCE (1)`, `transport_type = BROADCAST (0)`, `destination_type = SINGLE (0)`. With `context_flag == 1` (most modern senders, ratchet present):

```
[ 1B flags                                                              ]
[ 1B hops                                                               ]
[ 16B dest_hash                                                         ]   (HEADER_1; HEADER_2 inserts 16B transport_id before this)
[ 1B context: 0x00 normal / 0x0B PATH_RESPONSE                         ]
[ 64B public_key (X25519 || Ed25519)                                    ]
[ 10B name_hash (SHA256(app_name)[:10])                                 ]
[ 10B random_hash (5B random || 5B big-endian uint40 unix_seconds)      ]
[ 32B ratchet_pub (X25519)                                              ]   ← present iff context_flag bit set
[ 64B Ed25519 signature                                                 ]
[ N B  app_data                                                         ]   ← may be empty
```

Without ratchet (`context_flag == 0`) the 32-byte ratchet slot is absent and `signature` shifts up to start at offset `74 + 10 = 84` of the announce body.

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | `RNS/Transport.py` | `inbound`, line 1682-1686; `preprocess_inbound`, line 1753-1896 |
| 2 | `RNS/Identity.py` | `validate_announce(only_validate_signature=True)`, line 511-612 |
| 2 | `RNS/Interfaces/Interface.py` | `received_announce`, line 302-306 |
| 3 | `RNS/Interfaces/Interface.py` | `should_ingress_limit`, line 188-211; `hold_announce`, line 269-275; `process_held_announces`, line 277-300 |
| 4 | `RNS/Transport.py` | `destinations_map` lookup, line 2175 |
| 5 | `RNS/Identity.py` | `validate_announce` full pass, line 511-612 |
| 5 | `RNS/Identity.py` | `Identity.remember`, line 101-113; `_remember_ratchet`, line 410-443 |
| 6 | `RNS/Transport.py` | `random_blob` extraction, line 2217 |
| 7 | `RNS/Transport.py` | path table population decision tree, line 2206-2298 |
| 7 | `RNS/Transport.py` | `timebase_from_random_blobs`, line 3729-3735 |
| 8 | `RNS/Transport.py` | announce handler dispatch, line 2483-2534 |
| 8 | `LXMF/LXMRouter.py` | LXMF announce handler registration, line 226-227 |
| 9 | `RNS/Transport.py` | rebroadcast queue (see `forward-announce.md`), line 2300-2374 |
