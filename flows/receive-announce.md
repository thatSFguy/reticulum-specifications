# Flow: receive an announce

What happens chronologically on a node when an `ANNOUNCE` packet arrives on one of its interfaces. Without this flow working, nothing else does — no peer is ever known, every outbound message fails at `Identity.recall(dest_hash)`, and no path table entry exists for routing.

Pinned against **RNS 1.6.1**. Line numbers below are from that version.

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

1. KISS / HDLC deframer (and RNode 2-frame split-packet reassembly per [`../SPEC.md`](../SPEC.md) §8.3 if applicable) hands the raw Reticulum packet bytes to `RNS.Transport.inbound(raw, interface)` (`RNS/Transport.py:1987-1995` → `def inbound(raw, interface=None, tc=None, ifac_handled=False, no_accounting=False)`, which delegates to `preprocess_inbound` at `:2062` → `def preprocess_inbound(raw,`).
2. IFAC unmask if the interface has `ifac_identity` configured.
3. `packet = RNS.Packet(None, raw); packet.unpack()`. Since RNS 1.6, a packet whose `hops` has already reached the interface's `hop_limiter` or `Transport.HOP_LIMITER` (= `PATHFINDER_M`) is dropped here (`RNS/Transport.py:2108-2109` → `if not packet.hops < Transport.HOP_LIMITER:`). Then `packet.hops += 1`.
4. RSSI / SNR / Q stats are attached to the packet.
5. `Transport.packet_filter(packet)` dedup check; the packet's hash is added to `Transport.packet_hashlist` unless it belongs to a link or is an LRPROOF.
6. Dispatch by `packet.packet_type`. For an announce: `packet_type == ANNOUNCE (1)`, `destination_type == SINGLE (0)`, `transport_type == BROADCAST (0)`. Control reaches the announce branch of `preprocess_inbound` at `RNS/Transport.py:2117` → `if packet.packet_type == RNS.Packet.ANNOUNCE:`:

```python
if packet.packet_type == RNS.Packet.ANNOUNCE:
    ...
```

### 2. Ingress pre-filters and the signature-only validation

Everything in steps 2 and 3 runs in `preprocess_inbound`, on the interface's RX thread, before the packet is queued (SPEC.md §13.1.1). Since RNS 1.6 the announce branch (`RNS/Transport.py:2116-2170` → `# Ingress limit announces early`) runs these checks in order:

1. **Size bounds.** The frame must be at most `Reticulum.MTU`. A `HEADER_1` announce must also leave 16 bytes of headroom, and the data field must be at least 84 bytes (SPEC.md §4.5). A failure is a protocol violation against the interface.
2. **Destination-type filters (new in RNS 1.6).** The `name_hash` is read straight from the body. An announce whose `name_hash` is in `Transport.blocked_destination_types` is dropped silently. When `Transport.required_destinations_only` is set, only allowed or client-registered types pass (`:2123-2131` → `if Transport.blocked_destination_types and name_hash in Transport.blocked_destination_types: return`). Both are local configuration; nothing on the wire changes.
3. **Prefilter for known destinations (new in RNS 1.6).** If the destination is already in `path_table`, the announce is not a `PATH_RESPONSE`, and nothing is waiting on it (no pending path request, no queued rebroadcast), `Transport.announce_prefilter` decides whether it could update the path at all. It passes only when the announce was emitted later than the newest emission timestamp cached for the path, or at the same time but on a higher-`gravity` interface, or when the path is marked unresponsive (`RNS/Transport.py:4463-4480` → `def announce_prefilter(announce_packet, path_entry):`). Anything else is dropped **before signature validation** and counted as a filtered announce (`:2133-2143` → `prefilter_conditions  = packet.context != RNS.Packet.PATH_RESPONSE`).
4. **Signature-only validation.** `RNS/Transport.py:2147` → `RNS.Identity.validate_announce(packet, only_validate_signature=True`. This runs the body parse and Ed25519 signature verification (steps 1-2 of SPEC.md §4.5), but **skips** the destination_hash recomputation and the cache updates. A blackholed identity, or under stamp enforcement a missing or invalid announce stamp, is a silent filtered drop. A bad signature is a protocol violation (`:2148-2152` → `Invalid announce signature for`).

Only after all of this is the announce counted, by `interface.received_announce(size=len(raw))` (`RNS/Transport.py:2168` → `packet.receiving_interface.received_announce(size=announce_size)`). That call appends `time.time()` to the per-interface `ia_freq_deque` (`RNS/Interfaces/Interface.py:347-349` → `self.ia_freq_deque.append(time.time())`), which feeds `incoming_announce_frequency()` and drives the ingress-limit decision in step 3.

An announce with a bad signature never reaches the counter, so a sender spamming bad-signature announces cannot use up the receiver's ingress budget. Replicate this ordering: **check the signature, then count it**. Note that since RNS 1.6 two kinds of announce are counted with `size=0` without a signature check: announces dropped by the prefilter, and announces held by ingress limiting (step 3). They add to the frequency estimate but not to the byte counters.

### 3. Ingress rate limiting (defer-and-hold)

`RNS/Transport.py:2155-2163` → `elif packet.receiving_interface.should_ingress_limit():`:

```python
if not announced_destination_known:              # destination not in path_table
    if (packet.destination_hash in Transport.path_requests
        or packet.destination_hash in Transport.discovery_path_requests):
        pass            # already-pending path? — bypass ingress limit
    elif interface.should_ingress_limit():
        interface.hold_announce(packet)
        interface.received_announce(size=0)
        return False    # <-- announce is paused; will be released later
```

The check runs only for **unknown-destination** announces (already-known destinations are throttled by their own re-announce rate limiter, not the ingress limiter).

`should_ingress_limit()` (`RNS/Interfaces/Interface.py:216-239` → `def should_ingress_limit(self)`) trips into a "burst-active" state when `incoming_announce_frequency()` exceeds `IC_BURST_FREQ_NEW = 6 Hz` (interfaces younger than 2 hours, `IC_NEW_TIME`) or `IC_BURST_FREQ = 35 Hz` (older interfaces). Once in burst mode, every unknown-destination announce gets parked in the interface's `held_announces` dict until the rate drops below the threshold AND `IC_BURST_HOLD = 60s` has elapsed.

Held announces are released later by `Interface.process_held_announces()` (`RNS/Interfaces/Interface.py:308-345` → `def process_held_announces(self)`), which fires every `IC_HELD_RELEASE_INTERVAL = 2s`, picks the **lowest-hop-count** held announce, and re-injects it via `Transport.inbound(announce_packet.raw, announce_packet.receiving_interface)`. The re-injection re-enters this flow at step 1, so the rate-limiter doesn't get bypassed; the held announce takes its turn in line.

`held_announces` is bounded by `MAX_HELD_ANNOUNCES = 256` per interface; overflow simply drops the new announce instead of evicting an older one (`hold_announce` at `RNS/Interfaces/Interface.py:297-304` → `def hold_announce(self,`).

### 4. Local-destination short-circuit

Once the packet is dequeued, `Transport._inbound` runs the full validation first, then looks the destination up in `destinations_map` (`RNS/Transport.py:2561-2565` → `local_destination = Transport.destinations_map.get(packet.destination_hash)`):

```python
announce_valid = RNS.Identity.validate_announce(packet)
if not announce_valid: return packet.receiving_interface.protocol_violation("Invalid announce")
local_destination = Transport.destinations_map.get(packet.destination_hash)
if local_destination == None and announce_valid:
    ...
```

If the announce's `destination_hash` matches one of our own registered destinations, this is our own announce echo. The path-table and rebroadcast processing below is gated on `local_destination == None`, so it is skipped for self-announces. (SPEC.md §9.5 — the operator-runs-both-originator-and-transport scenario.) Since RNS 1.6 a failed full validation at this point is also counted as a protocol violation.

### 5. Full announce validation

`RNS/Transport.py:2565` → `if local_destination ==`:

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

`RNS/Transport.py:2607` → `random_blob  = packet.data[RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8:`. The 10-byte `random_hash` is re-extracted as `random_blob` (same bytes, different name in the routing-table code):

```python
random_blob = packet.data[64+10 : 64+10+10]   # bytes 74..84 of the announce body
```

The trailing 5 bytes of `random_blob` are the emission timestamp (SPEC.md §4.1). This blob is what the path table will store, dedupe against, and use for ordering decisions in step 7.

`received_from` is set to `packet.transport_id` if the announce arrived as `HEADER_2` with a transport_id (i.e. via at least one relay), else to `packet.destination_hash` itself.

### 7. Path table population

`RNS/Transport.py:2595-2696` → `should_add = False`. The full decision tree for whether and how to update `path_table[destination_hash]`, plus the RNS 1.6 dedup-interface bookkeeping, is roughly:

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
           elif announce_emitted == timebase AND receiving_interface.gravity > existing_interface.gravity:
               replace existing entry (same announce, better interface)
       else:                                                         # more hops than cached
           if existing path expired AND random_blob is new:
               replace existing entry
           elif announce_emitted > existing.timebase AND random_blob is new:
               replace existing entry
           elif announce_emitted == existing.timebase AND path is marked unresponsive:
               replace the path-table entry only (no rebroadcast)
       if not replaced AND this is the same packet already queued for rebroadcast:
           remember receiving_interface so the rebroadcast skips it  # new in RNS 1.6
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
  packet.packet_hash,
  path_used ]                # IDX_PT_USED, new in RNS 1.6: last-use time, 0 if never used
```

`path_ttl` comes from `Transport.path_timeout_from_interface` (`RNS/Transport.py:3833-3837` → `def path_timeout_from_interface(interface):`): `AP_PATH_TIME` (1 day) for an access-point-mode receiving interface, `ROAMING_PATH_TIME` (6 hours) for roaming mode, and otherwise `PATH_TIMEOUT` (1 week). RNS 1.6 renamed `DESTINATION_TIMEOUT` to `PATH_TIMEOUT`, with the same value. A path that is never used is evicted much sooner; see SPEC.md §12.4.2. The leaf-client read side (§7.1, §7.5) uses this entry to decide whether `has_path(dest_hash)` is true and to populate the next-hop transport_id when constructing HEADER_2 packets (§2.3).

A leaf client that **doesn't** maintain a path table can still send opportunistic LXMF — `LXMRouter.handle_outbound` will call `request_path` whenever `has_path()` returns false, then defer the message and retry — but the round-trip cost on every send is high enough that all serious clients maintain the table.

### 8. Announce handler dispatch

`RNS/Transport.py:2883-2937` → `# Call externally registered callbacks from apps`. With path-table updated, the receiver fans the announce out to any application-level listeners that registered via `RNS.Transport.register_announce_handler`:

```python
name_hash = packet.data[64:74]
announce_handlers  = Transport.announce_handlers.get(name_hash, [])   # handlers for this aspect
announce_handlers += Transport.announce_handlers.get(None, [])        # handlers with no filter
for handler in announce_handlers:
    if handler.paused: continue
    execute_callback = True
    if packet.context == RNS.Packet.PATH_RESPONSE:
        execute_callback = getattr(handler, "receive_path_responses", False) == True
    if execute_callback:
        # 3, 4 or 5-argument received_announce(), chosen by its signature
        Transport.pending_callbacks.append(threading.Thread(target=job, daemon=True))
```

> **Changed in RNS 1.6.** `Transport.announce_handlers` is now a dict keyed
> on the 10-byte `name_hash` of the handler's `aspect_filter`, computed once
> at registration (`RNS/Transport.py:3433-3438` → `name_hash = RNS.Destination.name_hash(handler.aspect_filter) if handler.aspect_filter else None`).
> Through 1.5.7 it was a list, and every announce was matched against every
> handler by recomputing `hash_from_name_and_identity(aspect_filter, identity)`.
> Now a handler is matched on the announce's `name_hash` alone. A handler can
> also be `paused`, and a fifth callback argument, `is_path_response`, is
> available. A path-table update still happens whether or not any handler matches.

Three details that bite implementers:

1. **`aspect_filter` is a name string, matched by `name_hash`.** A handler that wants only `lxmf.delivery` announces sets `self.aspect_filter = "lxmf.delivery"`. Since RNS 1.6 Reticulum hashes that once to its 10-byte `name_hash` and matches announces on that alone, so a single handler sees every peer's `lxmf.delivery` destination. The match does not re-derive the destination hash; the full validation in step 5 has already checked it.
2. **`PATH_RESPONSE` is filtered OUT by default.** A handler must opt in via `handler.receive_path_responses = True` to see path-response announces; otherwise it sees only periodic re-announces. The path-table update in step 7 still happens regardless.
3. **The handler is called in a fresh daemon thread.** Since RNS 1.6 the thread is queued on `Transport.pending_callbacks` (`RNS/Transport.py:2933` → `Transport.pending_callbacks.append(threading.Thread(target=job, daemon=True))`), and is started outside the announce-handler lock on the next `Transport.jobs` pass, which runs every `job_interval = 0.25` s (`:1471-1473` → `# Launch deferred callbacks`). A handler therefore fires up to a quarter of a second after the announce is processed. A slow handler doesn't block subsequent inbound packets, but it also can't assume serialised execution — two announces from the same destination arriving back-to-back will run two handler threads concurrently. Handlers that mutate shared state need their own locks.

LXMF registers two handlers at `LXMF/LXMRouter.py:257-258` → `RNS.Transport.register_announce_handler(LXMFDeliveryAnnounceHandler(self))`:

```python
RNS.Transport.register_announce_handler(LXMFDeliveryAnnounceHandler(self))   # aspect = "lxmf.delivery"
RNS.Transport.register_announce_handler(LXMFPropagationAnnounceHandler(self)) # aspect = "lxmf.propagation"
```

so any client built on the LXMF router gets contacts/propagation-node discovery for free. Custom clients (NomadNet pages, telemetry beacons, application-specific destinations) register their own handlers with the relevant aspect_filter.

### 9. Optional rebroadcast (transport nodes only)

If `RNS.Reticulum.transport_enabled() == True`, the same `Transport.inbound` dispatch then walks an additional code path that constructs a rebroadcast announce, queues it on each suitable interface (`announce_queue`), and emits it later subject to the per-interface `announce_cap` (default 2% of airtime). This entire path is skipped on a leaf client.

The rebroadcast logic is the bulk of `RNS/Transport.py:2700-2747` → `is_from_local_client =` and is documented separately in [`forward-announce.md`](forward-announce.md).

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
| 1 | `RNS/Transport.py` | `inbound`; `preprocess_inbound` |
| 2 | `RNS/Transport.py` | `preprocess_inbound` announce branch; `announce_prefilter` (RNS ≥ 1.6) |
| 2 | `RNS/Identity.py` | `validate_announce(only_validate_signature=True)`, line 511-612 |
| 2 | `RNS/Interfaces/Interface.py` | `received_announce`, line 302-306 |
| 3 | `RNS/Interfaces/Interface.py` | `should_ingress_limit`, line 188-211; `hold_announce`, line 269-275; `process_held_announces`, line 277-300 |
| 4 | `RNS/Transport.py` | `_inbound`, `destinations_map` lookup |
| 5 | `RNS/Identity.py` | `validate_announce` full pass, line 511-612 |
| 5 | `RNS/Identity.py` | `Identity.remember`, line 101-113; `_remember_ratchet`, line 410-443 |
| 6 | `RNS/Transport.py` | `_inbound`, `random_blob` extraction |
| 7 | `RNS/Transport.py` | `_inbound`, path table population decision tree; `path_timeout_from_interface` |
| 7 | `RNS/Transport.py` | `timebase_from_random_blobs` |
| 8 | `RNS/Transport.py` | `_inbound`, announce handler dispatch; `register_announce_handler` |
| 8 | `LXMF/LXMRouter.py` | LXMF announce handler registration, line 226-227 |
| 9 | `RNS/Transport.py` | `_inbound` announce-table insertion; `jobs` rebroadcast (see `forward-announce.md`) |
