# Flow: forward an announce (transport-node rebroadcast)

What a transport-mode node does when it receives an inbound announce destined for a non-local destination. This is the flow that makes the mesh actually mesh — without it, announces never propagate beyond direct radio range. Pinned against **RNS 1.6.1**; cross-references [`../SPEC.md`](../SPEC.md) §4.5 (validation), §12.3 (rebroadcast rules), §12.4 (path table).

This flow only runs on a node with `enable_transport = Yes` per §12.1. Leaf clients can ignore it entirely.

---

## Sequence

### 1. Inbound announce passes validation

The receive-announce flow ([`receive-announce.md`](receive-announce.md)) runs first — signature check, dest_hash recompute, public-key collision check, ingress rate limit, path table population. By the time the rebroadcast logic runs, the announce is known-valid and the path_table entry is already updated.

### 2. Eligibility checks

`RNS/Transport.py:2722-2726` → `if (RNS.Reticulum.transport_enabled() or is_from_local_client) and packet.context != RNS.Packet.PATH_RESPONSE:`. Three conditions all must hold, but they are **not** one boolean — the rate check is nested inside the gate:

```python
if (RNS.Reticulum.transport_enabled() or is_from_local_client) and packet.context != RNS.Packet.PATH_RESPONSE:
    # Insert announce into announce table for retransmission
    if rate_blocked: RNS.log("Blocking rebroadcast of announce from ...")
    else:
        ...
        Transport.announce_table[packet.destination_hash] = [...]
```

- `transport_enabled OR is_from_local_client` — leaf clients only forward announces that came from a local-client interface (the rare "client behind shared rnsd" case).
- `packet.context != PATH_RESPONSE` — path-response announces are NOT rebroadcast (they go on a single specific interface back to the requester per [`path-discovery.md`](path-discovery.md) step 7).
- `not rate_blocked` — per-interface announce-rate limits aren't tripped for this destination. A rate-blocked announce still passes the outer gate; it is logged and simply never inserted into `announce_table`, which is what suppresses the rebroadcast. `rate_blocked` is computed at `:2702-2708` → `rate_blocked = False` against the receiving interface's `announce_rate_target`. Since RNS 1.6 it is kept in `RNS.Storage.AnnounceRateTable` (`check_and_update(...)`) rather than a plain dict; the target, grace and penalty semantics are unchanged.

### 3. Insert into `announce_table`

`RNS/Transport.py:2735-2746` → `Transport.announce_table[packet.destination_hash] = [`. Unless the path update was a table-only replacement (an unresponsive path being swapped out), the relay adds an entry:

```python
Transport.announce_table[packet.destination_hash] = [
    now,                          # 0  IDX_AT_TIMESTAMP
    retransmit_timeout,           # 1  IDX_AT_RTRNS_TMO  — when to emit next
    retries,                      # 2  IDX_AT_RETRIES   — emissions so far, starts at 0
    received_from,                # 3  IDX_AT_RCVD_IF   — transport_id the announce came from (or dest_hash)
    announce_hops,                # 4  IDX_AT_HOPS      — hops as received (already incremented)
    packet,                       # 5  IDX_AT_PACKET    — full Packet object
    local_rebroadcasts,           # 6  IDX_AT_LCL_RBRD  — times we heard a neighbour rebroadcast it
    block_rebroadcasts,           # 7  IDX_AT_BLCK_RBRD — emit as PATH_RESPONSE (path-request answers)
    attached_interface,           # 8  IDX_AT_ATTCHD_IF — emit only here (path-request answers)
    set(),                        # 9  IDX_AT_DEDUP_IFS — interfaces to skip (RNS >= 1.6)
]
```

`retransmit_timeout` for a non-local-client announce is `now + rand() * PATHFINDER_RW`, a random delay of up to 0.5 s (`RNS/Transport.py:2715` → `retransmit_timeout = now + (RNS.rand() * Transport.PATHFINDER_RW)`), so that neighbouring relays do not all rebroadcast at once. A local-client announce fires at `now` with `retries = PATHFINDER_R`, so it is sent exactly once. `PATH_REQUEST_GRACE = 0.4 s` applies only to path-request answers (SPEC.md §7.2.5).

**Dedup interfaces (new in RNS 1.6).** If, while an entry is waiting, the relay receives the **same announce packet** again on an interface that is not a shared medium, that interface is added to `IDX_AT_DEDUP_IFS` (`RNS/Transport.py:2692-2696` → `waiting_announce[IDX_AT_DEDUP_IFS].add(packet.receiving_interface)`). The rebroadcast is then not sent back on it: the neighbour there evidently has the announce already. On a shared medium such as a LoRa channel, every listener hears the same transmission, so this check is skipped there.

### 4. Periodic `Transport.jobs` walk drains the table

The relay's per-second-or-so housekeeping loop walks `announce_table` and for entries whose `retransmit_timeout <= now`, queues them for emission on each suitable interface:

```python
# Pseudocode of the relevant Transport.jobs branch
for dest_hash, entry in announce_table.items():
    if entry[RETRIES] > 0 and entry[RETRIES] >= LOCAL_REBROADCASTS_MAX:
        done(dest_hash)                            # LOCAL_REBROADCASTS_MAX = 2
    elif entry[RETRIES] > PATHFINDER_R:
        done(dest_hash)                            # PATHFINDER_R = 1
    elif now > entry[RTRNS_TMO]:
        entry[RTRNS_TMO] = now + PATHFINDER_G + PATHFINDER_RW   # 5 s + 0.5 s
        entry[RETRIES] += 1
        context = PATH_RESPONSE if entry[BLCK_RBRD] else NONE
        new_packet = Packet(dest, entry[PACKET].data, ANNOUNCE, context=context,
                            header_type=HEADER_2, transport_type=TRANSPORT,
                            transport_id=Transport.identity.hash,
                            attached_interface=entry[ATTCHD_IF],
                            blocked_interfaces=entry[DEDUP_IFS] or None)
        new_packet.hops = entry[HOPS]
        new_packet.send()                          # broadcast on every eligible interface
```

The actual code is in `RNS/Transport.py:965-1029` → `# Process announces needing retransmission`. Note that the receiving interface is **not** excluded: a normal rebroadcast goes out on every interface, the one it arrived on included, minus the dedup set. That is how an announce travels along a single LoRa channel. Interface *modes* can still block it (access-point, roaming and boundary rules in `Transport._outbound`).

### 5. Per-interface `announce_queue` drain

Each interface independently throttles its outbound announces against `interface.announce_cap`, a **fraction** of airtime: `Reticulum.ANNOUNCE_CAP = 2` is a percentage, divided by 100 wherever an interface is configured (`RNS/Reticulum.py:1153` → `announce_cap = Reticulum.ANNOUNCE_CAP/100.0`), so the default is `0.02`. The lazy fallback for an interface without one does the same. Since RNS 1.6 it lives in the queue drain itself (`RNS/Interfaces/Interface.py:459-460` → `self.announce_cap = RNS.Reticulum.ANNOUNCE_CAP/100.0`) rather than in `Transport`. Through RNS 1.5.2 it assigned the raw `2`, a 200% cap that throttled nothing. `Interface.process_announce_queue` (`RNS/Interfaces/Interface.py:456-499` → `min_hops = min(entry["hops"] for entry in self.announce_queue)`) drains the queue at a rate the cap permits, **picking the lowest-hop-count entry first** so closer destinations propagate before further ones:

```python
min_hops = min(e["hops"] for e in self.announce_queue)
selected = sorted([e for e in self.announce_queue if e["hops"] == min_hops],
                  key=lambda e: e["time"])[0]
tx_time   = (len(selected["raw"]) * 8) / self.bitrate
wait_time = tx_time / self.announce_cap
self.announce_allowed_at = now + wait_time
self.process_outgoing(selected["raw"])
```

The `wait_time` is what enforces the cap: on a 5kbps LoRa channel, a 200-byte announce takes 320ms airtime; with cap=2%, the next announce isn't allowed for `320ms / 0.02 = 16s`. This is what makes Reticulum's mesh well-behaved on slow shared channels.

### 6. Rebroadcast emission with hop increment

The rebroadcast is a **new packet** built from the received announce's body (step 4). Its `hops` is the received value, which `Transport.preprocess_inbound` already incremented on receive (`RNS/Transport.py:2114` → `packet.hops += 1`). It is always `HEADER_2`/`TRANSPORT` with the relay's own `transport_id`, whatever header the announce arrived with. There is no re-signing: the signature covers only the body (§4.2), so the header can change freely. What's wire-visible is the same body (dest_hash, public key, random_hash, signature, app_data), a new header with the relay's `transport_id`, and a hops byte of (hops_received + 1).

This is why, since RNS 1.6, an originator's `HEADER_1` announce must stay at or under 484 bytes: the first relay adds 16 bytes (SPEC.md §4.5).

### 7. Local-rebroadcast counter cleanup

If the relay later **hears its own rebroadcast** (a peer further along in the chain re-emitted it), `Transport.inbound` at `RNS/Transport.py:2577-2587` → `announce_entry[IDX_AT_LCL_RBRD] += 1` increments `entry[IDX_AT_LCL_RBRD]`. Once `local_rebroadcasts >= LOCAL_REBROADCASTS_MAX`, the entry is removed from `announce_table`:

```python
if announce_entry[IDX_AT_LCL_RBRD] >= LOCAL_REBROADCASTS_MAX:
    announce_table.pop(packet.destination_hash)
```

This is what stops the rebroadcast loop: once enough downstream peers have echoed the announce back, the relay stops trying.

### 8. `random_blob` replay defence

§4.5 step 6.3 / §12.3.2 already covers this — the relay won't even queue a rebroadcast if the inbound announce's `random_hash` is already in the cached `random_blobs` for this destination. The receive-announce flow drops it at the path-table-update stage.

---

## Wire-byte summary

The forwarded announce is wire-identical to the original, except:

- The `hops` byte is one higher.
- The header is `HEADER_2` with `transport_type = TRANSPORT` and the relay's own 16-byte `transport_id`. Receivers use that `transport_id` as the path's next hop (`receive-announce.md` step 6). This is true of every relay rebroadcast, whether the announce arrived as `HEADER_1` from its originator or as `HEADER_2` from an earlier relay. `context_flag` (ratchet present) is copied from the received packet.

```
Before relay (received from originator):          After relay (emitted):
[ flags: HEADER_1+BROADCAST+SINGLE+ANNOUNCE ]     [ flags: HEADER_2+TRANSPORT+SINGLE+ANNOUNCE ]
[ hops = N ]                                      [ hops = N+1 ]
                                                  [ 16B transport_id = relay's identity hash ]
[ 16B dest_hash ]                                 [ same dest_hash ]
[ 1B context = 0x00 ]                             [ 0x00, or 0x0B when answering a path request ]
[ ... announce body ... ]                         [ ... body bytes unchanged ... ]
```

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | (this flow follows `receive-announce.md` step 7) | |
| 2 | `RNS/Transport.py` | `_inbound`, rebroadcast eligibility |
| 3 | `RNS/Transport.py` | `_inbound`, announce_table insert; dedup-interface set (RNS ≥ 1.6) |
| 4 | `RNS/Transport.py` | `jobs`, announce retransmission |
| 5 | `RNS/Interfaces/Interface.py` | `process_announce_queue` |
| 6 | `RNS/Transport.py` | hops increment in `preprocess_inbound` |
| 7 | `RNS/Transport.py` | `_inbound`, local-rebroadcast counter |
| 8 | `RNS/Transport.py` | `_inbound`, random_blob replay check |
