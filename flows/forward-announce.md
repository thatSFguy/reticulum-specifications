# Flow: forward an announce (transport-node rebroadcast)

What a transport-mode node does when it receives an inbound announce destined for a non-local destination. This is the flow that makes the mesh actually mesh — without it, announces never propagate beyond direct radio range. Pinned against **RNS 1.5.2**; cross-references [`../SPEC.md`](../SPEC.md) §4.5 (validation), §12.3 (rebroadcast rules), §12.4 (path table).

This flow only runs on a node with `enable_transport = Yes` per §12.1. Leaf clients can ignore it entirely.

---

## Sequence

### 1. Inbound announce passes validation

The receive-announce flow ([`receive-announce.md`](receive-announce.md)) runs first — signature check, dest_hash recompute, public-key collision check, ingress rate limit, path table population. By the time the rebroadcast logic runs, the announce is known-valid and the path_table entry is already updated.

### 2. Eligibility checks

`RNS/Transport.py:2351-2355` → `if (RNS.Reticulum.transport_enabled() or is_from_local_client) and packet.context != RNS.Packet.PATH_RESPONSE:`. Three conditions all must hold, but they are **not** one boolean — the rate check is nested inside the gate:

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
- `not rate_blocked` — per-interface announce-rate limits aren't tripped for this destination. A rate-blocked announce still passes the outer gate; it is logged and simply never inserted into `announce_table`, which is what suppresses the rebroadcast. `rate_blocked` is computed at `:2302-2330` → `rate_blocked = False` against `interface.announce_rate_target`.

### 3. Insert into `announce_table`

`Transport.py:2363-2374` → `Transport.announce_table[packet.destination_hash] = [`. The relay adds an entry:

```python
Transport.announce_table[packet.destination_hash] = [
    now,                          # 0  IDX_AT_TIMESTAMP
    retransmit_timeout,           # 1  IDX_AT_RTRNS_TMO  — when to actually emit
    retries,                      # 2  IDX_AT_RETRIES   — PATHFINDER_R, default 4
    received_from,                # 3  IDX_AT_RCVD_IF   — interface NOT to rebroadcast on
    announce_hops,                # 4  IDX_AT_HOPS
    packet,                       # 5  IDX_AT_PACKET    — full Packet object
    local_rebroadcasts,           # 6  IDX_AT_LCL_RBRD  — count of times peers retransmitted
    block_rebroadcasts,           # 7  IDX_AT_BLCK_RBRD — true if a peer beat us to it
    attached_interface,           # 8  IDX_AT_ATTCHD_IF
]
```

`retransmit_timeout` for non-local-client originated announces is `now + PATH_REQUEST_GRACE = 0.4s` (giving directly-reachable peers time to rebroadcast first; if they do, `block_rebroadcasts = True` is set and we suppress our own emission). Local-client originated announces fire `now` with no grace.

### 4. Periodic `Transport.jobs` walk drains the table

The relay's per-second-or-so housekeeping loop walks `announce_table` and for entries whose `retransmit_timeout <= now`, queues them for emission on each suitable interface:

```python
# Pseudocode of the relevant Transport.jobs branch
for dest_hash, entry in announce_table.items():
    if entry[BLCK_RBRD]:
        continue                                   # peer already rebroadcast — drop
    if now < entry[RTRNS_TMO]:
        continue                                   # not yet time
    if entry[RETRIES] <= 0:
        announce_table.pop(dest_hash)              # exhausted
        continue
    for interface in interfaces:
        if interface == entry[RCVD_IF]:
            continue                               # don't re-emit on receive interface
        interface.announce_queue.append({"raw": entry[PACKET].raw, ...})
    entry[RETRIES] -= 1
```

The actual code is in `Transport.py:737-800` → `Transport.links_last_checked =` (the `jobs` drain) and `:2090-2290` → `link_entry = [ now,` (the inbound announce path); the structure above is a simplification for the spec.

### 5. Per-interface `announce_queue` drain

Each interface independently throttles its outbound announces against `interface.announce_cap` (default `Reticulum.ANNOUNCE_CAP = 2.0` = 2% airtime). `Interface.process_announce_queue` (`RNS/Interfaces/Interface.py:390-431` → `min_hops = min(entry["hops"] for entry in self.announce_queue)`) drains the queue at a rate the cap permits, **picking the lowest-hop-count entry first** so closer destinations propagate before further ones:

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

When the queue actually emits, the wire bytes are the original announce's `packet.raw` with the `hops` byte already incremented (`Transport.inbound` did this at `RNS/Transport.py:1800` → `packet.hops += 1` on receive). No re-signing — the signature in the announce body covers the original hop=0 emission, and signature validation ignores the outer hops byte (it's not in `signed_data`). What's wire-visible is the same body, the same dest_hash, the same random_hash, and a hops byte that's now (hops_received + 1).

### 7. Local-rebroadcast counter cleanup

If the relay later **hears its own rebroadcast** (a peer further along in the chain re-emitted it), `Transport.inbound` at `RNS/Transport.py:2188-2198` → `announce_entry[IDX_AT_LCL_RBRD] += 1` increments `entry[IDX_AT_LCL_RBRD]`. Once `local_rebroadcasts >= LOCAL_REBROADCASTS_MAX`, the entry is removed from `announce_table`:

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
- If the relay is between a HEADER_1-emitting originator and a destination > 1 hop away, the relay does NOT do the §2.3 conversion for ANNOUNCE packets — announces always travel HEADER_1+BROADCAST. The HEADER_2 conversion is only for DATA packets.

```
Before relay (received):                          After relay (emitted):
[ flags: HEADER_1+BROADCAST+SINGLE+ANNOUNCE ]     [ same flags ]
[ hops = N ]                                      [ hops = N+1 ]
[ 16B dest_hash ]                                 [ same dest_hash ]
[ 1B context = 0x00 ]                             [ same context ]
[ ... announce body identical ... ]               [ ... bytes unchanged ... ]
```

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | (this flow follows `receive-announce.md` step 7) | |
| 2 | `RNS/Transport.py` | rebroadcast eligibility, line 2351 |
| 3 | `RNS/Transport.py` | announce_table insert, line 2362-2373 |
| 4 | `RNS/Transport.py` | jobs / queue drain, line 765-829 |
| 5 | `RNS/Interfaces/Interface.py` | `process_announce_queue`, line 390-431 |
| 6 | `RNS/Transport.py` | hops increment in `inbound`, line 1800 |
| 7 | `RNS/Transport.py` | local-rebroadcast counter, line 2183-2193 |
| 8 | `RNS/Transport.py` | random_blob replay check, line 2206-2298 |
