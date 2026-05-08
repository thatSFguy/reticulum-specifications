# Flow: discover a path to an unknown destination

What happens chronologically when one node wants to reach another whose path is missing from `Transport.path_table`. This flow drives the well-known `rnstransport.path.request` destination (dest_hash `6b9f66014d9853faab220fba47d02761`, see [`../SPEC.md`](../SPEC.md) §1.2 and §7.1) and the path-response announce that returns along the reverse path.

Pinned against **RNS 1.2.4**.

Out of scope: the LXMF outbound retry that gates this flow (`flows/send-opportunistic-lxmf.md` step 4); the periodic `Transport.jobs` cycle that ages out stale paths; transport-mode rebroadcast of a known path on behalf of a remote requester (Tier 3 spec gap, see `../todo.md`).

---

## Preconditions

- Initiator has at least one `RNS.Identity` with private keys.
- Initiator has *no* `path_table` entry for the target — `RNS.Transport.has_path(dest_hash)` returns False. If a path entry exists, this flow does not run; the LXMF outbound goes straight through with the cached path.
- At least one node within reach knows the target — either because the target is directly attached to it (leaf-owns-destination case) or because it has the target in its own `path_table` (transport-relay-knows-path case). If nobody on the mesh knows, the request times out and the LXMF retry escalates per `LXMRouter.process_outbound`.

---

## Sequence

### 1. Initiator: `RNS.Transport.request_path(dest_hash)`

`RNS/Transport.py:2713-2750`. Triggered by:

- `LXMRouter.handle_outbound` when `not has_path(dest) and method == OPPORTUNISTIC` (see `send-opportunistic-lxmf.md` step 4).
- `LXMRouter.process_outbound` retry path after `MAX_PATHLESS_TRIES`.
- Application code calling `Transport.request_path()` directly (rncp, rnpath, rnstatus utilities all do this).

`request_path` constructs a `Packet` addressed to the well-known path-request destination:

```python
request_tag = tag or Identity.get_random_hash()                # 16B random unless caller supplied
if Reticulum.transport_enabled():
    payload = destination_hash + Transport.identity.hash + request_tag    # 48 bytes
else:
    payload = destination_hash + request_tag                              # 32 bytes

path_request_dst = Destination(None, OUT, PLAIN, "rnstransport", "path", "request")
packet = Packet(path_request_dst, payload,
                packet_type=DATA, transport_type=BROADCAST,
                header_type=HEADER_1, attached_interface=on_interface)
packet.send()
Transport.path_requests[destination_hash] = time.time()
```

The well-known dest hash `6b9f66014d9853faab220fba47d02761` is computed as `SHA256(SHA256("rnstransport.path.request")[:10])[:16]` per [`../SPEC.md`](../SPEC.md) §1.2 (the `identity=None` branch of `Destination.hash`). It is the same on every node — no per-node uniqueness — because the destination is `PLAIN` with no identity attached.

The packet is `DATA` (not ANNOUNCE), `BROADCAST` transport, `HEADER_1`, and `context = NONE`. The body is **unencrypted** because the outer destination is `PLAIN` — `Packet.pack` falls through to `self.destination.encrypt(self.data)` at `RNS/Packet.py:215`, and `Destination.encrypt` returns `plaintext` unchanged for `Destination.PLAIN` (`RNS/Destination.py:592-593`).

Initiator records `Transport.path_requests[destination_hash] = time.time()` for `PATH_REQUEST_GATE_TIMEOUT = 120s` rate-limiting (prevents the same node from repeating identical path? requests faster than `PATH_REQUEST_MI = 20s`).

### 2. Initiator: `Transport.outbound` broadcasts the request

The path? packet then runs through the standard outbound flow (`send-opportunistic-lxmf.md` steps 7-8) but lands in the broadcast branch (`Transport.py:1119+`) because its destination is `PLAIN` and not in the `path_table`. Result: the packet is transmitted on every OUT-flagged interface, not just one. This is intentional — until we know where the target lives, we have to ask everyone.

If the initiator is a transport node, the broadcast is subject to `announce_cap` rate limiting just like an announce (`Transport.py:1196+`). Leaf clients have no announce_cap and broadcast unthrottled.

### 3. Each peer: `Transport.inbound` recognizes the path-request destination

Every node on every interface that hears the broadcast packet runs it through `Transport.inbound`. The dispatch by `(packet_type, destination_type)` lands in the `DATA + PLAIN` branch (`Transport.py:2087-2103` — same code as the opportunistic-LXMF DATA dispatch in `flows/receive-opportunistic-lxmf.md` step 6, but for a PLAIN destination instead of SINGLE).

The destination lookup hits `Transport.destinations_map[dest_hash]` for the well-known path-request destination — every node has this destination registered automatically during `Transport.__init__` at `Transport.py:237-240`:

```python
Transport.path_request_destination = RNS.Destination(
    None, RNS.Destination.IN, RNS.Destination.PLAIN,
    Transport.APP_NAME, "path", "request",
)
Transport.path_request_destination.set_packet_callback(Transport.path_request_handler)
```

Control reaches `Destination.receive` → `path_request_handler(data, packet)`.

### 4. Each peer: parse and dedup

`Transport.py:2800-2843`. Per [`../SPEC.md`](../SPEC.md) §7.2.1, the handler extracts:

```
data[ 0:16]  destination_hash      — the requested target
data[16:32]  requesting_transport_instance OR tag_bytes (depending on length)
data[32:..]  tag_bytes              — only present when len(data) > 32
```

Tagless requests are dropped. Otherwise the handler builds `unique_tag = destination_hash || tag_bytes[:16]` and consults `discovery_pr_tags` to dedup (see §7.2.2). Duplicate requests are silently ignored without further processing — important because the broadcast in step 2 will reach the same relay via multiple interfaces in a meshy topology.

### 5. Each peer: dispatch in `Transport.path_request`

`Transport.py:2846-2973`, also documented in [`../SPEC.md`](../SPEC.md) §7.2.3. Five mutually-exclusive branches:

- **Branch 1 — local destination (the responder we want):** `destination_hash` is in `Transport.destinations_map`. Call `local_destination.announce(path_response=True, tag=tag, attached_interface=...)`. **Goto step 6.**
- **Branch 2 — transit relay knows the path:** `transport_enabled` AND `dest_hash` in `path_table`. Pull the cached announce packet from `path_table[dest_hash][IDX_PT_PACKET]`, queue it for rebroadcast on the receiving interface with `PATH_REQUEST_GRACE = 0.4s` delay (or `+1.5s` on roaming-mode interfaces). Out of scope for this flow doc — see Tier 3 todo.
- **Branch 3 — local client → forward:** request came from a local-client interface and we don't know the path. Forward the request to every other interface with a fresh random tag.
- **Branch 4 — transport-enabled, unknown, discovery-allowed:** record a `discovery_path_requests` entry (15s timeout) and forward the request to every other interface preserving the original tag.
- **Branch 5 — no match:** drop silently.

For a leaf client only Branches 1 and 5 matter. Branches 2-4 are transport-node behaviour.

### 6. Responder: `Destination.announce(path_response=True, tag=tag, ...)`

`RNS/Destination.py:243-318`. Builds an announce packet identical in body to a regular periodic announce (see `flows/receive-announce.md` for the validation side and [`../SPEC.md`](../SPEC.md) §4.1 for the body bytes), with two distinctions:

1. **Outer packet context = `PATH_RESPONSE (0x0B)`** instead of `NONE (0x00)`:
   ```python
   if path_response: announce_context = RNS.Packet.PATH_RESPONSE
   else:             announce_context = RNS.Packet.NONE
   ```
   This is the only wire-byte difference between a path response and a regular re-announce.

2. **`tag` parameter caches the body for `PR_TAG_WINDOW = 30s`** (`Destination.py:260-278`). If multiple relays forward the same `path?` to this leaf in quick succession, the leaf serves the **same announce bytes** to all of them — same `random_hash`, same `signature`, identical wire bytes — so transit-relay dedup logic (path-table `random_blobs` cache, see [`../SPEC.md`](../SPEC.md) §4.5 step 6.3) treats the multiple incoming responses as one.

The path-response announce is sent on `attached_interface` only (the interface the request arrived on), not broadcast on all interfaces — so the response travels back along the same path the request came in on.

### 7. Reverse path traversal

The path-response announce is itself a regular ANNOUNCE packet, broadcast-routed. As it traverses each transit node, the standard receive-announce flow runs (`flows/receive-announce.md`):

- Step 2: signature-only quick check, increment per-interface ingress-frequency deque.
- Step 3: ingress-rate limit check — but **path-responses bypass ingress limiting** because the destination is in `Transport.path_requests` (recently-requested-by-us) or `Transport.discovery_path_requests` (recently-requested-on-behalf-of). See `Transport.py:1632-1639`.
- Step 5: full `validate_announce` — same signature, dest_hash, collision checks as any announce.
- Step 7: path table population. **The hop count is whatever the cached announce stored** (`Transport.py:2890`: `packet.hops = path_table[dest_hash][IDX_PT_HOPS]` if served from cache by Branch 2); for Branch 1 responses, hops counts up naturally as the announce traverses back.
- Step 8: announce handler fan-out. **Path-response announces are filtered OUT of regular handler dispatch by default** (`Transport.py:1989-1991`):
  ```python
  if packet.context == RNS.Packet.PATH_RESPONSE:
      execute_callback = handler.receive_path_responses == True
  ```
  So an LXMF delivery handler that doesn't opt in via `receive_path_responses = True` won't see path-response announces as "new contacts", but will still benefit from the path-table side effect.

### 8. Initiator: path table populated, deferred LXM resumes

When the path-response announce arrives back at the initiator, `validate_announce` populates `Transport.path_table[dest_hash]` with `[recv_time, received_from, hops, expires, random_blobs, receiving_interface, packet_hash]` per [`../SPEC.md`](../SPEC.md) §4.5 step 6.3.

`Transport.has_path(dest_hash)` now returns True. The next time `LXMRouter.process_outbound` checks the deferred LXM (after `LXMRouter.PATH_REQUEST_WAIT` from `send-opportunistic-lxmf.md` step 4), it finds the path is known and proceeds to the encrypt-and-send branch in `LXMessage.send`.

### 9. Timeout and escalation

If no response arrives within `Transport.PATH_REQUEST_TIMEOUT = 15s`, the `discovery_path_requests` entry on transit relays is aged out by the `Transport.jobs` cycle (`Transport.py:778-783`). The originating LXM stays in `pending_outbound`; on the next retry tick after `LXMRouter.PATH_REQUEST_WAIT`, `LXMRouter.process_outbound` checks `has_path()` again, finds it still False, and re-issues `request_path`. This continues up to `LXMRouter.MAX_DELIVERY_ATTEMPTS` (typically 5) before the message is marked failed.

The full outer retry behaviour (drop_path then re-request, the `MAX_PATHLESS_TRIES + 1` rediscovery branch at `LXMRouter.py:2577-2586`) is documented in `flows/send-opportunistic-lxmf.md` step 12.

---

## Wire-byte ladder

Single-hop request, leaf-client target (no transport_id in request):

```
                                             Initiator              Mesh / Relay              Target leaf
1. PATH? request (DATA, dest=well-known      ──────────────────────►──────────────────────►
   PLAIN destination 6b9f...02761,
   ctx=0x00)
   payload = target_dest_hash(16) || tag(16)

   broadcast on every OUT interface

2. PATH-RESPONSE announce (ANNOUNCE,                                ◄──────────────────────  Branch 1: leaf
   dest=target_dest_hash, ctx=0x0B)                                                            owns dest →
                                                                                              announces with
                                                                                              ctx=PATH_RESPONSE

   forwarded along reverse path back        ◄──────────────────────
   to initiator
```

Two-hop request, transit relay knows the path:

```
                                             Initiator              Transit relay         Target leaf (offline)
1. PATH? request                             ──────────────────────►
   payload = target || transport_id || tag

2. (no broadcast forward)                                            Branch 2: relay
                                                                     pulls cached announce
                                                                     from its path_table

3. PATH-RESPONSE announce (cached            ◄──────────────────────
   announce body, ctx rewritten
   to PATH_RESPONSE)
   PATH_REQUEST_GRACE = 0.4s delay before
   relay rebroadcasts
```

In the second case, the target leaf doesn't see the request at all — the relay answers from its cache. This is the "transport-enabled rnsd in the middle" case that makes Reticulum resilient to leaf-node sleep/wake cycles: as long as one relay heard the leaf's most recent announce, peers can find it for the duration of `Transport.AP_PATH_TIME` after that.

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | `RNS/Transport.py` | `request_path`, line 2707 |
| 2 | `RNS/Transport.py` | `outbound` broadcast branch, line 1119+ |
| 3 | `RNS/Transport.py` | `Transport.__init__` registration, line 237; PLAIN+DATA dispatch, line 2087+ |
| 4 | `RNS/Transport.py` | `path_request_handler`, line 2800 |
| 5 | `RNS/Transport.py` | `path_request`, line 2846 (5-way dispatch) |
| 6 | `RNS/Destination.py` | `announce(path_response=True)`, line 243 |
| 7 | `RNS/Transport.py` | inbound ANNOUNCE branch, line 1623; ingress-limit bypass, line 1637 |
| 7 | `RNS/Transport.py` | path-response handler filter, line 1989-1991 |
| 8 | `LXMF/LXMRouter.py` | `process_outbound` resume after path-resolution, line 2566 |
| 9 | `RNS/Transport.py` | `discovery_path_requests` cleanup, line 778-783 |
