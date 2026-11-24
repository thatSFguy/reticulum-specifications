# Flow: send an announce

What happens chronologically when a node emits an announce — the periodic broadcast that lets the rest of the mesh discover or refresh a path to this destination. Pinned against **RNS 1.6.1**.

Out of scope: the relay-side rebroadcast (`forward-announce.md` — see [`../SPEC.md`](../SPEC.md) §12.3) and path-response announces (already covered in [`path-discovery.md`](path-discovery.md)).

---

## Sequence

### 1. Caller invokes `Destination.announce(app_data=...)`

`RNS/Destination.py:286-305` → `def announce(self, app_data=None, path_response=False, attached_interface=None, tag=None, send=True):` (the public entry point only; the build is `_announce`, step 2). Triggers:

- Periodic re-announce loop (every 5-15 minutes per §7.5; LXMF runs this from `LXMRouter.jobs`).
- Application-explicit announce (e.g. user clicks "announce now" in Sideband).
- Path-response branch — see [`path-discovery.md`](path-discovery.md) step 6.

**Since RNS 1.6, `announce()` may not emit anything yet.** Announces are stamped by default (`STAMP_DESTINATIONS = True`, [`../SPEC.md`](../SPEC.md) §4.7). If the destination has no stamp yet, `announce()` queues the work for the background stamper thread and returns `None` (`RNS/Destination.py:297-301` → `RNS.Transport.enqueue_stamped_announce(self, app_data=app_data, path_response=path_response,`). Only a destination that already holds a stamp builds and sends inline, through `_announce` (`RNS/Destination.py:307` → `def _announce(self`). Consequences an implementer driving upstream, or copying its behaviour, should know:

- **The first announce of a new destination is delayed** by the stamp's proof-of-work, generated to `DESTINATION_VALUE = 25.0` (`RNS/Transport.py:201` → `DESTINATION_VALUE           = 25.0`). Receivers require only `DESTINATION_COST = 23.5` by default (§4.7). In the verifier runs for this revision it took about two minutes of CPU. The stamp is then persisted (§4.7) and reused, so later announces go out immediately.
- **Queued announces for one destination collapse.** The queue is keyed on `destination.hash`, and a new entry replaces any pending one for the same key (`RNS/Transport.py:1529-1538` → `def enqueue_stamped_announce(`, `:107-119` → `def put(self, priority, key, item):`). Path-response announces use key `None`, so they never collapse, and they run at the higher priority.
- **A full queue drops the announce.** The limit is `STAMPER_AN_QUEUE_LENGTH = 32` pending destinations, and the drop is logged only at DEBUG.
- `announce(send=False)` bypasses the queue and **blocks** in `_announce` until the stamp exists (`RNS/Destination.py:349` → `if not self._await_stamp():`). If stamp generation fails, it returns `None` and nothing is announced.

### 2. Build `random_hash`

```python
random_hash = RNS.Identity.get_random_hash()[:5] + int(time.time()).to_bytes(5, "big")
```

5 random bytes + 5 bytes big-endian uint40 unix-seconds timestamp per [`../SPEC.md`](../SPEC.md) §4.1 (`RNS/Destination.py:333` → `random_hash = RNS.Identity.get_random_hash()[0:5]+int(time.time()).to_bytes(5, "big")`). The timestamp is used by transit relays for path-table replay-ordering decisions per §4.5 step 6.3.

Since RNS 1.6 this timestamp is taken **before** step 3b waits for the stamp. On a destination's first announce it can therefore predate emission by the full proof-of-work time, which can be minutes. Receivers must not apply a freshness window to it ([`../SPEC.md`](../SPEC.md) §15).

### 3. Optional ratchet rotation

If the destination has ratchets enabled (`destination.ratchets != None`), `rotate_ratchets()` runs (`RNS/Destination.py:250-264` → `new_ratchet = RNS.Identity._generate_ratchet()`):

```python
if now > self.latest_ratchet_time + self.ratchet_interval:
    new_ratchet = Identity._generate_ratchet()             # X25519 keypair, 32B priv
    self.ratchets.insert(0, new_ratchet)                   # most-recent-first
    self.latest_ratchet_time = now
    self._clean_ratchets()                                 # cap at RATCHET_COUNT = 512
    self._persist_ratchets()                               # storagepath/ratchets/<hex>
```

The new ratchet's public key is what gets included in this announce. `RATCHET_INTERVAL = 30*60s` so a ratchet rotates at most every 30 minutes — back-to-back announces within that window reuse the current ratchet (per §7.3 the relays would dedup them on `(dest_hash, ratchet_pub)` if even the random_hash collided, but the 10 random bytes prevent that).

### 3b. Append the stamp trailer (RNS ≥ 1.6)

If no `app_data` was passed, the destination's `default_app_data` (bytes, or a callable returning bytes) is used. Then, with `STAMP_DESTINATIONS` on, `_announce` waits for the destination stamp and appends the 18-byte trailer of [`../SPEC.md`](../SPEC.md) §4.7 to `app_data` (`RNS/Destination.py:354` → `ext_payload = bytes([RNS.Identity.EXTPAYLOADMARKER, self.get_ext_flags()])+self.stamp+bytes([cost_bytes[1], cost_bytes[0]])`):

```python
app_data = (app_data or b"") + b"\xC1" + ext_flags + stamp(14) + lr_cost_frac + lr_cost_int
```

With no application `app_data` at all, `app_data` is exactly the 18-byte trailer. Everything from here on (signature, body, wire size) includes the trailer.

### 4. Build signed_data

Per §4.2 (`RNS/Destination.py:359-360` → `signed_data = self.hash+self.identity.get_public_key()+self.name_hash+random_hash+ratchet`):

```python
signed_data = self.hash + self.identity.get_public_key() + self.name_hash + random_hash + ratchet
if app_data is not None:
    signed_data += app_data
```

`self.hash` is the destination_hash (which appears in the outer Reticulum header on the wire, but is also signed). `ratchet` is `b""` when no ratchet is included.

### 5. Sign and pack the announce body

```python
signature = self.identity.sign(signed_data)                # Ed25519 long-term key
announce_data = self.identity.get_public_key() + self.name_hash + random_hash + ratchet + signature
if app_data is not None:
    announce_data += app_data
```

The `dest_hash` is **not** in `announce_data` even though it's in `signed_data` — the receiver gets `dest_hash` from the outer packet header per §4.1.

### 6. Cache the body for path-response replay

`RNS/Destination.py:367` → `self.path_responses[tag] = [time.time(), announce_data]`: stored if a `tag` was supplied (path-response branch). The cache TTL is `PR_TAG_WINDOW = 30s` per §7.2.4 — same wire bytes served to multiple racing relays for dedup convergence.

### 7. Construct and emit the Reticulum ANNOUNCE packet

```python
context_flag = FLAG_SET if ratchet else FLAG_UNSET
announce_context = PATH_RESPONSE if path_response else NONE
announce_packet = RNS.Packet(self, announce_data,
                             RNS.Packet.ANNOUNCE,
                             context = announce_context,
                             attached_interface = attached_interface,
                             context_flag = context_flag)
announce_packet.send()
```

Wire form per §4.1:
- `packet_type = ANNOUNCE (1)`, `transport_type = BROADCAST (0)`, `destination_type = SINGLE (0)`
- `header_type = HEADER_1` (the ratchet rotation announce is always broadcast — no transport_id at this stage)
- `context = NONE (0x00)` for periodic re-announces, `PATH_RESPONSE (0x0B)` for path-response announces
- `context_flag = 1` if ratchet present (signals the optional ratchet_pub slot in the body)

**Size limit (RNS ≥ 1.6).** `Packet.pack` refuses a `HEADER_1` announce whose packed size plus a 16-byte `transport_id` would exceed the MTU. So an originated announce is at most **484 bytes**, leaving room for the first relay to rewrite it as `HEADER_2` (`RNS/Packet.py:240-243` → `Transport-inserted announce packet size of`; [`../SPEC.md`](../SPEC.md) §4.5). The 18-byte stamp trailer counts toward this, which leaves 18 bytes less for application `app_data` than at RNS 1.5.7.

Announce packets are NOT encrypted — `Packet.pack` (`RNS/Packet.py:196-198` → `# Announce packets are not encrypted`) special-cases ANNOUNCE to skip encryption. The body is signed but plaintext, so anyone in earshot can validate the signature and decode the public key.

### 8. `Transport.outbound` broadcasts on every OUT interface

Same broadcast branch as a path? request (`flows/path-discovery.md` step 2) — the dest_hash isn't in `path_table` (it's our own destination, not a remote one), so the broadcast branch at `RNS/Transport.py:1740-1758` → `# If we don't have a known path for the destination, we'll` fires, emitting on every interface where `interface.OUT == True`. Per §7.5 the announce is rate-limited by `ANNOUNCE_CAP = 2` (a percentage: 2% airtime) on each interface.

### 9. Periodic re-announce loop

LXMF runs this via `LXMRouter.jobs` calling `LXMRouter.announce_propagation_node` and `LXMRouter.announce_destination` (for delivery destinations) at the configured cadence. Default re-announce interval is 5-15 minutes per §7.5. Without it, transit-relay path tables age out within minutes and peers can't message you.

---

## Wire-byte summary

```
[ 1B flags: HEADER_1 | context_flag | BROADCAST | SINGLE | ANNOUNCE ]
[ 1B hops=0 ]
[ 16B dest_hash ]
[ 1B context: 0x00 normal / 0x0B PATH_RESPONSE ]
[ 64B public_key (X25519 || Ed25519) ]
[ 10B name_hash ]
[ 10B random_hash (5B random || 5B big-endian uint40 unix_seconds) ]
[ 32B ratchet_pub ]   ← present iff context_flag bit set
[ 64B Ed25519 signature ]
[ N B  app_data ]     ← application app_data, may be empty
[ 18B stamp trailer ] ← 0xC1 || flags || stamp(14) || lr_cost(2); RNS ≥ 1.6 default, signed as part of app_data
```

Total ≤ 484 bytes (§4.5, RNS ≥ 1.6).

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | `RNS/Destination.py` | `announce`; queues to the stamper when no stamp is held |
| 1 | `RNS/Transport.py` | `enqueue_stamped_announce`, `stamper_job`, `WorkerQueues.put` |
| 2 | `RNS/Destination.py` | `_announce`, random_hash construction |
| 3 | `RNS/Destination.py` | `rotate_ratchets` |
| 3b | `RNS/Destination.py` | `_announce` → `_await_stamp`, `ext_payload` |
| 4 | `RNS/Destination.py` | `_announce`, signed_data assembly |
| 5 | `RNS/Destination.py` | `_announce`, sign + pack |
| 6 | `RNS/Destination.py` | `_announce`, path_responses cache |
| 7 | `RNS/Destination.py` | `_announce`, Packet construction |
| 7 | `RNS/Packet.py` | `pack`: ANNOUNCE skips encryption; `HEADER_1` headroom check |
| 8 | `RNS/Transport.py` | `_outbound` broadcast branch |
| 9 | `LXMF/LXMRouter.py` | jobs / re-announce cadence |
