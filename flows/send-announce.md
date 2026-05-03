# Flow: send an announce

What happens chronologically when a node emits an announce — the periodic broadcast that lets the rest of the mesh discover or refresh a path to this destination. Pinned against **RNS 1.2.0**.

Out of scope: the relay-side rebroadcast (`forward-announce.md` — see [`../SPEC.md`](../SPEC.md) §12.3) and path-response announces (already covered in [`path-discovery.md`](path-discovery.md)).

---

## Sequence

### 1. Caller invokes `Destination.announce(app_data=...)`

`RNS/Destination.py:243-318`. Triggers:

- Periodic re-announce loop (every 5-15 minutes per §7.5; LXMF runs this from `LXMRouter.jobs`).
- Application-explicit announce (e.g. user clicks "announce now" in Sideband).
- Path-response branch — see [`path-discovery.md`](path-discovery.md) step 6.

### 2. Build `random_hash`

```python
random_hash = RNS.Identity.get_random_hash()[:5] + int(time.time()).to_bytes(5, "big")
```

5 random bytes + 5 bytes big-endian uint40 unix-seconds timestamp per [`../SPEC.md`](../SPEC.md) §4.1. The timestamp is used by transit relays for path-table replay-ordering decisions per §4.5 step 6.3.

### 3. Optional ratchet rotation

If the destination has ratchets enabled (`destination.ratchets != None`), `rotate_ratchets()` runs (`Destination.py:227-235`):

```python
if now > self.latest_ratchet_time + self.ratchet_interval:
    new_ratchet = Identity._generate_ratchet()             # X25519 keypair, 32B priv
    self.ratchets.insert(0, new_ratchet)                   # most-recent-first
    self.latest_ratchet_time = now
    self._clean_ratchets()                                 # cap at RATCHET_COUNT = 512
    self._persist_ratchets()                               # storagepath/ratchets/<hex>
```

The new ratchet's public key is what gets included in this announce. `RATCHET_INTERVAL = 30*60s` so a ratchet rotates at most every 30 minutes — back-to-back announces within that window reuse the current ratchet (per §7.3 the relays would dedup them on `(dest_hash, ratchet_pub)` if even the random_hash collided, but the 10 random bytes prevent that).

### 4. Build signed_data

Per §4.2:

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

`Destination.py:303-309`: store `self.path_responses[tag] = [time.time(), announce_data]` if a `tag` was supplied (path-response branch). The cache TTL is `PR_TAG_WINDOW = 30s` per §7.2.4 — same wire bytes served to multiple racing relays for dedup convergence.

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

Announce packets are NOT encrypted — `Packet.pack` (`RNS/Packet.py:189-191`) special-cases ANNOUNCE to skip encryption. The body is signed but plaintext, so anyone in earshot can validate the signature and decode the public key.

### 8. `Transport.outbound` broadcasts on every OUT interface

Same broadcast branch as a path? request (`flows/path-discovery.md` step 2) — the dest_hash isn't in `path_table` (it's our own destination, not a remote one), so the broadcast branch at `RNS/Transport.py:1119+` fires, emitting on every interface where `interface.OUT == True`. Per §7.5 the announce is rate-limited by `ANNOUNCE_CAP = 2.0` (2% airtime) on each interface.

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
[ N B  app_data ]     ← may be empty
```

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | `RNS/Destination.py` | `announce`, line 243 |
| 2 | `RNS/Destination.py` | random_hash construction, line 282 |
| 3 | `RNS/Destination.py` | `rotate_ratchets`, line 227 |
| 4 | `RNS/Destination.py` | signed_data assembly, line 297 |
| 5 | `RNS/Destination.py` | sign + pack, line 300-303 |
| 6 | `RNS/Destination.py` | path_responses cache, line 305 |
| 7 | `RNS/Destination.py` | Packet construction, line 313 |
| 7 | `RNS/Packet.py` | ANNOUNCE-skips-encryption, line 189-191 |
| 8 | `RNS/Transport.py` | outbound broadcast branch, line 1119 |
| 9 | `LXMF/LXMRouter.py` | jobs / re-announce cadence |
