# Flow: send an LXMF message over a Reticulum Link (DIRECT method)

What happens chronologically when an app calls `LXMRouter.handle_outbound(lxm)` for an `LXMessage` whose `desired_method == DIRECT` (or whose payload exceeds the opportunistic single-packet content limit and is downgraded from `OPPORTUNISTIC` to `DIRECT` at pack time). The `DIRECT` method runs the LXMF body over an established Reticulum Link rather than a single Reticulum DATA packet.

Pinned against **RNS 1.5.2 / LXMF 1.1.1**. Line numbers below are from those versions.

Out of scope: opportunistic delivery (see [`send-opportunistic-lxmf.md`](send-opportunistic-lxmf.md)), propagation-node delivery (`PROPAGATED`), and paper messages (`PAPER`).

---

## When DIRECT runs

DIRECT is reached two ways:

1. **App-requested:** `LXMessage(desired_method=LXMessage.DIRECT, …)`. Used for messages too large for one packet, or for sessions where the app wants the link's full-duplex DATA channel (e.g. an interactive chat). The router opens or reuses an `RNS.Link` to the recipient and sends the message over it.
2. **Auto-downgrade from OPPORTUNISTIC:** `LXMessage.pack` at `LXMF/LXMessage.py:397-411` → `raise TypeError(f"LXMessage desired opportunistic delivery method` falls back to `DIRECT` if the encrypted-form content size exceeds `ENCRYPTED_PACKET_MAX_CONTENT`. The originator may or may not surface this transition to the user; it's silent at the protocol layer.

Within DIRECT there are two **representations** decided at pack time (`LXMF/LXMessage.py:414-421` → `self.representation = LXMessage.PACKET`):

- **PACKET** — the body fits in a single `LINK_PACKET_MAX_CONTENT`-sized DATA packet on the link.
- **RESOURCE** — the body is larger than that and must be sent as an `RNS.Resource` (multi-packet, fragmented, with its own checksum / progress / retransmit machinery). The Resource fragmentation protocol is currently NOT in [`../SPEC.md`](../SPEC.md); see [`../todo.md`](../todo.md). This flow document covers PACKET in full and only sketches RESOURCE.

---

## Sequence

### 1. App constructs `LXMessage` and submits it

Same as steps 1-2 of `send-opportunistic-lxmf.md`. `LXMessage.pack()` builds the same `dest_hash || src_hash || signature || msgpack_payload` bytes per [`../SPEC.md`](../SPEC.md) §5.5; the difference is that for DIRECT delivery the **recipient's `dest_hash` is NOT stripped** before transmission (SPEC.md §5.2 vs §5.1) — the link payload includes it. `LXMRouter.handle_outbound` adds the message to `pending_outbound` and starts `process_outbound` in a thread.

### 2. `process_outbound` enters the DIRECT branch

`LXMF/LXMRouter.py:2700-2714` → `if lxmessage.method == LXMessage.DIRECT and delivery_destination_hash in self.direct_links:`. Logic for an `LXMessage` whose `method == DIRECT`:

```python
delivery_destination_hash = lxmessage.get_destination().hash
direct_link = self.direct_links.get(delivery_destination_hash) \
           or self.backchannel_links.get(delivery_destination_hash)

if direct_link is not None:
    if direct_link.status == RNS.Link.ACTIVE:
        # Step 5 below — link is up, transfer the LXM
        lxmessage.set_delivery_destination(direct_link)
        lxmessage.send()
    elif direct_link.status == RNS.Link.CLOSED:
        # Drop link, request_path, retry
        ...
    else:
        # PENDING — wait for ACTIVE or CLOSED via established_callback
        ...
else:
    # No link exists; establish one IF a path is known, else request_path first.
    if RNS.Transport.has_path(delivery_destination_hash):
        delivery_link = RNS.Link(lxmessage.get_destination())          # step 3
        delivery_link.set_link_established_callback(self.process_outbound)
        self.direct_links[delivery_destination_hash] = delivery_link
    else:
        RNS.Transport.request_path(delivery_destination_hash)          # step 0 (path?)
        lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
```

Setting `process_outbound` itself as the link's established-callback is the trick that connects steps 3-4 to step 5: when the LRPROOF arrives and the link transitions to ACTIVE, the callback re-enters `process_outbound`, finds the now-active link in `self.direct_links`, and proceeds to the transfer branch.

### 3. `RNS.Link(destination)` builds and sends a LINKREQUEST

`RNS/Link.py:230-323` → `def __init__(self, destination=None, established_callback=None`. The `Link` constructor on the **initiator** side generates a fresh ephemeral X25519 + Ed25519 keypair (`pub_bytes` and `sig_pub_bytes`) and constructs the LINKREQUEST body (`RNS/Link.py:308-324`):

```
request_data = initiator_X25519_pub(32) || initiator_Ed25519_pub(32) || [signalling(3)]
```

Both initiator-side keys are **fresh-ephemeral**, used only for this link. The optional 3-byte `signalling` field, present iff `Reticulum.link_mtu_discovery()` returns true and the next-hop interface advertises an HW MTU, encodes the path-MTU and link-mode hints (SPEC.md §6.1; encode/decode helpers at `RNS/Link.py:148-152` → `def signalling_bytes(mtu, mode)`).

```python
self.packet = RNS.Packet(destination, self.request_data, packet_type=RNS.Packet.LINKREQUEST)
self.packet.pack()
self.set_link_id(self.packet)                                    # = SHA256(get_hashable_part)[:16]
RNS.Transport.register_link(self)
self.start_watchdog()                                            # 60s establishment_timeout per hop
self.packet.send()
```

The LINKREQUEST is a **regular Reticulum DATA-routed packet** — `packet_type = LINKREQUEST (2)`, `destination_type = SINGLE`, addressed to the recipient's `lxmf.delivery` `dest_hash`. Per `RNS/Packet.py::pack` (`RNS/Packet.py:192-194`) `LINKREQUEST` packets are **not encrypted** — the body is `request_data` verbatim — because the responder needs to decode the public keys to perform the handshake.

The link_id is set immediately on the initiator side via `set_link_id` (SPEC.md §6.3): the SHA-256-truncated-to-16 hash of `get_hashable_part(LINKREQUEST_packet)`, with trailing signalling bytes stripped via `link_id_from_lr_packet`. Since `get_hashable_part` is invariant under HEADER_1↔HEADER_2 conversion (`RNS/Packet.py:348-353`), the responder will arrive at the same link_id even if the LINKREQUEST passed through one or more relays.

The LINKREQUEST then goes through the same `Transport.outbound` path as any other DATA packet (steps 7-9 of `send-opportunistic-lxmf.md`), which means it can itself be subject to the path-table miss → path-request preamble before it leaves.

### 4. Wait for LRPROOF; verify; complete handshake

The initiator's link sits in `Link.PENDING` while it waits for the responder's LRPROOF. The responder's side of this exchange (entering `Destination.receive` with `packet_type == LINKREQUEST` → `incoming_link_request` → `Link.validate_request` → `Link.handshake` → `Link.prove`, all at `RNS/Link.py:186-227` → `def validate_request(owner, data, packet)`, and `:348-375`) is its own flow document; this flow describes only what the initiator sees.

The LRPROOF arrives back at `Transport.inbound` with `packet_type = PROOF`, `context = LRPROOF (0xff)`, `dest_hash = link_id`. `Transport.inbound` looks up the link by its `link_id` and dispatches to `Link.validate_proof` (`RNS/Link.py:391-451` → `def validate_proof(self, packet)`). For an initiator with link still in `PENDING`:

```
proof_data layout (RNS/Link.py:371):
   signature(64) || responder_X25519_pub(32) || [signalling(3)]
```

Validation (`RNS/Link.py:410-422`):

1. Parse `signature = packet.data[:64]`, `peer_pub_bytes = packet.data[64:96]`.
2. Read the responder's long-term Ed25519 public key from the `Destination.identity` we already had cached (from a prior announce — line 412: `self.destination.identity.get_public_key()[ECPUBSIZE//2:ECPUBSIZE]`). The Ed25519 pub is **not** sent in the LRPROOF body; it must be known locally already.
3. Derive `signed_data = link_id || responder_X25519_pub || responder_long_term_Ed25519_pub || [signalling]` (line 417).
4. Verify the Ed25519 signature against `signed_data` using the responder's long-term Ed25519 pub.
5. On success: `link.handshake()` runs (`RNS/Link.py:348-363` → `def handshake(self)`) — ECDH with the responder's fresh X25519 pub, then HKDF over the shared secret with `salt = link_id`, derives `signing_key(32) || encrypt_key(32)` per SPEC.md §6.4. Link state transitions to `Link.ACTIVE`.
6. The initiator's `established_callback` registered at step 2 — `LXMRouter.process_outbound` — fires, re-entering step 2 with the link now ACTIVE.

A confirmed-MTU hint in the LRPROOF (length is `64+32+3 = 99` instead of `64+32 = 96`) updates `link.mtu` to the smaller of the responder's hint and the initiator's view (`RNS/Link.py:404-408`).

Immediately after step 5 succeeds — and before any application DATA leaves — the initiator MUST emit a Link Round-Trip Time packet (`context = LRRTT (0xfe)`, `RNS/Link.py:440-442`). This is **not** an informational hint; the responder uses LRRTT receipt as the sole trigger to transition its own link state from `HANDSHAKE` to `ACTIVE` and to fire the application's `link_established_callback` (per SPEC.md §6.4.2). On the LXMF responder that callback is what installs `set_resource_strategy(ACCEPT_APP)` (`LXMF/LXMRouter.py:1959`); without it, every Resource ADV the initiator sends — including any LXM body large enough to spill from packet form into Resource form — silently hits the `ACCEPT_NONE` branch on the responder and is dropped. The initiator transitions to `ACTIVE` independently on LRPROOF validation, but the responder does not.

### 5. Transfer the LXM body over the active link

Back in `process_outbound` (`LXMF/LXMRouter.py:2789-2799`), with `direct_link.status == ACTIVE`:

```python
lxmessage.set_delivery_destination(direct_link)                 # __delivery_destination = link
lxmessage.send()                                                # LXMessage.send branches on representation
```

`LXMessage.send` for DIRECT/PACKET (`LXMF/LXMessage.py:471-490`) calls `self.__as_packet()` which constructs:

```python
RNS.Packet(self.__delivery_destination, self.packed)            # full LXMF body, dest_hash included
```

i.e. the destination is the **Link object**, and the data is the full `dest_hash || src_hash || signature || msgpack_payload` (SPEC.md §5.2 — Link delivery does NOT strip dest_hash from the body, in contrast to opportunistic delivery).

When `RNS.Packet.pack()` runs for this packet (`RNS/Packet.py:177+`), the destination type is `LINK`, so:

- The header is `flags(1) || hops(1) || link_id(16) || context=0x00(1)`. The `link_id` occupies the dest_hash position.
- `destination.encrypt(plaintext)` for a Link calls into the link's session-key Token form (`RNS/Cryptography/Token.py`). Per SPEC.md §3.1 the Link-derived Token form omits the `ephemeral_pub` prefix because both sides already share the session key from the handshake — the wire body is `iv(16) || aes_ciphertext || hmac(32)`.

`Packet.send()` returns a `PacketReceipt`; LXMF binds:

```python
receipt.set_delivery_callback(self.__mark_delivered)
receipt.set_timeout_callback(self.__link_packet_timed_out)
```

so the LXMessage advances `SENT → DELIVERED` when the recipient's PROOF for this DATA packet arrives (SPEC.md §6.5 — every CTX_NONE DATA packet on a link gets a mandatory PROOF receipt).

### 6. Wire bytes leave (KISS / HDLC framing)

Same as `send-opportunistic-lxmf.md` step 9 — the framed link DATA packet leaves the interface. Note that, in contrast to opportunistic DATA, **`Transport.outbound` does NOT apply the HEADER_1→HEADER_2 conversion for link-addressed packets**, regardless of how many transport hops the link traverses. The HEADER_1→HEADER_2 path is keyed on a `path_table` lookup against `dest_hash`; a link-addressed packet's `dest_hash` is the `link_id`, which lives in `link_table`, not `path_table`. Relays then forward it via `link_table` forwarding — which preserves the header bytes verbatim — so emitting HEADER_2 with `transport_id` set on a link-addressed packet would have it dropped at the destination's `packet_filter` as "for another transport instance" (SPEC.md §6.4.3). The next-hop interface for a link is cached on the link object (`link.attached_interface`) so all subsequent traffic uses that same interface without further path-table lookup.

### 7. PROOF receipt arrives → `__mark_delivered` fires

The recipient (per the receive flow — TODO `receive-link-lxmf.md`) decrypts the link DATA, parses the LXMF body via `LXMessage.unpack_from_bytes`, validates the signature, and emits a PROOF for this packet (`Packet.prove` from inside `LXMRouter.delivery_packet` at line 1820, same as the opportunistic receive). The PROOF travels back along the link, `PacketReceipt.proven` resolves on the sender, and `__mark_delivered` puts the LXMessage in `DELIVERED`.

### 8. (Optional) RESOURCE representation for large bodies

If the packed body exceeds `LINK_PACKET_MAX_CONTENT` (`LXMF/LXMessage.py:415-421`), `representation` is set to `RESOURCE` and step 5 instead constructs an `RNS.Resource` (`__as_resource`, line 651):

```python
RNS.Resource(self.packed, self.__delivery_destination, callback=..., progress_callback=..., auto_compress=...)
```

The `RNS.Resource` machinery handles fragmentation, ordering, retransmission, and progress reporting on top of the link's DATA channel. Each fragment is its own DATA packet on the link with its own PROOF receipt. The Resource fragmentation protocol — block sizes, sequence numbers, the resource-proof message — is **not in SPEC.md as of this writing** (see `../todo.md`); reading `RNS/Resource.py` is currently the only authoritative source.

When the resource concludes successfully, the same `__mark_delivered` path runs as for PACKET.

### 9. Backchannel identification (optional, after first successful DIRECT delivery)

`LXMF/LXMRouter.py:2700-2714`. After a DIRECT delivery completes (`lxmessage.state == DELIVERED`), if the link doesn't yet have a backchannel identity associated, the initiator's `LXMRouter` calls `direct_link.identify(backchannel_identity)`:

- `direct_link.identify` sends an IDENTIFY packet on the link bound to one of the **sender's** local `lxmf.delivery` destinations.
- The receiving side's `delivery_link_established` callback (set at `LXMRouter.py:1956-1963` → `def delivery_link_established(self, link)`) installs `delivery_packet` on the link's packet callback, so subsequent inbound DATA on this link reaches the LXMF parser.
- The link is now usable in **both directions** without each side having to open its own Link to the other. The receiver can now reply over this same link.

This enables an interactive conversation over a single link rather than each message opening a new link.

### 10. Link teardown

A link stays in `ACTIVE` until either side calls `link.teardown()`, the watchdog times out (no inbound activity within `Link.STALE_GRACE` after the keepalive interval), or the next-hop interface goes down. `RNS/Link.py` keepalives are `CTX_KEEPALIVE` (0xfd) packets; the cadence is `Link.KEEPALIVE` seconds.

Teardown sends `RNS.Packet(link, b"", context=Link.PROOF, ...)` informing the peer; once teardown completes, the link is removed from `Transport.active_links` and from `LXMRouter.direct_links`, and the next DIRECT message to the same destination has to repeat the full handshake from step 3.

---

## Wire-byte summary

The handshake in three packets:

```
LINKREQUEST (initiator → responder), unencrypted body:
[ 1B flags ][ 1B hops ][ 16B responder_dest_hash ][ 1B context=0x00 ]
[ 32B initiator_X25519_pub ][ 32B initiator_Ed25519_pub ][ optional 3B signalling ]

LRPROOF (responder → initiator), unencrypted body:
[ 1B flags ][ 1B hops ][ 16B link_id ][ 1B context=0xff ]
[ 64B Ed25519_signature ][ 32B responder_X25519_pub ][ optional 3B signalling ]

DATA on link (either direction), Token-encrypted (no eph_pub prefix):
[ 1B flags ][ 1B hops ][ 16B link_id ][ 1B context=0x00 ]
[ 16B iv ][ N×16B aes_ciphertext ][ 32B hmac_sha256 ]
   (plaintext = full LXMF body: dest_hash || src_hash || signature || msgpack_payload)
```

Per SPEC.md §6.5 the receiver of any CTX_NONE DATA packet on the link MUST emit a PROOF receipt back; this is the mandatory `Packet.prove_packet` step on the receiving side, and is what resolves the sender's `PacketReceipt`.

---

## Source map for this flow

| Step | File | Function / line |
|---|---|---|
| 1 | `LXMF/LXMessage.py` | `pack`, line 352 |
| 2 | `LXMF/LXMRouter.py` | `process_outbound` DIRECT branch, line 2599 |
| 3 | `RNS/Link.py` | `Link.__init__` initiator branch, line 308 |
| 3 | `RNS/Packet.py` | `pack` LINKREQUEST not-encrypted, line 192 |
| 3 | `RNS/Link.py` | `set_link_id` / `link_id_from_lr_packet`, line 340 |
| 3 | `RNS/Packet.py` | `get_hashable_part`, line 354 |
| 4 | `RNS/Link.py` | `validate_proof`, line 396 |
| 4 | `RNS/Link.py` | `handshake`, line 353 |
| 5 | `LXMF/LXMessage.py` | `send` DIRECT branch, line 471 |
| 5 | `LXMF/LXMessage.py` | `__as_packet` DIRECT, line 632 |
| 5 | `RNS/Packet.py` | Link-destination encrypt path |
| 5 | `RNS/Cryptography/Token.py` | Token encrypt (no eph_pub prefix for Link) |
| 6 | `RNS/Transport.py` | `outbound`, line 1031 |
| 7 | `RNS/Packet.py` | `prove` |
| 8 | `RNS/Resource.py` | RESOURCE machinery (not yet in SPEC.md) |
| 9 | `LXMF/LXMRouter.py` | backchannel identify, line 2532 |
| 10 | `RNS/Link.py` | watchdog / teardown |
