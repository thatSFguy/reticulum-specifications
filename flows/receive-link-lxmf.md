# Flow: receive an LXMF message over a Reticulum Link

The inverse of [`send-link-lxmf.md`](send-link-lxmf.md), covering both halves of the responder side: accepting the inbound LINKREQUEST, sending the LRPROOF, then handling LXMF DATA on the established link. Pinned against **RNS 1.5.2 / LXMF 1.1.1**; cross-references [`../SPEC.md`](../SPEC.md) §6 (Link), §6.5 (PROOF), §6.6 (signalling), §6.7 (KEEPALIVE/teardown), §10 (Resource).

---

## Sequence

### 1. LINKREQUEST arrives

A Reticulum DATA packet with `packet_type = LINKREQUEST (2)`, addressed to the responder's `lxmf.delivery` dest_hash. Body (§6.1):

```
initiator_X25519_pub(32) || initiator_Ed25519_pub(32) || [signalling(3)]
```

`Transport.inbound` (`RNS/Transport.py:2540` → `elif packet.packet_type == RNS.Packet.LINKREQUEST and not link_request_handled:`) recognizes `packet_type == LINKREQUEST + destination_type == SINGLE`, looks up the destination in `destinations_map`, and calls `Destination.receive(packet)` which routes to `Destination.incoming_link_request(data, packet)` per `RNS/Destination.py:414-435` → `def receive(self,` (`receive` at 414 → `if packet.packet_type == RNS.Packet.LINKREQUEST:`, dispatching to `incoming_link_request` at `:431` → `def incoming_link_request(self,`):

```python
def receive(self, packet):
    if packet.packet_type == LINKREQUEST:
        self.incoming_link_request(packet.data, packet)
```

### 2. Responder builds Link state via `Link.validate_request`

`RNS/Link.py:186-227` → `def validate_request(owner, data, packet)`. Length-checks the body (`ECPUBSIZE` or `ECPUBSIZE + LINK_MTU_SIZE`), rejects otherwise. On success:

1. Build a `Link` object with `peer_pub_bytes = data[:32]` and `peer_sig_pub_bytes = data[32:64]`.
2. `set_link_id(packet)` per §6.3 — the link_id derives from `Packet.get_hashable_part`, invariant under HEADER_1↔HEADER_2 conversion.
3. If signalling present, parse MTU and mode per §6.6.
4. Call `link.handshake()` — ECDH with the initiator's X25519 ephemeral pub, HKDF over the shared secret with `salt=link_id`, derives `signing_key || encrypt_key`. Status `PENDING → HANDSHAKE`.
5. Call `link.prove()` to emit the LRPROOF.
6. Register the link in `Transport.active_links` and append to the destination's `links` list.

### 3. Responder emits LRPROOF

`RNS/Link.py:366-375` → `def prove(self)`. Body per §6.2:

```
proof_data = signature(64) || responder_X25519_pub(32) || [signalling(3)]
```

where `signature = sign(link_id || responder_X25519_pub || responder_long_term_Ed25519_pub || [signalling])`. Wire packet: `packet_type = PROOF (3)`, `context = LRPROOF (0xFF)`, `dest_hash` field carries the link_id.

### 4. RTT measurement (LRRTT round trip)

After the initiator validates the LRPROOF and sends `Link.LRRTT (0xFE)` carrying its measured RTT, the responder receives it at `Link.receive` line 1056-1059 and calls `rtt_packet`. The responder's RTT cache updates and `Link.STATUS = ACTIVE` triggers the `link_established_callback` registered via `Destination.set_link_established_callback`.

For LXMF, that callback is `LXMRouter.delivery_link_established` (`LXMF/LXMRouter.py:1956-1963` → `def delivery_link_established(self, link)`):

```python
link.track_phy_stats(True)
link.set_packet_callback(self.delivery_packet)        # ← inbound LXMF flows here
link.set_resource_strategy(RNS.Link.ACCEPT_APP)
link.set_resource_callback(self.delivery_resource_advertised)
link.set_resource_started_callback(self.resource_transfer_began)
link.set_resource_concluded_callback(self.delivery_resource_concluded)
link.set_remote_identified_callback(self.delivery_remote_identified)
```

This is what makes inbound DATA on this link route into LXMF processing.

### 5. Inbound LXMF DATA — single-packet (PACKET representation)

A regular DATA packet on the link (`context = NONE`, Token-encrypted with link session key per §3.1). `Link.receive` decrypts and passes the plaintext to `delivery_packet(data, packet)` (`LXMF/LXMRouter.py:1926-1954` → `def delivery_packet(self, data, packet)`) — the same handler used by opportunistic delivery. Differences:

- `packet.destination_type == LINK` so `method = DIRECT`.
- The LXMF body arrives **with** the recipient's dest_hash (§5.2), so no re-prepend like the opportunistic path does at step 9 of `receive-opportunistic-lxmf.md`.

The handler calls `packet.prove()` immediately (mandatory PROOF receipt per §6.5), then dispatches the body to `LXMessage.unpack_from_bytes` and `lxmf_delivery` exactly like the opportunistic flow's steps 10-12.

### 6. Inbound LXMF DATA — Resource representation

A larger LXMF body arrives as a Resource transfer per `flows/receive-resource.md`. The Link's `resource_strategy = ACCEPT_APP` triggers `delivery_resource_advertised(resource)` (`LXMF/LXMRouter.py:1977-1984` → `def delivery_resource_advertised(self, resource)`):

```python
def delivery_resource_advertised(self, resource):
    size = resource.get_data_size()
    if self.delivery_per_transfer_limit and size > self.delivery_per_transfer_limit*1000:
        return False                                  # reject — over limit
    return True                                       # accept
```

If accepted, `Resource.accept` runs and the receiver state machine in `flows/receive-resource.md` takes over. On completion, `delivery_resource_concluded(resource)` fires, reads the assembled file, and feeds it through `lxmf_delivery` exactly like the single-packet path.

### 7. KEEPALIVE / teardown

Standard §6.7 protocol. The responder reflects every `0xFF` ping with a `0xFE` pong, emits its own KEEPALIVE-driven STALE→CLOSED transition if `last_inbound + 2*keepalive` elapses, and accepts inbound LINKCLOSE packets (validating that `decrypt(body) == link_id`).

### 8. Backchannel-identify (post-first-delivery)

After a successful inbound LXMF delivery, the LXMRouter on the **initiator** side may emit a `LINKIDENTIFY (context = 0xFB)` proof so the responder can record the initiator's long-term identity for backchannel use (`flows/send-link-lxmf.md` step 9). On the responder side, this triggers `delivery_remote_identified` which lets the responder send LXMF replies back over the same link without opening its own.

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | `RNS/Transport.py` | LINKREQUEST dispatch, line 2540 |
| 1 | `RNS/Destination.py` | `receive` LINKREQUEST branch, line 414-429 |
| 2 | `RNS/Link.py` | `validate_request`, line 186-227 |
| 2 | `RNS/Link.py` | `handshake`, line 348-363 |
| 3 | `RNS/Link.py` | `prove` (LRPROOF emission), line 366-375 |
| 4 | `RNS/Link.py` | `rtt_packet`, line 516-538 |
| 4 | `LXMF/LXMRouter.py` | `delivery_link_established`, line 1956-1963 |
| 5 | `LXMF/LXMRouter.py` | `delivery_packet`, line 1926-1954 |
| 6 | `LXMF/LXMRouter.py` | `delivery_resource_advertised`, line 1977-1984 |
| 7 | `RNS/Link.py` | KEEPALIVE handling, line 1130 |
| 8 | `LXMF/LXMRouter.py` | `delivery_remote_identified`, line 1995-1998 |
