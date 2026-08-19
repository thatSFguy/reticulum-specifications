# Flow: send a PROPAGATED LXMF message via a propagation node

What happens when an LXMF client submits a message to a propagation node for store-and-forward delivery — the path used when the recipient is offline, intermittent, or simply somewhere the sender can't reach directly. Pinned against **RNS 1.2.4 / LXMF 0.9.7**; cross-references [`../SPEC.md`](../SPEC.md) §5.8 (propagation protocol), §6 (Link), §10 (Resource), §11 (REQUEST/RESPONSE).

---

## Preconditions

- Sender has discovered at least one propagation node via its `lxmf.propagation` announce (§4.4 / §5.8.5). `LXMRouter.set_outbound_propagation_node(propagation_node_dest_hash)` records which one to use.
- Sender has a path to the propagation node in `Transport.path_table`.

---

## Sequence

### 1. App constructs an LXMessage with `desired_method = PROPAGATED`

Same as `send-opportunistic-lxmf.md` step 1 except the desired_method differs. The router's `handle_outbound` (`LXMF/LXMRouter.py:1746+`) will eventually route this to the propagation pipeline.

### 2. `LXMessage.pack()` — propagation-specific encryption

`LXMF/LXMessage.py:423-441`. Differences from the opportunistic and direct paths:

- The body is encrypted **to the recipient's public key** (Token form per §3.1 with eph_pub prefix), the same as opportunistic — the propagation node never decrypts.
- The encrypted bytes form `pn_encrypted_data`; the wire body delivered to the propagation node is `dest_hash || pn_encrypted_data` (the recipient's destination_hash is preserved so the propagation node can route to the right recipient on retrieval).
- `transient_id = SHA256(lxmf_data)` (full hash of the encrypted body) — the propagation node's storage key.
- The whole thing is then wrapped: `propagation_packed = msgpack.packb([time.time(), [lxmf_data]])`.

`representation` is set to `PACKET` if `propagation_packed` fits in `link.mdu`, else `RESOURCE`.

### 3. `LXMRouter.process_outbound` for PROPAGATED method

`LXMF/LXMRouter.py:2713+` (the `PROPAGATED` branch is structurally similar to the `DIRECT` branch in `send-link-lxmf.md`). High-level state:

- If a Link to the propagation node already exists and is `ACTIVE`: reuse it.
- Else if the path is known: open a fresh `RNS.Link(propagation_node_destination)` with `LXMRouter.process_outbound` registered as the `link_established_callback` so the LXM is sent as soon as the link establishes.
- Else: `Transport.request_path(propagation_node_dest_hash)` and defer for `LXMRouter.PATH_REQUEST_WAIT`.

### 4. Link establishes (per `send-link-lxmf.md` steps 3-4)

LINKREQUEST → LRPROOF → ACTIVE. The propagation node's `delivery_link_established` analogue for the propagation destination wires `LXMRouter.propagation_packet` as the link's packet callback.

### 5. (Optional) Stamp generation for propagation cost

If the propagation node's announce app_data declared a `stamp_cost` (element [5][0] per §5.8.5), the sender computes a propagation stamp via `LXMessage.get_propagation_stamp(target_cost)` (`LXMessage.py:326-350`). Algorithm same as §5.7 stamps but with `WORKBLOCK_EXPAND_ROUNDS_PN = 1000` rounds (cheaper than the regular `3000`-round stamp), and computed over the `transient_id` rather than `message_id`.

The stamp is appended to the wire body: `lxmf_data += propagation_stamp` (the propagation node validates the stamp before storing).

### 6. Submit via Link DATA (PACKET representation)

If `representation == PACKET`, the sender emits a Link DATA packet (`context = NONE`) carrying `propagation_packed`. The propagation node's `propagation_packet` callback (`LXMRouter.py:2234+`) decodes the msgpack outer, extracts the LXMF bodies, validates the propagation stamp if required, and stores each one in `propagation_entries[transient_id]`.

The Link DATA packet gets the standard mandatory PROOF receipt per §6.5; the receipt resolves the sender's `PacketReceipt` and `LXMessage.state` advances to `SENT`. **The state goes to `SENT`, not `DELIVERED`** — propagated messages are "delivered to the propagation node" but not yet "delivered to the recipient". The recipient pulls them later via `/get` (§5.8.3).

### 7. Submit via Resource (RESOURCE representation)

If `representation == RESOURCE`, the sender emits the `propagation_packed` blob as a Resource transfer per `flows/send-resource.md`. The propagation node accepts via `delivery_resource_advertised`, and on completion runs `propagation_resource_concluded` (`LXMRouter.py:2194+`) which decodes the `[time, [lxmf_data, ...]]` outer and stores each contained LXMF body.

### 8. The link can stay open or be torn down

After a successful propagation submission, the sender either tears down the link (`link.teardown()` per §6.7) or keeps it for another submission. The propagation node doesn't care — it has the messages and will offer them to peers via §5.8.2 sync independently.

### 9. Eventual delivery — recipient pulls via `/get`

When the recipient comes online (or just periodically), they open a Link to the propagation node, run `link.identify(my_identity)` so the propagation node knows whose mail to deliver, then issue a `/get` REQUEST per §5.8.3. The propagation node returns the stored LXMF bodies, and the recipient processes each through the same `lxmf_delivery` path that handles opportunistic / direct deliveries (`receive-opportunistic-lxmf.md` from step 10 onwards — the LXMF body bytes are identical regardless of how they arrived).

This step is the recipient's flow (`receive-propagated-lxmf.md` — TODO), not the sender's, but it's worth noting here so the full lifecycle is visible.

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | (app code) | `LXMessage(..., desired_method=PROPAGATED)` |
| 2 | `LXMF/LXMessage.py` | `pack` PROPAGATED branch, line 423-441 |
| 3 | `LXMF/LXMRouter.py` | `process_outbound` PROPAGATED branch, line 2547+ |
| 4 | (see `send-link-lxmf.md` steps 3-4) | |
| 5 | `LXMF/LXMessage.py` | `get_propagation_stamp`, line 326-350 |
| 5 | `LXMF/LXStamper.py` | `WORKBLOCK_EXPAND_ROUNDS_PN = 1000` |
| 6 | `LXMF/LXMRouter.py` | `propagation_packet`, line 2080+ |
| 7 | `LXMF/LXMRouter.py` | `propagation_resource_concluded`, line 2194 |
| 9 | `LXMF/LXMRouter.py` | `request_messages_from_propagation_node`, line 485 |
| 9 | `LXMF/LXMPeer.py` | client-side `/get` flow |
