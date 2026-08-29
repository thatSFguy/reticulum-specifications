# Flow: receive a propagated LXMF message (recipient pulls via `/get`)

The closing half of [`send-propagated-lxmf.md`](send-propagated-lxmf.md): how a recipient client retrieves messages that were store-and-forwarded for it by a propagation node. Pinned against **RNS 1.5.2 / LXMF 1.1.1**; cross-references [`../SPEC.md`](../SPEC.md) §5.8 (propagation protocol), §11 (REQUEST/RESPONSE).

This is the inverse-side flow that turns "the message was queued at a propagation node" (`send-propagated-lxmf.md` step 9) into "the message arrives in the recipient's inbox".

---

## Preconditions

- Recipient has discovered at least one propagation node via its `lxmf.propagation` announce. The recipient's `LXMRouter.outbound_propagation_node` records which one to use.
- Recipient has a path to the propagation node in `Transport.path_table`.

---

## Sequence

### 1. Recipient initiates retrieval

`LXMRouter.request_messages_from_propagation_node(identity, max_messages)` (`LXMF/LXMRouter.py:502+`). Triggered by:

- Manual user action (Sideband "Refresh inbox" button).
- Periodic background poll (every few minutes by default in long-running clients).
- An incoming `lxmf.propagation` announce from the configured PN, signalling availability.

### 2. Open a Link to the propagation node

If `Transport.has_path(propagation_node_dest)` is False, request_path first and defer (same pattern as opportunistic LXMF send). Otherwise:

```python
self.outbound_propagation_link = RNS.Link(
    propagation_node_destination,
    established_callback=msg_request_established_callback,
)
```

(`LXMF/LXMRouter.py:532`). Standard Link establishment per `flows/send-link-lxmf.md` steps 3-4.

### 3. Identify on the link

Once the link is `ACTIVE`, the recipient calls `link.identify(my_lxmf_delivery_identity)` so the propagation node knows whose mail to deliver. Without this, the `/get` request handler returns `LXMPeer.ERROR_NO_IDENTITY` (per §5.8.3).

### 4. Listing query — `/get` with `[None, None]`

```python
data = [None, None]                                              # [wanted, have]
link.request("/get", data, response_callback=on_message_list)
```

The propagation node's `message_get_request` handler at `LXMF/LXMRouter.py:1482-1504` → `def message_get_request(self,` walks `propagation_entries` for messages keyed to the requester's destination_hash and returns:

```python
[ [transient_id_1(16), size_1(int)],
  [transient_id_2(16), size_2(int)],
  ... ]                                                          # sorted by size ascending
```

For `[None, None]`, the response after the propagation node strips its internal `(transient_id, size)` tuples to just transient_ids:

```python
return [transient_id_1, transient_id_2, ...]
```

### 5. Recipient picks which messages to fetch

Application logic decides. Common heuristic: fetch all transient_ids the recipient doesn't already have stored locally, prioritising smaller messages first. Build:

```python
data = [wanted_ids, have_ids, transfer_limit_kb]
link.request("/get", data, response_callback=on_message_batch)
```

- `wanted_ids` — list of 16-byte transient_ids to deliver.
- `have_ids` — list of 16-byte transient_ids the recipient already has stored locally; the propagation node deletes these from its store as a side effect (§5.8.3 "ack and purge").
- `transfer_limit_kb` — optional cap on total bytes the recipient is willing to receive in one batch.

### 6. Propagation node returns a flat list of message bodies

`message_get_request` builds `response_messages = []` (`LXMF/LXMRouter.py:1523` → `response_messages =`), appends one LXMF body per served message, and returns **that list directly** (`:1555-1556` → `self.client_propagation_messages_served +=`):

```python
response_messages.append(lxmf_data[:-LXStamper.STAMP_SIZE])   # :1549
...
return response_messages                                      # :1556
```

Two things to get right here, both of which fail silently:

- **There is no `[timestamp, [bodies]]` envelope.** That shape belongs to the *upload* direction only (`flows/send-propagated-lxmf.md` step 2). The retrieval response is a bare list.
- **The propagation stamp is stripped before serving** (`:1549` → `response_messages.append(lxmf_data[:-LXStamper.STAMP_SIZE])`). Each served body is the pre-stamp propagated form, `dest_hash(16) || ciphertext` — do not slice `STAMP_SIZE` off it again.

Returned as a §11 RESPONSE. If the bundle fits in `link.mdu` it's a single Link DATA packet; otherwise it's a Resource (per `flows/send-resource.md`). Either way the Link layer strips the `[request_id, response]` framing before the callback fires.

### 7. Recipient processes each body and rehashes it for the purge round

The recipient's `message_get_response` callback (`LXMF/LXMRouter.py:1607-1644` → `def message_get_response(self,`) iterates the response as bodies, with nothing to unwrap:

```python
# LXMF/LXMRouter.py:1624-1627
for lxmf_data in request_receipt.response:
    result = self.lxmf_propagation(lxmf_data, signal_duplicate=LXMRouter.DUPLICATE_SIGNAL)
    haves.append(RNS.Identity.full_hash(lxmf_data))
```

`haves` is the `have_ids` list for step 8. It works because the node keyed its store on `transient_id = RNS.Identity.full_hash(lxmf_data)` computed **before** the stamp was appended (`LXMF/LXMRouter.py::lxmf_propagation` → `transient_id =`, then `:2512` → `stamped_data = lxmf_data+stamp_data`), and step 6 stripped exactly those bytes back off — so `full_hash(body_as_received)` reproduces the node's own store key.

`lxmf_propagation` routes the body into `lxmf_delivery`, the same path used for opportunistic and direct receive (`flows/receive-opportunistic-lxmf.md` step 11+) — it calls `LXMessage.unpack_from_bytes`, validates the signature against the sender's known identity, runs ticket / stamp / dedup checks, and fires the application's delivery callback. **The LXMF body bytes are identical regardless of how they arrived** — opportunistic, direct over a Link, or propagated. The propagation node never touched the encrypted body.

### 8. (Optional) Acknowledge and purge

In the next `/get` request, the recipient passes the just-fetched transient_ids in the `have_ids` slot per step 5. The propagation node deletes those entries on receipt. This caps the propagation node's storage growth — without it, every message would accumulate forever until the operator manually purged.

A clean-room recipient that doesn't implement the purge handshake works correctly (gets messages delivered) but contributes to long-term storage growth on shared propagation nodes. Implement the purge as a courtesy.

### 9. Link teardown or reuse

After the bundle is processed, the recipient either tears down the link (`link.teardown()` per §6.7) or keeps it for another `/get` round if more messages are expected. Most clients tear down after each successful batch — the propagation node's `lxmf.propagation` destination is `ALLOW_ALL` for `/offer` and `/get` so reopening a fresh link has no auth cost.

---

## Source map

| Step | File | Function / line |
|---|---|---|
| 1 | `LXMF/LXMRouter.py` | `request_messages_from_propagation_node`, line 502 |
| 2 | `LXMF/LXMRouter.py` | outbound link establishment, line 522-532 |
| 3 | `RNS/Link.py` | `Link.identify`, line 454 |
| 4-6 | `LXMF/LXMRouter.py` | `message_get_request` handler, line 1482-1561 |
| 7 | `LXMF/LXMRouter.py` | `message_get_response`, line 1607-1644 |
| 7 | `LXMF/LXMRouter.py` | `lxmf_propagation`, line 2487-2540 (`transient_id` at `LXMF/LXMRouter.py::lxmf_propagation` → `transient_id =`, stamp appended at `:2512` → `stamped_data = lxmf_data+stamp_data`) |
| 7 | `LXMF/LXMRouter.py` | `lxmf_delivery`, line 1837 |
| 8 | `LXMF/LXMRouter.py` | purge via `/get` `have_ids` slot, line 1508-1519 |
| 9 | `RNS/Link.py` | `teardown`, line 662 |
