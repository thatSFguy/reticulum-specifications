# Proposal: LXMF-native group messaging

**Status:** Draft for upstream discussion (markqvist/LXMF)
**Author:** [@thatSFguy](https://github.com/thatSFguy)
**Date:** 2026-07-26

> All wire shapes in this document are **strawman sketches** intended to
> start a discussion, not a finished specification. Field numbers,
> encodings, and derivations are open to change entirely. The goal here
> is agreement on the *architecture*; the bytes come after.

---

## 1. Summary

A design for multi-party messaging in LXMF that requires **no new
cryptographic primitives and no changes to Reticulum's transport
layer**. It consists of:

1. **Sender keys** — each member encrypts a group message *once* under
   a per-sender hash-ratcheted chain key, distributed to members over
   the existing pairwise E2E LXMF channel.
2. **A signed membership object** — group state is an admin-signed data
   structure gossiped between members; no registration, no directory,
   no coordination service.
3. **Delivery in two phases:**
   - **Phase 1 (LXMF only):** the sender fans out N−1 copies of the
     identical ciphertext using the existing delivery methods. Works
     today with zero infrastructure changes.
   - **Phase 2 (propagation extension):** a versioned extension to the
     propagation-node protocol allowing one uploaded ciphertext blob to
     carry a list of recipient delivery entries. Sender cost drops to
     O(1); fan-out is absorbed by infrastructure that already exists
     and already handles opaque encrypted mail.

The design deliberately follows the architecture Signal chose for its
groups: encrypt once with sender keys, distribute keys pairwise, and
let an **untrusted** store-and-forward box duplicate ciphertext it
cannot read. Reticulum already has that box — the propagation node.

## 2. Motivation

LXMF today is strictly one-to-one. Every fielded "group chat" on
Reticulum is an application-layer workaround, and the common shape is a
**trusted fan-out service**: a hub that receives a message, decrypts
it, and re-encrypts N−1 copies to the members. This has three problems:

- **Trust.** The hub reads every message and holds the full membership
  and social graph. This is at odds with the rest of the stack, where
  no infrastructure node can read or correlate user traffic.
- **Fragility.** The hub is a mandatory, singular service. If it goes
  away, the group goes away.
- **Fragmentation.** Each application invents its own incompatible
  scheme. `FIELD_GROUP` (`0x0B`) has been allocated in `LXMF/LXMF.py`
  for a long time, but with no pinned value shape, nothing interops.

A native design would remove the trusted middlebox, give applications
one shared convention to implement, and keep the security posture
consistent with the rest of Reticulum.

## 3. Design goals and non-goals

**Goals**

- No new cryptographic primitives — reuse the existing Token
  (AES-256-CBC + HMAC-SHA256), the existing identity/signature scheme,
  and the existing pairwise ratcheted LXMF channel for key transport.
- No changes to RNS. Phase 1 requires no changes outside client
  applications and a pinned `FIELD_GROUP` shape; Phase 2 is a
  backward-compatible, versioned extension to the LXMF propagation
  protocol only.
- Untrusted infrastructure. Propagation nodes must not be able to read
  group content. (What they *can* observe is analyzed honestly in §9.)
- Permissionless. Creating a group is generating keys — nothing is
  registered anywhere.
- Graceful degradation. Group delivery slots into the existing
  opportunistic → direct → propagated ladder; when no Phase-2-capable
  propagation node is reachable, Phase 1 client fan-out is the
  fallback.

**Non-goals**

- **Network-layer multicast.** No routed GROUP destinations, no
  distribution trees in Transport. Group messaging does not require
  multicast (no mainstream group messenger uses it); it only requires
  fan-out, and fan-out belongs at the application/propagation layer.
- **Hiding group membership from members.** Members know who is in the
  group; the membership object says so. (Signal's zero-knowledge group
  credentials exist to hide membership from Signal's *server*; the
  analogous concern here — what propagation nodes observe — is
  addressed differently, see §9.)
- **Very large groups.** The design targets the tens-of-members scale.
  Aggregate delivery cost is inherently O(N) (§10).

## 4. Overview

A group message exists exactly once as a **canonical group message** —
an LXMF message addressed to the *group* rather than to any individual
member, encrypted under the sender's current chain key. That one
artifact (and therefore one canonical `message_id`) is what gets
delivered to every member, by whichever delivery path. Reactions,
replies, and threading reference the canonical `message_id` and
compose with the existing `FIELD_REACTION` / `FIELD_REPLY_TO`
machinery unchanged.

The pieces:

```
┌─────────────────────────────────────────────────────────────┐
│ group layer (new, LXMF)                                     │
│   sender keys: encrypt once per message, ratchet forward    │
│   membership object: admin-signed, gossiped                 │
│   key distribution: over existing pairwise E2E LXMF         │
├─────────────────────────────────────────────────────────────┤
│ delivery (existing, extended in Phase 2)                    │
│   Phase 1: N−1 pairwise sends of identical ciphertext       │
│   Phase 2: 1 upload → multi-recipient propagation entries   │
├─────────────────────────────────────────────────────────────┤
│ Reticulum (unchanged)                                       │
└─────────────────────────────────────────────────────────────┘
```

## 5. The group layer

### 5.1 Group identity

A group is identified by a 16-byte `group_id`, generated at random by
the creator. It occupies the same identifier space as destination
hashes and is used as the `destination_hash` of canonical group
messages. It is **not announced** and is **not routable** — it is an
addressing label at the LXMF layer, never a Reticulum destination
anyone sends packets to. (Whether to derive it from a name-hash recipe
instead of pure randomness is an open question, §11.)

### 5.2 Sender keys

Per (member, group, epoch), the member generates a random 32-byte
`chain_key_0` and distributes it to every other member over the
existing pairwise LXMF channel (which already provides per-message
ephemeral ECDH and ratchet rotation — it is the Double-Ratchet-analog
transport for this exchange, and the reason no new key-agreement
mechanism is needed).

Per message `i`, strawman derivations:

```
message_key_i = HKDF(chain_key_i, info="lxmf.group.msg", L=64)
chain_key_i+1 = HKDF(chain_key_i, info="lxmf.group.chain", L=32)
```

`message_key_i` is a 64-byte Token key (32B HMAC-SHA256 signing key ||
32B AES-256-CBC key — the same split the Token class already uses).
The chain key is deleted as the chain advances, giving forward secrecy
*within an epoch*: compromise of a device at chain position `i` does
not reveal messages `< i`.

Unlike Signal's sender keys, **no per-group signing key is needed**:
every LXMF message is already signed by the sender's long-term Ed25519
identity, and members verify attribution through the normal LXMF
signature. This removes an entire key type from Signal's design.

Because mesh delivery is lossy and unordered, receivers cache derived
`message_key`s for skipped chain indices, bounded (strawman: keep at
most 256 skipped keys per sender chain, oldest evicted).

### 5.3 The canonical group message

Strawman wire shape of the stored/transported blob:

```
group_lxmf_data =
    group_id(16)                          # in the destination_hash slot
 || group_header                          # small plaintext: epoch,
                                          #   sender_key_id, chain_index
 || Token_encrypt(message_key_i,
        source_hash(16) || signature(64) || packed_payload)
```

- The plaintext `group_header` carries only what a member needs to
  select the right chain and derive `message_key_i`. Its exact
  encoding (msgpack vs fixed-width) is open.
- `signature` is the normal LXMF Ed25519 signature by the sender's
  identity over the hashed part (destination = `group_id`), verified
  by members after decryption. Sender identity is *inside* the
  ciphertext — observers and propagation nodes do not learn who in
  the group authored a given message.
- The canonical `message_id` is computed from this blob once, so every
  member agrees on it; `FIELD_REACTION` (`0x40`) and `FIELD_REPLY_TO`
  (`0x30`) then work across the group with no changes.

### 5.4 `FIELD_GROUP` (`0x0B`) value shape

The already-allocated field gets a pinned shape. Strawman: a
msgpack map with integer keys, where the variant present determines
the meaning:

| Key | Name | Value |
|---|---|---|
| `0x00` | `GROUP_ID` | 16 bytes |
| `0x01` | `GROUP_EPOCH` | int |
| `0x02` | `GROUP_MESSAGE` | canonical group message blob (when carried inside a pairwise wrapper, Phase 1) |
| `0x03` | `GROUP_SENDER_KEY` | 32-byte chain key (key-distribution message, pairwise only) |
| `0x04` | `GROUP_MEMBERSHIP` | signed membership object (§6) |

Variants `0x03`/`0x04` only ever appear in pairwise (SINGLE-to-SINGLE)
messages and inherit that channel's full security properties.

## 6. Membership

Group state is a msgpack structure signed by an admin identity:

```
membership = {
    group_id:  16 bytes,
    epoch:     int,          # increments on every membership change
    name:      str,          # optional display name
    members:   [dest_hash_1, ...],
    admins:    [dest_hash_1, ...],
    timestamp: int,
}
signed_membership = membership_bytes || admin_signature(64)
```

- Distributed to members pairwise (`FIELD_GROUP` variant `0x04`) on
  join and on every change. Members accept a membership object iff it
  is signed by an admin of the epoch they currently hold and its epoch
  is greater.
- **Adding** a member: new epoch, new member receives the membership
  object and every member's current-epoch sender key.
- **Removing** a member: new epoch, and **every remaining member
  generates a fresh chain key** and redistributes it pairwise. The
  removed member cannot read epoch e+1. This is the same
  re-key-on-leave semantic as Signal, with the same cost: one
  membership change triggers O(N²) small pairwise messages across the
  group. At the tens-of-members scale this is acceptable; it is the
  main reason very large groups are a non-goal.
- Admin model is deliberately minimal (creator is first admin, admins
  can add admins). Richer authorization is an application concern.

## 7. Phase 1 — delivery over existing LXMF (no infrastructure changes)

The sender encrypts once, then delivers the identical canonical blob to
each member as a normal pairwise LXMF message carrying `FIELD_GROUP`
variant `0x02`, using whatever method the existing outbound ladder
selects per member (opportunistic, direct link, or propagated to that
member's usual propagation node).

Properties:

- Interoperable group chat across any two applications that implement
  the convention — today, with zero changes to LXMRouter or
  propagation nodes.
- Sender cost is O(N) transmissions. Encryption cost is O(1); the
  ciphertext is byte-identical per copy, only the outer pairwise
  envelope differs.
- Fully E2E: the outer envelope adds a second layer (pairwise ECDH)
  on top of the sender-key layer.

Phase 1 is proposed as the *mandatory baseline* — it is also the
permanent fallback whenever no Phase-2-capable propagation node is
reachable, preserving the works-with-nothing property.

## 8. Phase 2 — multi-recipient propagation (versioned extension)

Today a propagation entry is structurally keyed to exactly one
recipient: delivery is filtered on
`propagation_entries[tid][0] == requester_destination_hash`
(`LXMRouter.py:1440, 1455`), and the recipient is implied by the
blob's leading `destination_hash`. The extension relaxes exactly this.

### 8.1 Submission

A sender submits the canonical group blob **once** to a propagation
node, accompanied by a recipient list drawn from the membership object
at send time:

```
group_submission = [group_lxmf_data, [recipient_hash_1, ..., recipient_hash_N]]
```

The node stores one blob under its `transient_id`
(`SHA256(group_lxmf_data)[:16]`, unchanged) and creates N delivery
entries pointing at it.

### 8.2 Retrieval

`/get` semantics are unchanged from the client's perspective: the
listing query returns transient_ids the requester is entitled to,
which now includes group blobs whose recipient list contains the
requester's destination hash. `have_ids` acknowledgment marks that
recipient's entry delivered; the blob is purged when all entries are
delivered or on the node's normal retention expiry.

### 8.3 Peer sync

`/offer` transient_id exchange is unchanged; the Resource transfer
that follows carries the recipient-entry list alongside each group
blob so a peer node can serve the same recipients. (Exact framing
open — strawman: the msgpack transfer array gains a parallel
per-message metadata element for group blobs only.)

### 8.4 Versioning and compatibility

- Capability is advertised in the propagation announce `app_data` —
  strawman: a key in the element-[6] metadata dict, so the 7-element
  shape and `pn_announce_data_is_valid` are untouched and legacy
  clients parse the announce exactly as before.
- Clients only send `group_submission` to nodes advertising the
  capability; otherwise they fall back to Phase 1 per member.
- Legacy nodes never see the new shapes. Phase-2 nodes peer-syncing
  with legacy nodes simply do not offer group blobs to them.
- Stamps and peering keys apply unchanged; a strawman option is one
  stamp per submission at cost proportional to the recipient count, so
  a group submission cannot be a spam amplifier against the node.

## 9. Security and privacy analysis

**What a propagation node cannot do.** Read content, forge messages,
or attribute a message to an individual sender within the group —
sender identity and signature are inside the sender-key ciphertext.
This matches the existing posture where nodes store mail they cannot
open.

**What a propagation node observes (honest accounting).** In Phase 2
the node sees a correlated recipient list: "these N destination hashes
share a group." Today an observer node can *infer* similar structure
from N same-sized uploads in one session; the extension makes it
structural, which is a real step and the most philosophically serious
cost in this proposal. Two mitigations are on the table:

1. **Blinded delivery entries.** Instead of plaintext recipient
   hashes, the sender submits per-recipient retrieval tokens (e.g.
   derived from the recipient hash and the blob id) such that the
   node can match a claimant to an entry without learning the
   recipient set outright. Sketch-level only; whether a derivation
   exists that is both cheap and actually resistant to a node that
   also observes `/get` link identities is an open question (§11) —
   a node must identify the requesting identity for delivery anyway,
   so the honest framing is that blinding raises the cost of *bulk
   passive* correlation, not that it defeats an active node.
2. **Spreading**: members retrieving from different propagation nodes
   fragments the picture any single node holds.

The proposal's position: name this tradeoff explicitly rather than
design around the impossible. Every group-messaging system leaks
grouping metadata to whatever performs fan-out; the design choice
available is *who* that party is (here: an untrusted, self-elected,
replaceable node rather than a trusted mandatory hub) and how much it
sees (ciphertext + recipient set, not content + social graph +
plaintext).

**Forward secrecy.** Within an epoch: hash-chain FS per sender
(compromise reveals nothing earlier in the chain, everything later
until rotation). Across epochs: rotation on every membership change,
plus optionally time-based. This is a weaker guarantee than the
pairwise channel's ratchets and identical to the tradeoff Signal
accepted for sender keys; a full MLS-style tree ratchet would
strengthen it at a cost in complexity that seems disproportionate at
the target group scale — explicitly flagged for discussion (§11).

**Authentication.** Message attribution rides the existing identity
signature. Membership authenticity rides admin signatures. A malicious
*member* can leak keys and content — true of every group system;
out of scope.

## 10. Cost analysis (being honest about the physics)

Phase 2 changes *where* cost lands, not the total:

| | sender airtime | infra cost | aggregate network |
|---|---|---|---|
| trusted hub (status quo) | O(1) | O(N), trusted | O(N) |
| Phase 1 client fan-out | **O(N)** | none | O(N) |
| Phase 2 propagation | **O(1)** | O(N), untrusted | O(N) |

Aggregate delivery is O(N) in every scheme because each member must
receive one copy; only true last-hop broadcast could change that, and
that is deliberately out of scope. The proposal should therefore be
evaluated as a **trust and sender-cost** improvement — the sender-side
O(1) matters enormously for duty-cycle-limited LoRa leaf nodes — and
not oversold as a bandwidth optimization.

## 11. Open questions

1. `group_id` derivation: pure random 16 bytes, or a name-hash recipe
   for consistency with destination hashing?
2. Exact `group_header` encoding and the canonical `message_id`
   computation for the group blob.
3. Skipped-message-key cache bound and eviction policy.
4. Blinded delivery entries: is there a derivation that meaningfully
   raises correlation cost given that `/get` links are identified?
5. Stamp policy for multi-recipient submissions (per-submission cost
   scaling with N, or per-recipient?).
6. Epoch rotation cadence beyond membership changes (time-based?).
7. Is sender-key FS-within-epoch sufficient, or is there appetite for
   an MLS-like tree at the cost of substantial complexity?
8. Whether `FIELD_GROUP` variants for key distribution and membership
   should instead be distinct top-level fields.

## 12. Why this fits Reticulum

- **Removes** a trusted middlebox from the ecosystem's de-facto
  practice and replaces it with untrusted, optional, already-deployed
  infrastructure.
- Adds **zero** cryptographic primitives and **zero** RNS changes;
  Phase 1 is purely an application convention around one
  already-allocated field, Phase 2 is one versioned extension to one
  protocol, invisible to legacy nodes.
- Permissionless, identity-is-keys, works with no infrastructure at
  all, degrades gracefully — the same properties the rest of the
  stack is built on.
- The precedent is good: reactions and reply-threading followed
  exactly this path — app-layer convention first, upstream field
  blessing after (`FIELD_REACTION`, `FIELD_REPLY_TO`).
