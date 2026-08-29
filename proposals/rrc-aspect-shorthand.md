# Proposal: register `rrc` as a NomadNet link-target aspect shorthand

**Status:** Draft for discussion
**Author:** [@thatSFguy](https://github.com/thatSFguy)
**Date:** 2026-08-29

> This proposes **no wire change**. It asks that one shorthand string be
> written down, so that a convention several implementations would
> otherwise each invent differently is instead invented once.

---

## 1. Summary

`SPEC §11.6.3` documents the link-target syntax NomadNet's browser
parses, and the `expand_shorthands` table that gives it two aliases:

```python
def expand_shorthands(self, destination_type):
    if destination_type == "nnn":   return "nomadnetwork.node"
    elif destination_type == "lxmf": return "lxmf.delivery"
    else: return destination_type
```

The grammar around it — `[aspect@]<32hex>[:/path]` — is not specific to
pages. It is a general way to write down *a destination and something on
it*, it is the only such convention this ecosystem has, and it is
already readable by every NomadNet user.

**This proposal registers one more shorthand:**

| Shorthand | Expands to | Names |
|---|---|---|
| `nnn` | `nomadnetwork.node` | a page-serving node *(exists)* |
| `lxmf` | `lxmf.delivery` | a conversation *(exists)* |
| **`rrc`** | **`rrc.hub`** | **a room on an RRC hub** *(this)* |

```
rrc@43c8adb1172377a76b8f9ba41bb85e5c:/room/lobby
```

`rrc.hub` is the aspect an RRC (Reticulum Relay Chat) hub registers.

---

## 2. Why this is worth writing down

RRC has no way to express "this room, on this hub". Room names are not
unique across hubs and nothing spoken aloud carries which hub was meant,
so an RRC room is not shareable at all today.

The gap is worst where it hurts most. An RRC hub that notifies an absent
member over LXMF produces a message that lands in the recipient's
ordinary messaging app, tells them they were named in `#ops`, and offers
no way to get there.

Any implementation solving that will invent something. Without a
registered shorthand they will each invent a *different* something —
some a `rrc://` URI, some a bare hash, some a JSON blob — and links will
not survive being pasted between clients, which is the only thing a link
is for. One line in `expand_shorthands` prevents that.

---

## 3. Path convention

Namespaced, as `/page/` and `/file/` are, so later targets can be added
without ambiguity:

```
/room/<segment>       a room; segment is the room name
```

RRC room names are arbitrary UTF-8, and a link is a whitespace-delimited
token pasted out of a message body, so `<segment>` is percent-encoded
over UTF-8 bytes escaping everything outside the RFC 3986 unreserved set
— stricter than a typical path encoder, which would leave `:` and `@`
alone. Both are structural in this grammar.

A link with no path names a hub and no particular room.

---

## 4. What implementations should do

Nothing is required of anyone. A client that does not implement this
renders the token as text, and a person can copy it — which is the
property that makes a text convention the right shape here, rather than
a new message type.

A client that does implement it should, on activation: connect to
`rrc.hub` at the given destination hash and `JOIN` the named room.

**Strictness follows §11.6.3's existing warning**, which applies to this
shorthand exactly as to the others: reject embedded separators, require
exactly 32 hex characters, lower-case before use. Forgiving hash parsing
creates aliases for one destination and risks cache poisoning.

---

## 5. Prior art in this document set

`SPEC §11.6.3` is marked informational rather than normative, since
NomadNet is not an admissible source for a normative claim per
[`agent.md`](../agent.md) §0. This proposal does not change that: it
asks that the shorthand table be treated as a **registry** — a list
anyone may add to, with the same informational standing the rest of
§11.6 has — rather than as a closed enumeration of what NomadNet
happens to implement.

If that framing is accepted, the concrete change is one row in the
§11.6.3 table and one line of prose noting that the list is open.

---

## 6. Reference implementation

`thatSFguy/reticulum-relay-chat`:

- `internal/hub/rrclink.go` — parser and renderer
- `internal/hub/rrclink_test.go` — conformance cases: every accepted
  form, the strictness rules, and round trips over room names
  containing spaces, `:`, `@`, `/`, `%` and non-Latin scripts
- `docs/rrc-room-links.md` — the client-facing convention

Emitted in offline mention notifications, and by a `/link [room]`
command.
