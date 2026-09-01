# Proposal: register `rrc` as a NomadNet link-target aspect shorthand

**Status:** **WITHDRAWN — the shorthand already existed.**
**Author:** [thatSFguy](https://github.com/thatSFguy)
**Date:** 2026-08-29 · **Withdrawn:** 2026-09-01

---

## Why this was withdrawn

This proposal asked that `rrc` be registered as a link-target aspect
shorthand alongside `nnn` and `lxmf`, expanding to `rrc.hub`, with a
`:/room/<percent-encoded>` path convention. It argued that without a
registered shorthand, implementations *"will each invent a different
something — some a `rrc://` URI, some a bare hash"* and links would not
survive being pasted between clients.

That was already the situation, in the direction the proposal did not
check. NomadNet 1.2.8 — released **2026-07-24**, five weeks before this
was written — ships a full RRC client and had already claimed both
spellings, with a **different payload grammar**:

- `rrc://<32hex>[:<dest_name>]/<room>` — `Browser.py:277-280`
- `rrc@…`, via `expand_shorthands` mapping `rrc` to `rrc.hub.session`
  and `handle_link` dispatching that to the same parser —
  `Browser.py:206-214`, `:312-314`
- the parser itself — `Browser.py:426-461`

So there was nothing to register: the shorthand existed, and this
proposal's `:/room/` path convention was the parallel invention it set
out to prevent. The two do not fail cleanly against each other — a
`:/room/ops` link resolves the right hub and yields a room named
`room/ops`, which a hub creates without complaint.

`SPEC §11.6.3` now documents what NomadNet actually parses, which is
what this proposal should have been from the start: a description, not a
request.

## What is worth keeping from it

Two arguments survive and are folded into §11.6.3:

- **Strictness.** §11.6.3's existing warning about forgiving hash
  parsing — reject embedded separators, require exactly 32 hex
  characters, lower-case before use — applies to this shorthand as it
  does to the others, and is stricter than upstream's own
  `bytes.fromhex` length check. Being stricter than the grammar costs no
  interop.
- **A shorthand table is a registry, not a closed enumeration.** That
  framing was right; it just did not need a new row, because the row was
  already there. The table in §11.6.3 has been corrected to quote the
  pinned function verbatim rather than a two-branch condensation of it,
  so the next reader sees every shorthand upstream defines.

## The lesson, for the next proposal

The failure here was not "did not check upstream" — this proposal cites
`SPEC §11.6.3` and quotes `expand_shorthands`. It was checking
upstream's convention for a *neighbouring* problem (page links) and
generalising it, without checking whether upstream already had an answer
for *this* problem. It did, in a module the same package ships.

Before proposing a convention for a protocol some upstream client
already speaks, grep that client for the protocol's name first.
