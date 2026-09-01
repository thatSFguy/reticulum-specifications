# Verifier scripts

Self-contained Python scripts that test claims in [`../SPEC.md`](../SPEC.md) against the upstream RNS / LXMF Python stack.

## Conventions

- Each script verifies one claim or one related cluster of claims.
- Exit code 0 on PASS, non-zero on FAIL.
- Print a one-line PASS/FAIL summary plus a unified diff or hex dump on mismatch.
- Reference the SPEC.md section the script verifies in a docstring at the top.

## Required environment

```
pip install -r requirements.txt
```

`requirements-docs.txt` is a separate, **docs-only** pin (currently NomadNet)
used to re-anchor the informational §11.6 citations. CI does not install it and
no verifier imports it — see the comments in that file for why it is kept out of
this environment.

The scripts read `RNS.__version__` at startup and print it in their output so a future reader can tell which RNS version a verification ran against.

## Citation checking — `check_citations.py`

`check_citations.py` is not a verifier and is deliberately outside the
`verify_*.py` glob; CI runs it as a separate, earlier gate. It resolves every
source citation in `SPEC.md` and `flows/` against the pinned install.

The rule it enforces: **a line number is generated output, never input.** A
citation may carry a verbatim upstream snippet as its anchor, and the checker
finds where that snippet actually lives:

| Form | Example | Checked |
|---|---|---|
| **anchored** | `` `LXMF/LXMessage.py:277` → `self.stamp == RNS.Identity.truncated_hash(ticket+self.message_id)` `` | snippet must exist in the file; cited line must agree |
| **anchored (continuation)** | `` `:1549` → `lxmf_data[:-LXStamper.STAMP_SIZE]` `` | same, bound to the file cited to its left |
| **anchored (symbol)** | `` `RNS/Resource.py::assemble` → `open(self.storagepath, "ab")` `` | snippet must exist inside that symbol's body |
| **symbol** | `` `RNS/Packet.py::prove` `` | symbol must exist |
| **line** | `` `RNS/Resource.py:167-246` `` | legacy; bounds-checked only |

Pick the shortest snippet that is distinctive — `truncated_hash(ticket+self.message_id)`,
not the whole line. Anchor the citations that carry a normative claim; a bare
`file:line` is fine for a "see also" pointer. Whitespace is normalised on both
sides, so indentation and wrapping don't matter.

An anchor snippet must be upstream source text, never another citation —
`` `A.py:1-2` → `B.py:3-4` `` is a call-flow arrow and is left alone.

```
python tools/check_citations.py            # check SPEC.md and flows/
python tools/check_citations.py --fix      # rewrite drifted line numbers
python tools/check_citations.py --selftest # prove the checker still catches each failure mode
python tools/check_citations.py --strict   # warnings become errors
```

**On a version bump this replaces the manual re-read.** Bump
`requirements.txt`, run `--fix`, review the diff. Anything `--fix` refuses to
touch is a citation whose snippet is nowhere in the new upstream — i.e. a
behaviour that actually changed, which is exactly what needs a human.

`tools/citations-exempt.txt` grandfathers documents whose pin declaration is
known-stale. It is a countdown: an entry that is no longer needed is itself an
error, so the list can't rot.

## Status

Populated against RNS 1.5.2 / LXMF 1.1.1 (all 21 scripts re-run green at this pin):

| Script | Verifies SPEC.md section | Status |
|---|---|---|
| `verify_destination_hash.py` | §1.1, §1.2, §1.3 — identity composition, `dest_hash = SHA256(name_hash \|\| identity_hash)[:16]`, on-disk private-key round-trip via `to_file`/`from_file` | ✅ |
| `verify_packet_header.py` | §2.1, §2.2, §2.3 — flag byte layout, HEADER_1/HEADER_2 form, originator HEADER_1→HEADER_2 conversion via upstream `Transport.outbound` | ✅ |
| `verify_token_crypto.py` | §3 — Token encrypt/decrypt, HKDF salt = identity_hash, HMAC-then-AES order, PKCS#7 padding | ✅ |
| `verify_announce_app_data.py` | §4.3 — LXMF announce app_data 2-element form, parser tolerance | ✅ |
| `verify_app_data_dispatch.py` | §4.6 — app_data is opaque to RNS; LXMF's first-byte dispatch on non-LXMF payloads | ✅ |
| `verify_announce_roundtrip.py` | §4.1, §4.2, §4.5 — announce body layout, signature, dest_hash recompute, tamper rejection | ✅ |
| `verify_lxmf_opportunistic.py` | §5.1, §5.2, §5.5, §5.6 — full identity → encrypt → decrypt → parse round-trip | ✅ |
| `verify_canonical_msgpack.py` | §5.6, §5.6.1 — canonical msgpack is a MUST for stamped messages and a SHOULD otherwise; round-trips a non-canonical integer envelope through upstream both ways and reads its verdict, including the unstamped control case | ✅ |
| `verify_lxmf_fields.py` | §5.9 — every `FIELD_*` / `AM_*` / `RENDERER_*` / `PN_META_*` / `SF_*` / reaction-comment-continuation dict-index constant matches upstream, plus an audit that fails if upstream adds an un-enumerated constant | ✅ |
| `verify_lxmf_peer_constants.py` | §5.8.1, §5.8.2 — propagation-node request-path strings across both destinations and the eight `LXMPeer.ERROR_*` response bytes (incl. the unallocated `0xf2`), plus an audit that fails if upstream adds an un-enumerated `ERROR_*` or `*_PATH` constant | ✅ |
| `verify_proof_packet.py` | §6.5 — implicit (64B) and explicit (96B) proof body forms, validator length-dispatch | ✅ |
| `verify_link_handshake.py` | §6.1, §6.2, §6.3, §6.6 — LINKREQUEST/LRPROOF body order, link_id derivation, signalling | ✅ |
| `verify_link_lrrtt.py` | §6.4.2, §6.4.3 — LRRTT wire form, HEADER_1 header, dest_type=LINK, ctx=0xfe, link-form Token body, msgpack float64 plaintext | ✅ |
| `verify_path_request.py` | §1.2 well-known hashes, §7.1 LXMF path-preamble gating | ✅ |
| `verify_rnode_split.py` | §8.3 — RNode air-frame split-packet TX/RX state machines | ✅ |
| `verify_msgpack_quirk.py` | §9.3 — encoding name as bytes vs str affects upstream parsing | ✅ |
| `verify_stamps.py` | §5.7 — workblock determinism, PoW stamp search/validate, ticket shortcut, and the ticket-stamp length: `truncated_hash(ticket \|\| message_id)` is 16 bytes (half `STAMP_SIZE`), emitted by `get_stamp` with `stamp_value = COST_TICKET = 0x100` | ✅ |
| `verify_propagation_get.py` | §5.8.3 — the `/get` retrieval response is a flat list of bodies (not the `[timestamp, [bodies]]` upload envelope), each stripped of its propagation stamp, and `full_hash(body_as_received)` reproduces the node's `transient_id` so the `have_ids` purge round closes | ✅ |
| `verify_resource_sizing.py` | §10.2 step 6, §10.4, §5.7.4 — which Resource quantities follow the negotiated link MTU vs. which are fixed class constants; that upstream still imposes no receive-time part-size check; and the `stamp_cost` `1..254` range with its `< 1 → None` / `>= 255` refused rules | ✅ |
| `verify_ratchet_dedup.py` | §7.3 / §4.5 step 6.3 — confirms replay defence is keyed on `random_blob`, NOT on `(dest_hash, ratchet_pub)` | ✅ |
| `verify_ingress_bounds.py` | §2.2, §4.5 — receive-side ingress bounds added in RNS 1.5.2: `Packet.unpack` rejects a zero-length data field (HEADER_1 and HEADER_2), and `Transport.inbound` refuses an ANNOUNCE over the 500-byte `Reticulum.MTU` as a protocol violation before `validate_announce` runs, while accepting one at exactly the MTU | ✅ |
| `verify_resource_segment_store.py` | §10.11.1 — receiver-side multi-segment store: `storagepath` keyed on the advertised `o` alone (per-node, shared across links), segments concatenated in **arrival** order rather than by `i`, and the 24 h idle `RESOURCE_CACHE` / 15 min sweep / 64-char filename filter | ✅ |
| `regen_identities.py` | regenerates `test-vectors/identities.json` | ✅ |
| `regen_announces.py` | regenerates `test-vectors/announces.json` (deterministic announce wire bytes, with and without ratchet) | ✅ |
| `regen_lxmf.py` | regenerates `test-vectors/lxmf.json` (deterministic opportunistic-LXMF plaintext + Token ciphertext) | ✅ |
| `regen_links.py` | regenerates `test-vectors/links.json` (deterministic LINKREQUEST + LRPROOF + derived session key) | ✅ |

See [`../agent.md`](../agent.md) §5 and [`../todo.md`](../todo.md) for the remaining priority order.
