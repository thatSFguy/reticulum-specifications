# Reticulum Specifications

Byte-level interoperability specifications for the [Reticulum Network Stack](https://reticulum.network/) and [LXMF](https://github.com/markqvist/LXMF) — the parts that aren't in the upstream manuals but are needed to build a working client from scratch.

Upstream Reticulum has excellent operator-facing documentation (config, deployment, design philosophy). What's missing — and what every alternative implementation has had to reverse-engineer from the Python source — is an authoritative wire-level spec: header bit layouts, msgpack field types, signature input formats, the exact behavior of `Transport.outbound`, and the long list of "would never guess from reading the manual" gotchas that cost hours of debugging each.

This repo collects those findings in one place. The hope is that future client authors (Kotlin, Swift, Rust, Go, embedded C — pick your stack) can read this instead of re-deriving everything from `RNS/Transport.py`.

## Status

**Early days, contributions welcome.** Current content was bootstrapped from the working notes of two reverse-engineering efforts:

- The web-based Reticulum client at [`reticulum-lora-webclient`](https://github.com/thatSFguy/reticulum-lora-webclient)
- The native Android client at [`reticulum-mobile-app`](https://github.com/thatSFguy/reticulum-mobile-app)

Each finding is grounded in upstream source citations (file + line) so it can be re-verified as RNS evolves. Now that the spec exists, **upstream is the only source of truth** — see the [`agent.md`](agent.md) §0 prime directive.

Tagged releases (CalVer — see [releases](../../releases), e.g. `v2026.06.19`) record the exact `RNS` / `LXMF` versions the whole document was last verified against. A GitHub Actions `verify` workflow re-runs every `tools/verify_*.py` on each PR, and Dependabot opens a bump PR whenever upstream publishes a new release — so wire-format drift surfaces immediately.

## What's here

- [`SPEC.md`](SPEC.md) — the single combined spec document, organized by protocol layer
- [`playbook.md`](playbook.md) — how to troubleshoot interop bugs, design tests that don't lie to you, and navigate the protocol's code-as-spec parts. **Read this if you're starting any Reticulum implementation work, not just contributing to this repo.** Includes an incident registry of past wire-format bugs and their fixes.
- [`agent.md`](agent.md) — rules for adding to this repo: the **§0 prime directive** (the spec is authoritative and follows upstream only — third-party app behavior is not admissible evidence), plus verification markers, `tools/` verifiers, and test-vectors
- [`templates/`](templates/) — drop-in `AGENTS.md` for new Reticulum implementation projects in any language. Copy into your project root, edit the marked sections, and the next agent or contributor lands on the right docs automatically.
- [`flows/`](flows/) — chronological end-to-end narratives (e.g. "send a message"), cross-referencing SPEC.md sections
- [`tools/`](tools/) — self-contained Python verifier scripts that test SPEC.md claims against upstream RNS / LXMF. Pinned via [`tools/requirements.txt`](tools/requirements.txt) to the upstream versions the scripts were last re-verified against
- [`test-vectors/`](test-vectors/) — known-good byte sequences each implementation should be able to round-trip (intent: grow into a compliance suite)

As content grows, `SPEC.md` will be split into per-layer files (packet header, identity, announce, token-crypto, LXMF, link, resource, transport).

## Spec corrections

Errata that may invalidate code built against an earlier revision of `SPEC.md`. Newest first. Feature additions and ordinary edits live in `git log` — this section is reserved for cases where the spec said one thing, that turned out to be wrong, and an implementer who pulled the bad version needs to fix their code.

- **2026-08-28 — §5.6.1: canonical msgpack encoding is a MUST for stamped messages, not a SHOULD.**
  §5.6.1 said senders "SHOULD produce signing-input bytes that match `umsgpack`'s output … so receivers' path-1 (raw) verification succeeds and the path-2 (decode + re-encode) fallback stays defensive rather than load-bearing." For any message carrying a §5.7 stamp that framing is structurally wrong: path-1 cannot succeed. The signature covers the **4-element** payload (`LXMF/LXMessage.py:367`) and the stamp is appended afterwards (`:373`), so the **5-element** array is what reaches the wire (`:381`) — the signed bytes are never the wire bytes. The receiver rebuilds them by re-encoding the first four elements (`:758`, inside the `len(unpacked_payload) > 4` gate at `:755`), which makes the sender's encoding an equality between two independently produced byte strings rather than a nicety. Upstream Python satisfies it trivially, same encoder on both sides, which is why it is invisible from the Python side. An implementer who read the old SHOULD and shipped a non-canonical encoder — one wide integer envelope is enough — sees `signature_validated = False` with `unverified_reason = SIGNATURE_INVALID` on every stamped message, and a diverging `message_id` (`:763`) that fails stamp validation alongside it, presenting as two bugs. §5.6 now also records that upstream does not try both variants but selects one on stamp presence, so a sender has no raw-bytes fallback. Unstamped messages keep the SHOULD, and that carve-out is verified rather than assumed. Now covered by `tools/verify_canonical_msgpack.py`. Surfaced by [issue #43](../../issues/43), reported against a clean-room Go implementation; the issue's closing comment records one correction to the report — the re-encode at `:758` is gated by `len(unpacked_payload) > 4` at `:755`, which is what makes the unstamped SHOULD correct rather than an oversight.

- **2026-08-28 — §5.8.3: the `/get` message-delivery response is a flat list of bodies, not `[timestamp, [bodies]]` — and the propagation stamp is stripped before serving.**
  §5.8.3 described the retrieval response as a Resource carrying `msgpack.packb([time.time(), [lxmf_data_1, ...]])`. That is the **upload** envelope (§5.8.2). Upstream's `message_get_request` builds `response_messages = []` (`LXMF/LXMRouter.py:1523`) and returns it directly (`:1555-1556`); the client iterates it as bodies with nothing to unwrap (`:1624-1627`). An implementer who built from the old text decodes body #1 as a timestamp and body #2 as the message list, so the first non-empty mailbox either drops every message or mangles the first two. Two further details were missing entirely: the node serves `lxmf_data[:-LXStamper.STAMP_SIZE]` (`:1549`), so a retrieved body is the **pre-stamp** propagated form and must not have 32 bytes sliced off it again; and the `transient_id` used in the `have_ids` purge round is `full_hash` of the body *as received*, because the node derived that id before appending the stamp (`:2494`, `:2512`). `flows/receive-propagated-lxmf.md` carried the same wrong shape and is corrected in the same revision. Now covered by `tools/verify_propagation_get.py`. Surfaced by [issue #38](../../issues/38).

- **2026-08-28 — §5.7.3: a ticket stamp is 16 bytes (`truncated_hash`), not 32 — the `[:32]` was wrong.**
  §5.7.3 gave the ticket-stamp formula as `SHA256(ticket || message_id)[:32]  # truncated to STAMP_SIZE`. Upstream uses `RNS.Identity.truncated_hash` (`LXMF/LXMessage.py:300`, compared at `:277`), which truncates to `TRUNCATED_HASHLENGTH = 128` bits — **16** bytes, half a proof-of-work stamp. The two lengths do not interoperate in either direction: a sender emitting 32 bytes misses upstream's ticket branch, falls through to the PoW branch, fails that too, and is dropped by any receiver enforcing stamps; a receiver expecting 32 bytes rejects every genuine ticket stamp. Nothing logs a length error — the message simply reads as unstamped. It also breaks an otherwise reasonable `len(stamp) == STAMP_SIZE` guard before splicing payload element [4], which is **not** fixed-width. §5.7.1 now says so, and §5.7.3 states `COST_TICKET = 0x100` = 256 explicitly, since implementations surface it on the same `stamp_value` field a PoW stamp reports leading-zero counts on. Now covered by `tools/verify_stamps.py`. Surfaced by [issue #39](../../issues/39).

- **2026-08-27 — §12.6 tunnel-table entry shape was wrong: index 0 is `tunnel_id` and index 1 is the interface, not a timestamp and an expiry.**
  §12.6 showed the `tunnels[tunnel_id]` entry as `[now, expires, paths_dict, ...]` with an `IDX_TT_TIMESTAMP` label at index 0. There is no `IDX_TT_TIMESTAMP` constant in upstream. The real shape is `[tunnel_id, interface, paths, expires]` (`RNS/Transport.py:2762-2764`) with indices `IDX_TT_TUNNEL_ID = 0`, `IDX_TT_IF = 1`, `IDX_TT_PATHS = 2`, `IDX_TT_EXPIRES = 3` (`:4083-4086`). Only index 2 was right. An implementer who built tunnel handling from the old table reads the interface handle where it expects an expiry timestamp and vice versa — tunnels either never expire or expire immediately, and `void_tunnel_interface` writes to the wrong slot. This affects transport-node implementations only; leaf clients don't maintain tunnels. Found during the full source-citation audit; no runtime verifier covers tunnels (see `todo.md`).

- **2026-08-27 — §9.10 / §4.1: the microReticulum `random_hash` deviation has been fixed upstream; the spec described it as live.**
  §9.10 was a full section, and §4.1 carried an UNVERIFIED callout, both stating that `attermann/microReticulum` emits 10 fully-random bytes for the announce `random_hash` instead of `5 random || big-endian uint40 unix_seconds`, causing mixed-vendor path-table stickiness. Upstream has since landed the timestamp half: `src/microReticulum/Destination.cpp:272-280` builds `Cryptography::random(5) + time_bytes(5)` (the source path also moved from `src/Destination.cpp`). Verified against microReticulum master `40fa628` (2026-07-20) **and** `5fbdbf37` (2026-06-19), the commit `thatSFguy/reticulum-lora-repeater` pins — both carry the fix, so the repeater and Faketec are conformant. An implementer who read the old §9.10 would carry receiver-side workarounds, and possibly a "reject far-future timestamps" rule, for a bug that no longer exists. §9.10 is rewritten as a historical entry that keeps only the clock-hygiene advice, which stands on its own.

- **2026-08-27 — §12.3.2 / §16.1 `Transport.MAX_RANDOM_BLOBS` is `64`, not `32`; §7.2.2 `Transport.max_pr_tags` is `16000` as of RNS 1.5.0.**
  §12.3.2 stated that the per-destination `random_blobs` list "is capped at `Transport.MAX_RANDOM_BLOBS` (default 32) entries", contradicting §4.5 step 6.3 and §16.1 in the same document, both of which said `64`. Upstream has been `MAX_RANDOM_BLOBS = 64` throughout (`RNS/Transport.py:159`), so §12.3.2 was wrong from introduction rather than drifting. An implementer who sized the blob ring at 32 evicts announce blobs twice as fast as upstream and re-forwards announces the reference relay would have suppressed as already-seen — a mild rebroadcast amplification on a busy destination, not a hard interop break. Separately, §7.2.2 gave the path-request dedup table's bound as `max_pr_tags = 32000`; that was correct through RNS 1.4.2 but upstream halved it to `16000` in 1.5.0, and the same revision changed `discovery_pr_tags` from a list to a two-generation set (see the §7.2.2 callout). Both values corrected against the `rns==1.5.0` pin; no runtime verifier covers either constant (see `todo.md`).

- **2026-08-19 — §5.8.2 propagation-node error-response values: `ERROR_THROTTLED` is `0xf6` (not `0xf2`) and `ERROR_NOT_FOUND` is `0xfd` (not `0xf5`).**
  The §5.8.2 error table listed `ERROR_THROTTLED = 0xf2` and `ERROR_NOT_FOUND = 0xf5`. Upstream `LXMF/LXMPeer.py:24-31` defines neither of those values at those points: the constants are `ERROR_NO_IDENTITY = 0xf0`, `ERROR_NO_ACCESS = 0xf1`, `ERROR_INVALID_KEY = 0xf3`, `ERROR_INVALID_DATA = 0xf4`, `ERROR_INVALID_STAMP = 0xf5`, `ERROR_THROTTLED = 0xf6`, `ERROR_NOT_FOUND = 0xfd`, `ERROR_TIMEOUT = 0xfe` — with no constant allocated at `0xf2`. These values are unchanged as far back as LXMF 0.9.7, so the spec was wrong from the section's introduction rather than drifting from a later upstream change. An implementer who built against the old table treats a genuine `ERROR_THROTTLED (0xf6)` as an unknown error and retries immediately instead of backing off for `PN_STAMP_THROTTLE`, and mis-reads `0xf5` (`ERROR_INVALID_STAMP`) as `ERROR_NOT_FOUND`. §5.8.2 now lists all eight constants with the upstream values, notes the `0xf2` gap explicitly, and warns that the values are not contiguous. Found while re-resolving source citations against the `rns==1.4.2` / `lxmf==1.1.1` pin bump; no runtime verifier covered these constants (see `todo.md`).

- **2026-06-19 — §5.9.8 tap-back reactions now have an official upstream allocation at `FIELD_REACTION = 0x40`, which differs from the `fields[0x10]` app-extension the spec previously documented.**
  Before this revision §5.9.8 documented reactions only as a non-upstream app-extension at `fields[0x10]` (= `16`) with a *string-keyed* dict (`{"reaction_to", "emoji", "sender"}`) — there was then no `FIELD_REACTION` constant in upstream. LXMF 1.0.0 (2026-05-28) added one: `FIELD_REACTION = 0x40` (`LXMF/LXMF.py:25`), carrying an *integer-keyed* dict `{REACTION_TO(0x00): raw-bytes message_id, REACTION_CONTENT(0x01): UTF-8 reaction}` with **no in-dict sender** (attribution is the carrying message's own source identity). The two shapes differ in field key (`0x10` vs `0x40`), inner-key type (string vs int), hash encoding (hex string vs raw bytes), and sender handling. An implementer who built against the old §5.9.8 emits `0x10` reactions that upstream LXMF 1.0.x will not recognise as reactions, and ignores inbound `0x40` reactions. **§5.9.8 now documents only the upstream `0x40` form; the non-upstream `0x10` form has been removed entirely** — per the [`agent.md`](agent.md) §0 prime directive, the spec follows upstream (`markqvist/Reticulum`, `markqvist/LXMF`, and the author's `markqvist/Sideband` reference client) and no longer documents or accommodates third-party app behavior. Pins moved to `rns==1.3.5` / `lxmf==1.0.1` in the same revision; the related §5.9.9 reply-to keys (`0x30`/`0x31`) were also blessed upstream and §5.9.10/§5.9.11 added for the new `FIELD_COMMENT` (`0x41`) and `FIELD_CONTINUATION` (`0x42`).

- **2026-05-17 — §10.2 Resource integrity hash: the 4-byte prefix is NOT `r`, and is NOT in the hash input.**
  Bad text introduced in [`95823ad`](../../commit/95823ad); on master from 2026-05-03 to 2026-05-17. §10.2 step 3 wrongly equated the random-hash *prefix* prepended to the Resource body with the advertisement's `r` field, and step 5 wrongly fed that prefix into `hash`/`expected_proof` (claiming `hash = SHA256(random_hash || body || random_hash)`). Upstream `RNS/Resource.py` (1.2.4) uses *two distinct* `get_random_hash()[:4]` values: a throwaway prefix the receiver strips and discards (`:405`/`412`, `:682`), and `self.random_hash` — the advertisement's `r` field (`:440`, `:1285`). The integrity hash is `SHA256(uncompressed_plaintext || r)` over the prefix-stripped, decompressed body (`:441`, `:694`) — exactly as §10.8 already stated. An implementer who trusted §10.2 step 5 computes a hash no spec-compliant peer accepts; every Resource is rejected as `CORRUPT`. §10.2 corrected to agree with §10.8; §10.12's wire-layering block fixed to match. Surfaced by [issue #9](../../issues/9).

- **2026-05-06 — §2.1 flag byte: bit 7 is the IFAC flag, not part of `header_type`.**
  Bad text introduced in [`8c4d550`](../../commit/8c4d550), corrected in [`0c2021e`](../../commit/0c2021e); on master from 2026-05-04 to 2026-05-06. The corrected layout is `ifac_flag(bit 7) | header_type(bit 6) | context_flag(5) | transport_type(4) | destination_type(3-2) | packet_type(1-0)`, matching the official manual §4.6.3 and upstream `RNS/Packet.py:246` (parse mask `0b01000000 >> 6`) / `RNS/Transport.py:1003` (IFAC setter `raw[0] | 0x80`). Implementers who consumed the bad version will mis-parse every IFAC-protected packet as `header_type ∈ {2, 3}` and drop it. Surfaced by [issue #4](../../issues/4) item #1.

## Scope

**In scope:**
- Wire formats: byte layouts, field encodings, framing
- Signing inputs and what's hashed where
- Cross-cutting behaviors required for interop (path requests, ratchet rotation, retransmit semantics)
- "Gotchas" — things upstream code does that aren't obvious from the manual or RFC-style sketches
- Test vectors that any implementation must be able to round-trip

**Out of scope:**
- Operator/user documentation — see [the official manual](https://markqvist.github.io/Reticulum/manual/)
- API design choices for any specific implementation
- Networking layer config (interfaces, transport modes) — already well documented
- Third-party client-app behaviors and conventions — the spec follows upstream (`markqvist/Reticulum`, `markqvist/LXMF`, and the author's `markqvist/Sideband` for app-layer shapes LXMF itself doesn't pin). Apps conform to the spec, not the reverse — see [`agent.md`](agent.md) §0.

## Source citations

Where a finding cites upstream Python code, the path is relative to a standard `pip install rns lxmf` installation, e.g. `RNS/Transport.py`, `LXMF/LXMF.py`. Where the bundled `umsgpack` is referenced, the path is `RNS/vendor/umsgpack.py`.

When upstream code changes such that a citation no longer matches, file an issue or PR — the goal is to track the de-facto wire spec as it actually behaves, not as it was at any single snapshot.

## Contributing

If you've debugged a Reticulum interop problem and the answer wasn't in the upstream docs, please add it. Format:

```markdown
### N.M Short description of the finding

**Symptom:** what you observed that prompted the investigation.

**What's happening:** the actual mechanism, with an admissible upstream source citation (file + line) — see [`agent.md`](agent.md) §0 for what counts (RNS / LXMF / Sideband; third-party app behavior does not).

**Implication / fix:** what an implementation must do to interop.

**Source:** upstream file paths and approximate line numbers.
```

Add a worked test vector to `test-vectors/` if the finding is byte-level.

## License

[CC BY 4.0](LICENSE) — use freely, attribution appreciated.
