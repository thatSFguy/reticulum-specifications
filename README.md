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
