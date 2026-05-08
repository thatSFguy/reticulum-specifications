# Reticulum Specifications

Byte-level interoperability specifications for the [Reticulum Network Stack](https://reticulum.network/) and [LXMF](https://github.com/markqvist/LXMF) — the parts that aren't in the upstream manuals but are needed to build a working client from scratch.

Upstream Reticulum has excellent operator-facing documentation (config, deployment, design philosophy). What's missing — and what every alternative implementation has had to reverse-engineer from the Python source — is an authoritative wire-level spec: header bit layouts, msgpack field types, signature input formats, the exact behavior of `Transport.outbound`, and the long list of "would never guess from reading the manual" gotchas that cost hours of debugging each.

This repo collects those findings in one place. The hope is that future client authors (Kotlin, Swift, Rust, Go, embedded C — pick your stack) can read this instead of re-deriving everything from `RNS/Transport.py`.

## Status

**Early days, contributions welcome.** Current content was bootstrapped from the working notes of two reverse-engineering efforts:

- The web-based Reticulum client at [`reticulum-lora-webclient`](https://github.com/thatSFguy/reticulum-lora-webclient)
- The native Android client at [`reticulum-mobile-app`](https://github.com/thatSFguy/reticulum-mobile-app)

Each finding is grounded in upstream source citations (file + line) so it can be re-verified as RNS evolves.

## What's here

- [`SPEC.md`](SPEC.md) — the single combined spec document, organized by protocol layer
- [`flows/`](flows/) — chronological end-to-end narratives (e.g. "send a message"), cross-referencing SPEC.md sections
- [`tools/`](tools/) — self-contained Python verifier scripts that test SPEC.md claims against upstream RNS / LXMF. Pinned via [`tools/requirements.txt`](tools/requirements.txt) to the upstream versions the scripts were last re-verified against
- [`test-vectors/`](test-vectors/) — known-good byte sequences each implementation should be able to round-trip (intent: grow into a compliance suite)

As content grows, `SPEC.md` will be split into per-layer files (packet header, identity, announce, token-crypto, LXMF, link, resource, transport).

## Spec corrections

Errata that may invalidate code built against an earlier revision of `SPEC.md`. Newest first. Feature additions and ordinary edits live in `git log` — this section is reserved for cases where the spec said one thing, that turned out to be wrong, and an implementer who pulled the bad version needs to fix their code.

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

## Source citations

Where a finding cites upstream Python code, the path is relative to a standard `pip install rns lxmf` installation, e.g. `RNS/Transport.py`, `LXMF/LXMF.py`. Where the bundled `umsgpack` is referenced, the path is `RNS/vendor/umsgpack.py`.

When upstream code changes such that a citation no longer matches, file an issue or PR — the goal is to track the de-facto wire spec as it actually behaves, not as it was at any single snapshot.

## Contributing

If you've debugged a Reticulum interop problem and the answer wasn't in the upstream docs, please add it. Format:

```markdown
### N.M Short description of the finding

**Symptom:** what you observed that prompted the investigation.

**What's happening:** the actual mechanism, ideally with upstream source citation (file + line).

**Implication / fix:** what an implementation must do to interop.

**Source:** upstream file paths and approximate line numbers.
```

Add a worked test vector to `test-vectors/` if the finding is byte-level.

## License

[CC BY 4.0](LICENSE) — use freely, attribution appreciated.
