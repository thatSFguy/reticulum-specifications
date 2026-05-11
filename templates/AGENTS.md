<!--
This is a TEMPLATE. Copy it into the root of a new Reticulum implementation
project (Kotlin, Swift, Rust, Go, C, JS — any language) as `AGENTS.md`,
then edit the sections marked `<!-- FILL IN: ... -->`.

If you keep this file, you must keep the attribution to
https://github.com/thatSFguy/reticulum-specifications intact. The spec
repo is where the wire-format knowledge that makes your project possible
lives; pointing back to it is how that knowledge stays maintained and how
downstream agents find it.

Source: reticulum-specifications/templates/AGENTS.md
License: CC BY 4.0
-->

# AGENTS.md — guidance for contributors and AI agents

This project is a [Reticulum](https://reticulum.network/) implementation. The byte-level protocol it implements is specified in **[reticulum-specifications](https://github.com/thatSFguy/reticulum-specifications)** — that is the authoritative reference for every wire format, framing rule, and signature input touched by this codebase.

If you are an AI agent (Claude Code, Codex, Cursor, Copilot Workspace, etc.) working in this repo: read the four files linked below **before** reading any source in this project. Same for human contributors who haven't worked on a Reticulum stack before.

---

## 1. Read these first

Every Reticulum implementation builds on the same set of documents. Read in this order:

1. **[reticulum-specifications/SPEC.md](https://github.com/thatSFguy/reticulum-specifications/blob/main/SPEC.md)** — the byte-level spec. Section-numbered. Cite it in commit messages and code comments by section (e.g. "SPEC §6.4.3"). When this project's behavior disagrees with the spec, the spec wins until proven otherwise.
2. **[reticulum-specifications/playbook.md](https://github.com/thatSFguy/reticulum-specifications/blob/main/playbook.md)** — how to troubleshoot interop bugs, design tests that don't lie to you, and navigate a protocol whose primary documentation is its source code. Includes an incident registry of past wire-format bugs — skim it; one of them is probably your bug. Includes the cardinal rules summarized in §2 below.
3. **[reticulum-specifications/agent.md](https://github.com/thatSFguy/reticulum-specifications/blob/main/agent.md)** — verification discipline (markers, tools/, test-vectors) for contributions back to the spec repo. Relevant whenever you discover something the spec doesn't yet cover.
4. **This file** — project-specific conventions for the codebase in front of you. The sections below either point at the project's `README.md` / build files or contain project-specific rules the implementer has chosen.

These four documents together are the working set. Loading any subset of them produces shallow work.

---

## 2. Cardinal rules

These apply to every Reticulum implementation regardless of language. See `playbook.md` for the long form; the short form is:

1. **Spec before code.** Before debugging a wire-format bug, identify the spec section that governs the failing byte path and read it. Two minutes of spec-reading saves two hours of code-reading. Per `playbook.md` §2.1.
2. **Rebuild sibling-impl binaries before assuming your code is wrong.** A pre-built artifact in a sibling repo's `build/` directory may lag the source by months. Run `go build` / `cargo build` / `make` in the sibling repo first and confirm the version constant matches the source. Per `playbook.md` §2.2 — this trap costs hours every time it isn't caught.
3. **Self-round-trip tests are insufficient for wire formats.** They pass when both sides agree on the wrong thing. Any code that produces or consumes wire bytes must also have at least one byte-equality test against upstream Python RNS (see `reticulum-specifications/tools/`). Per `playbook.md` §5.
4. **Symptom mapping: silent drops are not random.** Common interop symptoms have specific spec-section root causes:
   - Multi-hop drops → SPEC §2.3 originator HEADER_2 conversion
   - Link establishes then silently drops DATA → SPEC §6.4.2 (LRRTT missing) or §6.4.3 (header rules)
   - Signature invalid → SPEC §4.2, §5.6.1, §6.2/§6.6 (signed_data construction)
   - Returns large message truncated → SPEC §10 Resource
   Read the registry in `playbook.md` §7 before designing a debugging plan from scratch.
5. **Write up what you learn.** When you discover a wire-format detail the spec doesn't cover, open an issue or PR against `reticulum-specifications` with a source citation. The spec stays useful only because the people who debug interop bugs feed their findings back. Even an "I found this, marked ⚠️ UNVERIFIED, here's where in upstream RNS it lives" contribution is high-value.

---

## 3. This project

<!-- FILL IN: one-paragraph description of what this implementation is.
     Target audience: an agent or contributor who has just read the spec
     and now needs to know what THIS codebase does specifically. Example:

     > Native Android + iOS client built in Kotlin Multiplatform. Implements
     > opportunistic LXMF, the Link protocol (initiator + responder), Resource
     > framing on the receive side, and BLE/USB/TCP transports. Replaces the
     > Capacitor-based webclient in `../reticulum-lora-webclient/`.
-->

### 3.1 Build and test

<!-- FILL IN: the actual commands. Examples:
     - `./gradlew :shared:testDebugUnitTest`
     - `go test ./...`
     - `cargo test --workspace`
     - `xcodebuild -scheme MyApp test`
     If there is a separate interop test path that spawns sibling binaries,
     name it explicitly and note that it auto-rebuilds the sibling per
     playbook.md §2.2.
-->

### 3.2 Architecture

<!-- FILL IN: enough orientation that an agent can find the right file
     for a given concern. A short table works well, e.g.:

     | Concern | Where it lives |
     |---|---|
     | Packet header encode/decode | src/protocol/Packet.kt |
     | Token crypto | src/crypto/TokenCrypto.kt |
     | Link state machine | src/engine/LinkSession.kt |
     | LXMF pack/unpack | src/lxmf/Lxmf.kt |

     Keep this list short — link to a longer doc if the project warrants one.
-->

### 3.3 Where this project deviates from the spec

<!-- FILL IN: ideally empty. If non-empty, every entry must cite the SPEC
     section it deviates from, the reason for the deviation, and the
     date/version this deviation was introduced. If the deviation is a
     bug, link to the issue tracking it. Keep this list honest — agents
     will look here to understand "wait, the spec says X but this code does Y."
-->

### 3.4 Project-specific conventions

<!-- FILL IN: any conventions an agent needs to know that aren't in the
     spec or playbook. Examples:
     - Commit message format
     - Test discipline (TDD? coverage thresholds?)
     - Release process / tagging
     - Sibling repos this project loads at test time
-->

---

## 4. Contributing findings back upstream

If you find a wire-format detail that isn't documented in `reticulum-specifications/SPEC.md`, you have an obligation to write it up. The spec repo's existence depends on it. Process:

1. **In your commit message for this project's code change**, cite the SPEC section the fix relates to (or note "not yet in SPEC"). This makes future `git blame` archaeology productive.
2. **Open an issue or PR against [`reticulum-specifications`](https://github.com/thatSFguy/reticulum-specifications)** with the finding. Even a one-paragraph description with a source citation (file + line in upstream RNS or in this project) is useful. Mark as `⚠️ UNVERIFIED` per the spec repo's `agent.md` §1 if you haven't written a `tools/verify_*.py` for it yet.
3. **Append an incident registry entry to `playbook.md` §7** if your fix corresponds to a non-obvious wire-format trap — symptom, spec section, fix, one-sentence lesson. Future contributors will pattern-match symptoms against this list before they start debugging from scratch.

This isn't bureaucracy — it's the only mechanism that keeps the spec from rotting into the same opaque code-only state every alternative implementation had to reverse-engineer through. The hour you spend writing up a finding saves the next implementer a day.

---

## 5. Attribution

This file is a template from [`reticulum-specifications/templates/AGENTS.md`](https://github.com/thatSFguy/reticulum-specifications/blob/main/templates/AGENTS.md), licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The wire-format knowledge that makes this project possible lives at **<https://github.com/thatSFguy/reticulum-specifications>**. If you find this template useful, please:

- Keep this attribution section intact in your project's `AGENTS.md`.
- Link the spec repo prominently in your project's `README.md`.
- Contribute findings back per §4.

Reticulum the protocol is by [Mark Qvist](https://github.com/markqvist) (`RNS` and `LXMF`). The spec repo, this template, and the cross-implementation interop work are community-maintained on top of his protocol.
