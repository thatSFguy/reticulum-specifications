# templates/

Drop-in files for new Reticulum implementation projects. Copy into the root of your project and edit the marked sections.

| File | Where to put it in your project | What it does |
|---|---|---|
| [`AGENTS.md`](AGENTS.md) | Project root, as `AGENTS.md` | Tells AI agents (Claude Code, Codex, Cursor, etc.) and human contributors which docs to read first, the cardinal rules for working on a Reticulum stack, and how to feed findings back upstream. Includes placeholder sections for project-specific build/architecture notes. |

## Why this exists

Every alternative Reticulum implementation (Kotlin, Swift, Rust, Go, C, JS) re-discovers the same handful of wire-format gotchas (HEADER_2 conversion, LRRTT, signalling in LRPROOF signed_data, etc.). Most of those gotchas are now in [`SPEC.md`](../SPEC.md) and [`playbook.md`](../playbook.md). The `AGENTS.md` template makes it trivial to point new projects at those documents — and at the incident registry — before they spend hours rediscovering known bugs.

## Attribution

These templates are [CC BY 4.0](../LICENSE). Use them freely. Keeping the attribution section pointing back to this repo is the entire ask — it's how downstream agents find their way back to the source of truth, and how the spec stays maintained.
