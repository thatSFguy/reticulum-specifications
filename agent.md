# AGENT.md — Instructions for AI agents working on this repository

This file tells AI coding agents (Claude Code, Codex, Cursor, Copilot Workspace, etc.) how to maintain this repository responsibly. The goal of this repo is to be the **canonical, verifiable** byte-level reference for the Reticulum protocol. Speculation is acceptable as a starting point but must be clearly marked as such until tested against the upstream Python implementation.

If you are an AI agent reading this: follow these rules. If you are a human reviewing an agent's PR: enforce these rules.

---

## 1. Verification is mandatory

Every claim in this repository falls into one of three states:

| State | Marker | Meaning |
|---|---|---|
| **Verified** | (no marker, or `[verified]`) | Claim has been tested against the upstream RNS Python stack with a runnable test, OR is a direct citation of upstream source code with file + line. |
| **Unverified** | `> ⚠️ **UNVERIFIED:**` callout | Plausible from source-reading or other-implementation behavior, but not directly tested against upstream Python. May be wrong. |
| **Speculation** | `> 🔮 **SPECULATION:**` callout | Hypothesis based on reasoning about how the protocol *probably* works, with no source citation OR runtime test. Must be resolved (verified or removed) before any release. |

Do not silently promote a claim from **unverified** to **verified** without doing the actual verification. The marker exists so a future reader can trust unmarked content.

### What counts as verification

In rough order of strength:

1. **Round-trip with upstream Python RNS.** A small script in `tools/` that loads the relevant RNS module, performs the operation in both directions, and compares bytes. Strongest evidence.
2. **Direct upstream source citation.** File path and line number in the standard `pip install rns lxmf` install layout (`RNS/`, `LXMF/`). Acceptable for behaviors that are hard to test (e.g. multi-hop forwarding rules).
3. **Wire capture with byte-level diff.** Capturing actual upstream emission (e.g. tcpdump on `rnsd`) and showing it matches the spec.

What does **NOT** count as verification:

- "It worked on my Sideband install" without a script anyone can re-run
- "The webclient does it this way" — webclient may have the same bug
- "Reading this code, I think it does X" — that's source-reading, which is acceptable as a citation but only if the citation is included
- "GPT/Claude/Gemini said so" — no

---

## 2. Workflow for adding a new claim

1. Draft the claim in the relevant section of `SPEC.md` (or the future per-layer file).
2. Mark it `> 🔮 **SPECULATION:**` if it's pure reasoning, or `> ⚠️ **UNVERIFIED:**` if there's a source citation but no runtime test.
3. Write a verifier in `tools/`:
   - For byte-level claims: a Python script that produces the expected upstream bytes and compares to a literal `expected = bytes.fromhex(...)`.
   - For behavioral claims (e.g. "originator inserts transport_id at offset 2 for >1-hop paths"): a script that exercises `RNS.Transport` with a known path table and dumps `process_outgoing` calls.
4. Run the verifier. If it confirms, remove the marker and add a `(verified by tools/<script>.py)` parenthetical to the claim.
5. If the verifier disproves, EITHER fix the claim AND the verifier, OR delete the claim entirely. Do not commit a verifier that hand-waves away a discrepancy.

PRs must include the verifier scripts. Don't commit a "verified" claim without the script that backs it.

---

## 3. Required tools

Agents working on this repo should have access to:

- A working Python 3 install with `rns` and `lxmf` packages: `pip install rns lxmf`
- The `RNS/` and `LXMF/` source trees (typically at `~/AppData/Roaming/Python/Python3xx/site-packages/RNS/` on Windows or `~/.local/lib/python3.x/site-packages/RNS/` on Linux/macOS).
- Optional but very useful: a packet-trace tool. `tcpdump -i lo -A -X port 4242` works for TCPServerInterface; for BLE you need ADB + an RNode-aware capture tool.

Hardware (RNode, RatDeck, etc.) is NOT required for most verification — most byte-level claims can be checked entirely in Python RNS without any radio.

---

## 4. Marking convention

Use these GitHub-flavored Markdown blockquote forms so they render distinctly:

```markdown
> ⚠️ **UNVERIFIED:** This is plausible from reading `RNS/Transport.py:1485` but I have not run a test that demonstrates the behavior end-to-end. Specifically need to confirm that a HEADER_1 packet from a TCP client to a sibling TCP client is forwarded after the rnsd auto-fills `transport_id`.

> 🔮 **SPECULATION:** The path-request payload may include the requester's own transport_id when issued from a transport-enabled originator. The `RNS/Transport.py::request_path` source suggests this but I have not decoded a captured upstream emission to confirm.
```

When you verify a previously-marked claim, **delete the entire blockquote** and (if helpful) append `(verified by tools/<script>.py)` to the claim's prose. Do not just remove the emoji — the structure should disappear so a future reader doesn't have to wonder.

---

## 5. Audit pass — initial state of `SPEC.md`

The bootstrap `SPEC.md` was assembled from the working notes of two reverse-engineering efforts ([webclient](https://github.com/thatSFguy/reticulum-lora-webclient) and [mobile-app](https://github.com/thatSFguy/reticulum-mobile-app)). Some sections are already strongly verified by working code in those repos; some are source-cited but not directly tested in this spec repo's tools; some are observational claims that need formal verification.

Before any v1.0 release, every section needs an explicit verification status. The first task for the next agent is to walk `SPEC.md` section by section and mark each claim per §1 above.

Initial confidence assessment (subjective, not authoritative — re-do this audit independently):

| SPEC.md section | Confidence | Notes |
|---|---|---|
| §1 Identity & destination hashes | High | Round-tripped against upstream in both reverse-engineering repos |
| §2.1, §2.2 Packet header bit layout | High | Matches upstream `RNS/Packet.py`; fixed test vectors round-trip |
| §2.3 Originator HEADER_1 → HEADER_2 conversion | **Source-cited but not test-verified in this repo.** Mark as such until a tools/ script confirms by exercising upstream `Transport.outbound` with a known multi-hop path table. |
| §3 Token crypto | High | Test vectors pass; both reference repos interop with upstream Sideband |
| §4 Announce wire format | High | Test vectors round-trip; signature verification works against upstream emissions |
| §4.3 `app_data` format | Mostly high. The `[name_bytes, stamp_cost, [capability_flags]]` 3-element variant is observed but not formally verified for this repo. |
| §5 LXMF wire format | High |
| §5.6 Dual msgpack-variant signature verification | High — fixed an interop bug in the webclient when added |
| §6 Reticulum Link protocol | High | Both initiator and responder are working in the reference repos |
| §7.1, §7.2 Path requests | **Recently surfaced bug-fix.** §7.2 (responding to inbound path requests) is verified end-to-end on BLE in the mobile-app. §7.1's claim that path requests *always* precede LXMF DATA needs verification — may only happen on stale paths. |
| §7.3 Ratchet rotation | **Spec corrected.** Earlier audit treated this as "verified end-to-end" — but the test result that prompted the verification was attributed to the wrong mechanism (ratchet rotation), when the actual win was the incidental `random_hash` rotation that came along for the ride. `tools/verify_ratchet_dedup.py` (RNS 1.2.0) confirms upstream replay defence is keyed on `random_blob`, not `(dest_hash, ratchet_pub)`. §7.3 reframed as forward-secrecy guidance; §4.5 step 6.3 documents the actual dedup mechanism. |
| §7.4 Ratchet ring (inbound decrypt tolerance) | **UNVERIFIED in current implementations.** The reference repos discard old ratchet privkeys on rotation. Upstream's "8 ratchets" default needs source citation. |
| §7.6 `TCPServerInterface.OUT` override | Source-cited; matches behavior observed in the mobile-app's local-transport experiments. |
| §8 KISS / HDLC framing | High — both work in production on the reference clients |
| §9.1–§9.8 Implementation gotchas | Each was a real bug that bit a real implementation. High confidence each is real; some lack formal test scripts. |
| §10 Resource fragmentation | Source-cited from `RNS/Resource.py` against RNS 1.2.0; not yet runtime-verified in this repo's `tools/`. |
| §11 Test vectors | The vectors themselves are verified; the test-vectors/ directory needs to be populated in this repo (currently partially populated). |
| §12 Source map | High |

**Concrete next-task list** for the agent picking this up:

1. Run the audit — re-evaluate the table above with your own reasoning, don't just trust it.
2. Populate `test-vectors/` with at least: identity material, a signed announce, an opportunistic-LXMF round-trip, a Link handshake.
3. Write `tools/verify_announce.py` that loads a test vector and verifies bytes against upstream RNS.
4. For each `> ⚠️` or `> 🔮` callout you add, write the verifier alongside.
5. Open issues for any claim you can't verify and tag them `needs-verification`.

---

## 6. PR rules

For any PR touching `SPEC.md`:

- Every new claim has a verification marker OR is unmarked because it has a `(verified by tools/...)` reference.
- Every removed marker has a corresponding new tools/ script in the same PR.
- No "I tested this manually and it worked" — capture the test as a runnable script.
- Reviewers should reject PRs that quietly remove markers without including the verifier.

For PRs adding to `test-vectors/`:

- Include the script that generated the vector (so it can be regenerated against future upstream RNS).
- Include the upstream RNS version the vector was generated against (`pip show rns` output is fine).
- The test vector should round-trip in both directions (build+sign AND parse+verify) when run through upstream RNS.

---

## 7. What to do when upstream changes

RNS evolves. When a future RNS version changes the wire format (or the in-source behavior cited in this spec):

1. **Don't silently update the spec.** The old behavior may still be in production deployments and matter for interop.
2. Add a versioned note: `As of RNS x.y.z this changed to ...`. Keep the prior behavior described too.
3. Update `tools/` verifiers to test against both the old and new behavior if possible.
4. Bump a `last-verified-against-rns: x.y.z` line in `SPEC.md`'s frontmatter.

The goal is for this spec to be useful even when run against an RNS version a year out of date — that's the worst-case in heterogeneous mesh deployments.

---

## 8. Don't

- Don't paste large blocks of upstream code into this repo (license & churn). Cite by file + line + small inline snippet only.
- Don't add claims based purely on what some other client does. Other clients have bugs too.
- Don't remove a `⚠️` or `🔮` marker without doing the verification work.
- Don't commit a verifier that swallows discrepancies (`if expected != actual: print("close enough")`). Either it matches or it doesn't.
- Don't trust your own training data on this — Reticulum-specific protocol details are sparse on the public web and most LLM knowledge is wrong or out of date. Verify everything.

---

## 9. Repo layout (current and aspirational)

```
reticulum-specifications/
├── README.md              Project intro
├── LICENSE                CC BY 4.0
├── agent.md               This file
├── SPEC.md                Combined spec (will be split into per-layer files as it grows)
├── tools/                 Verifier scripts (Python, callable against upstream RNS)
│   ├── verify_announce.py        (TODO)
│   ├── verify_packet_header.py   (TODO)
│   ├── verify_lxmf_roundtrip.py  (TODO)
│   └── verify_link_handshake.py  (TODO)
└── test-vectors/          Known-good byte sequences
    ├── README.md          (TODO — describe vector format)
    ├── identities.json    (TODO)
    ├── announces.json     (TODO)
    └── ...
```

Tools are Python because Python RNS is the reference. Verifiers should be self-contained scripts that print PASS/FAIL plus a diagnostic on mismatch. Exit code 0 on PASS, non-zero on FAIL.
