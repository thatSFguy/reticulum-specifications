# Playbook — debugging, testing, and problem-solving for Reticulum work

Companion to `agent.md`. Where `agent.md` governs **what evidence is admissible** as you add to the spec (markers, tools/, verifiers), this file covers **how to navigate the work** itself: how to triage a wire-format bug, how to design tests that don't lie to you, and how to make forward progress in a protocol that exists primarily in code rather than prose.

If you're an AI agent: read this when you start a Reticulum task, alongside `agent.md` and the spec section relevant to what you're touching.
If you're a human contributor: same.

---

## 1. The first question is always "which implementation, which version"

Reticulum exists in at least six places at the time of this writing:

| Repo / install | Language | Role |
|---|---|---|
| `~/.local/.../site-packages/RNS/` (upstream `pip install rns`) | Python | The reference implementation. When the spec is silent, RNS wins. |
| `reticulum-specifications/` (this repo) | Prose + Python verifiers | The authoritative byte-level spec. When implementations disagree, the spec wins. |
| `reticulum-mobile-app/` | Kotlin Multiplatform | Android + iOS native client. |
| `reticulum-forwarding-service/` (fwdsvc) | Go | Group-chat forwarder. Has the best test-harness pattern in the ecosystem — read it. |
| `reticulum-lora-webclient/` | TypeScript / Capacitor | Predecessor to mobile-app. Frozen but still useful for cross-checking. |
| `reticulum-rnode/`, `reticulum-lora-repeater/`, `microReticulum_Faketec_Repeater/` | C++ firmware | Embedded clients. Useful for byte-layout cross-checks on Link. |

A wire-format bug almost always sits in the interaction between two of these. Before reading any source, identify which two implementations are involved in the failing path and which version of each is actually running on the wire. This sounds obvious; it's where the most time gets lost (see §3).

---

## 2. The triage checklist

Before reading code or grepping logs, answer these in order. Do not skip ahead. Each step takes <5 minutes and rules out a huge slice of the search space.

### 2.1 Which byte path is failing?

Map the failure to a specific spec section:

- Connection won't establish → §6.1 LINKREQUEST, §6.2 LRPROOF
- Link establishes, then app data silently disappears → §6.4.2 LRRTT, §6.4.3 link header rules
- Multi-hop only → §2.3 originator HEADER_2 conversion, §12 transport relay
- Message goes through but signature reports invalid → §4.2, §5.6.1, §6.2/§6.6
- Large message truncated → §10 Resource
- Returning client can't be reached → §7 path requests, §7.3 ratchet

Read that spec section start-to-finish before reading any code. Two minutes of spec reading saves two hours of code reading on routing/framing bugs. This has been true on every wire-format incident in the project's history; see the incident registry below.

### 2.2 Is your local copy of every sibling actually current?

This is step zero in practice. The trap:

> You have a sibling repo checked out (`reticulum-forwarding-service/`, `reticulum-rnode/`, etc.). Your interop test loads a **pre-built binary** from that repo's `build/` directory. The binary was built months ago. The source has since fixed the very bug you're chasing.

Real example, 2026-05-10: ~2 hours debugging `Link.kt` against `fwdsvc-windows-amd64.exe` v1.0.1 when the source on the same disk was at v1.3.3 and the fix for the failing path had been committed in v1.0.3. Rebuilding from source resolved it.

Rule: **before reading any source on an interop bug, run the rebuild command in every sibling repo whose artifact is loaded by the test.** For Go: `go build`. For Rust: `cargo build`. For Python: nothing — but check the installed `pip show rns` version against what the spec was last verified against (`SPEC.md` records this).

If your test harness loads a pre-built artifact, fix the harness to rebuild on every run. Loading a cached binary is a footgun, full stop. The Go harness in `reticulum-forwarding-service/tests/interop/harness_test.go` (`requireFwdsvc(t)`) does this correctly; copy the pattern.

### 2.3 Is the symptom directional?

For any pair (A, B), the failure has one of three shapes:

- **A→A and B→B both work, A→B fails (or vice versa)** → wire-format divergence between A and B. One of them is spec-compliant, the other isn't. Identify which by reading the spec.
- **A→A works, A→B and B→A both fail** → A diverges from spec, B is spec-correct. The B side will show "signature invalid" / "drop unparseable" / similar.
- **A→A works after upgrade, A→A worked before upgrade, but A→A doesn't work mid-upgrade** → wire-format change you didn't realize was a wire-format change. Roll back, add a spec note, version the format.

Self-round-trip tests catch none of these (§5).

### 2.4 Is upstream Python able to do this exchange?

If the failure involves two non-Python implementations, ask: can I reproduce it with upstream RNS as one of the endpoints? If yes, you have a clean half of the comparison. If no, you have a clean confirmation that both sides diverge from upstream — different bug.

`rnsd` + a small Python script using `RNS.Reticulum` and `LXMF.LXMRouter` is enough for almost any reproduction. The `tests/interop/cases/*.py` files in `reticulum-forwarding-service/` are good templates.

---

## 3. Common debugging anti-patterns to avoid

### 3.1 Don't trust web search or LLM training data

Reticulum-specific protocol details barely exist on the public web outside the upstream Python source and the official `reticulum.community` forum. Most search results conflate Reticulum (the protocol) with `reticulum` (the BERT preprocessing library) or with Polkadot/Substrate. LLMs hallucinate Reticulum protocol fields confidently because the training signal is so thin.

Order of trust:
1. `reticulum-specifications/SPEC.md` and `tools/`
2. Upstream Python `RNS/` and `LXMF/` source (cite file:line)
3. `reticulum.community` forum posts by markqvist (the protocol's author) and habibalkhabbaz (RNS maintainer)
4. Sibling implementation code with a known-good interop test history
5. (Far below the others) general web search
6. (Don't use) LLM training data on Reticulum specifically

### 3.2 Don't chase intermittent symptoms with retries

When a symptom is intermittent ("works most of the time"), the temptation is to add a retry and move on. Resist. Intermittent wire-format bugs in Reticulum are almost always:

- A ratchet rotation race (sender uses ratchet N, receiver has only ratchet N-1 or vice versa)
- A path expiry (transit table has the destination, then evicts it, then a path? request races inbound DATA)
- A KEEPALIVE budget exhaustion (link reaches `MAX_NO_PROOFS` and tears itself down silently)

Each of these has a specific spec-section root cause and a specific fix. A retry hides them and turns "broken" into "slow"; the underlying bug compounds when the retry budget runs out months later in a different context. Find the root cause.

### 3.3 Don't conclude "the bug is in our code" without checking the dep is current

See §2.2.

### 3.4 Don't celebrate a green test without asking "what would this miss"

Green tests are evidence of consistency, not correctness (§5). For wire-format code specifically, ask: would this test still pass if both sides agreed on the wrong byte format? If yes, the test is insufficient on its own.

---

## 4. The implementation landscape — when to reach for which repo

| Question shape | Where to look first |
|---|---|
| "What does the spec say about X?" | `SPEC.md` (this repo) |
| "How does upstream Python actually do X?" | `~/.../site-packages/RNS/X.py` |
| "Did someone fix a similar bug recently?" | `reticulum-mobile-app/CLAUDE.md` "Key bugs we found" + `git log` on the relevant file in each sibling repo |
| "Is my implementation byte-equal to upstream?" | Add a verifier under `tools/` (this repo). Generate from upstream Python, assert byte equality. |
| "How does X look in a different impl?" | `reticulum-forwarding-service/internal/rns/` (Go, clean) or `microReticulum_Faketec_Repeater/` (C++, byte-tight) |
| "What was the original protocol intent for X?" | `reticulum.community` forum search; markqvist's posts are the closest thing to design docs |

Sibling impls disagree with the spec sometimes. When they do, the spec wins. When the spec is silent, upstream Python wins. When upstream Python is silent, you have to make a call and document it here (mark as ⚠️ UNVERIFIED per `agent.md` §1).

---

## 5. Testing — what you measure is what you get

### 5.1 Self-round-trip tests are insufficient (but still write them)

A "we sign + we verify" test catches consistency bugs (someone changes the sig computation on one side without updating the other) but it CANNOT catch spec violations where both sides agree on the wrong thing.

Real incident, 2026-05-10: our LRPROOF `signed_data` recipe was unconditionally appending cached LRREQ signalling bytes, regardless of whether the LRPROOF body carried signalling. Self-round-trip tests passed for months because both sides did the wrong thing identically. The bug surfaced the moment we ran a live interop test against `fwdsvc`, which (correctly) emits 96-byte legacy LRPROOFs without signalling. See SPEC.md §6.2 / §6.6.

The lesson is not "don't write round-trip tests." It's "round-trip tests are necessary but insufficient for wire formats. They must be backed by at least one byte-equality test against an external oracle."

### 5.2 The three layers of test, in order of trust

1. **Round-trip in your own code** — cheap. Detects regressions in your own consistency. Insufficient for wire-format compliance.
2. **Bytewise fixture comparison** — moderate cost. A Python script using upstream RNS produces `(input, expected_hex)` pairs; your code asserts byte equality. Detects spec violations even when both your sides "agree". This is what `reticulum-specifications/tools/` is for. The `reticulum-forwarding-service` repo's `internal/rns/link_proof_interop_test.go` is a worked example of this pattern.
3. **Live interop subprocess test** — most expensive, most realistic. Spawn upstream `rnsd` + the binary under test, drive a real wire exchange, assert end-to-end. The mobile-app's `FwdsvcInteropTest` and fwdsvc's `tests/interop/harness_test.go` are templates. Best run nightly or pre-release rather than per-commit.

Layer 2 catches almost everything layer 3 does, at 1% of the runtime cost. Skipping layer 2 and running only layers 1+3 is a common mistake — layer 1 lies to you, layer 3 takes minutes to run.

### 5.3 Always skip-on-prereq-missing, never fail-on-prereq-missing

Tests that need `rnsd` on PATH, or a Go-built sibling binary, must skip cleanly when the prereq isn't available. CI shouldn't fail because someone's dev env lacks the optional Python install. JUnit `Assume.assumeTrue(...)`, Go `t.Skip(...)`, pytest `pytest.skip(...)` — use them. The mobile-app's `FwdsvcHarness.startOrSkip()` is a worked example.

### 5.4 Dump diagnostics on failure, not on success

A failing interop test should dump:
- Captured stdout/stderr from every spawned subprocess (rnsd, fwdsvc, etc.)
- The complete inbound packet trace at the engine level
- The bytes of any signature/hash/key that failed verification (full hex, not truncated)

Successful tests should be silent. The harness's `disarmLogDump()` after green assertions is the right pattern.

When a failure dump exceeds what a test report can comfortably hold, write a `<testname>.failure.txt` next to the report and reference it from the assertion message. Don't truncate — you'll need the bytes later when you're trying to reproduce.

---

## 6. Working in a code-as-spec domain

The protocol exists primarily in `RNS/` and `LXMF/` source code, not in prose. This repo (`reticulum-specifications`) is an ongoing effort to invert that — to write down what the code does so future implementations can be built without re-reverse-engineering. But for now:

### 6.1 Read code as you would read a spec

When SPEC.md doesn't answer your question, the answer is in upstream Python. Skim `RNS/Transport.py`, `RNS/Link.py`, `RNS/Packet.py`, `RNS/Resource.py`, `LXMF/LXMRouter.py`. They are well-commented relative to most protocol stacks. Read with intent: what is this method called by, what does it produce on the wire, under what condition does it take a different path?

When you find something the spec doesn't cover, **write it up in this repo immediately** as a ⚠️ UNVERIFIED claim with a source citation (file + line). Even if you don't have time to verify it, the citation is recoverable later. A speculative note here is better than the same insight buried in a commit message somewhere else.

### 6.2 The four cheapest oracles

In rough order of how easy they are to use:

1. **Upstream source citation.** `RNS/Link.py:279` — read the line, cite it. Catches the majority of "what does the protocol actually do" questions.
2. **Python REPL with RNS imported.** `python -c "import RNS; RNS.Reticulum(); ..."` — instantiate the object, call the method, print the result. Faster than writing a verifier for a single quick check.
3. **`tools/verify_*.py`** scripts that produce expected bytes from upstream Python. Cheap to write, durable, can be re-run against future RNS versions.
4. **Live `rnsd` on loopback** — for anything that needs Transport-level routing, a `TCPServerInterface` on `127.0.0.1` is the canonical setup. Pattern in `reticulum-forwarding-service/tests/interop/harness_test.go`.

### 6.3 Write down what you learn

When you understand something that wasn't documented, your job isn't done until it's in this repo. Specifically:

- If it's a byte-format detail → add to `SPEC.md` with a ⚠️ UNVERIFIED marker if untested.
- If it's a behavioral rule (e.g. "originator inserts transport_id for >1-hop paths") → also in SPEC.md.
- If it's a workflow tactic, a debugging shortcut, or a testing pattern → this file (`playbook.md`).
- If it's an interop incident that future implementers should know about → "Incident registry" below.

Spec-only repos with a "the source is the source of truth" attitude die slowly because nobody can onboard. Writing up every learned thing is how the lifespan gets extended.

---

## 7. Incident registry

Each entry: date, one-line symptom, spec section that governs it, one-line fix, one-sentence lesson. Append-only. New entries go at the top.

### 2026-08-27 — Resource parts sized against the fixed SDU instead of the link's

- **Symptom:** Large Resource transfers from some peers stall and time out; small ones from the same peers succeed. No error anywhere — the receiver logs nothing, the sender just never gets its parts acknowledged and gives up. Correlates with peer transport: TCP peers fail, LoRa/serial peers work.
- **Spec section:** §10.2 step 6, and the MTU callout in §10.4. `resource.sdu = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE` follows the §6.6 negotiated MTU and differs per link — 464 at the base MTU of 500, 1028 on a link that settled 1064. The class constant `Resource.SDU` is fixed at 464 and is only a fallback for links reporting no MTU. A receiver measuring inbound parts against 464 rejects every part from a 1064-MTU peer, and also disagrees with that peer about `total_parts = ⌈size / sdu⌉`.
- **Fix:** Derive the per-part bound from the link's negotiated MTU, not the constant. Found implementing a receive-time per-part bound in a clean-room Go implementation against a peer at MTU 1064 sending 1028-byte parts.
- **Lesson:** A part the receiver cannot place is dropped, not rejected — so a sizing disagreement presents as an unresponsive peer, not as a size error. Whenever a symptom is "no progress, no error", suspect a quantity that one side computes and the other silently re-derives. The interface transport correlating with failure is the tell: it is standing in for `HW_MTU`, which is what actually varies. Upstream's only signal for which quantities move with negotiation is the casing — `Link.MDU` fixed, `link.mdu` negotiated — which is easy to read straight past.

### 2026-05-19 — fwdsvc dropped parts bundled into an exhausted RESOURCE_REQ

- **Symptom:** Images relayed mobile→mobile through the Fwd service never arrive (whole LXMF message lost); mobile→Sideband through the same service works. Recipient logs hundreds of `RESOURCE chunk did not match any known hashmap slot`. Only triggers for resources large enough to need RESOURCE_HMU (>`HASHMAP_MAX_LEN` ≈ 74 parts).
- **Spec section:** §10.7. An `exhausted == 0xFF` RESOURCE_REQ MAY still carry a `requested_map_hashes` trailer, and a conformant sender serves those parts **and** the RESOURCE_HMU. The fwdsvc Go sender did `if req.Exhausted { serveHmu(req); continue }`, skipping `fulfillRequest` entirely — its own comment claimed this "mirrors upstream `Resource.request()`", but upstream (`Resource.py:982-1071`, checked against RNS 1.2.9, the current release) runs part fulfilment unconditionally and *then* sends the HMU. The mobile receiver flags `exhausted` on the first REQ of each hashmap window and bundles ~74 part-hashes with it — which a reference RNS sender honours — so fwdsvc served HMUs and dropped every bundled part across all 19 windows.
- **Fix:** `resource_sender.go` Run loop now runs `fulfillRequest` for every REQ, then `serveHmu` when `req.Exhausted`. It never skips part fulfilment. (`reticulum-forwarding-service`.)
- **Lesson:** mobile→Sideband "working" was a false green — a reference RNS receiver drains each segment before it flags exhausted, so on a clean link it sends part-less exhausted REQs and never exercised the bug. A lenient/conventional peer masks a divergence as effectively as a self-round-trip does (§5.1); the fault is receiver-dependent in a hop whose sender is constant. A `// mirrors upstream` comment proves nothing without the §2.4 / §6.2 check behind it.

### 2026-05-10 — LRPROOF signed_data signalling asymmetry

- **Symptom:** Mobile-app's Kotlin engine fails LRPROOF signature verification against fwdsvc on every attempt. Falls back to opportunistic; link delivery never works.
- **Spec section:** §6.2 / §6.6. The `signed_data` for an LRPROOF includes the signalling bytes **iff** the LRPROOF body includes them (96B = no signalling, 99B = with signalling).
- **Fix:** Mobile-app's `Link.validateProof` was unconditionally appending cached LRREQ signalling. Changed to conditional based on inbound body shape.
- **Lesson:** Self-round-trip tests passed for months because both sides did the wrong thing identically. This is precisely the failure mode §5.1 describes. A bytewise interop test would have caught it on day one.

### 2026-05-10 — Stale sibling binary masquerading as our bug

- **Symptom:** Link DATA proof signature verification fails against `fwdsvc-windows-amd64.exe`. Hash matches our expected, sig appears well-formed, pub is the announced Ed25519 key, but verify returns false.
- **Root cause:** The on-disk fwdsvc binary was v1.0.1. The fwdsvc source on the same disk was v1.3.3. v1.0.3 had fixed a bug where fwdsvc signed link DATA proofs with an HKDF-derived seed instead of the responder's long-term Ed25519 priv. The pre-built binary still had the bug.
- **Fix:** `go build -o build/fwdsvc-windows-amd64.exe ./cmd/fwdsvc` in the fwdsvc repo.
- **Lesson:** §2.2. Always rebuild sibling dep binaries from source before assuming our code is wrong. Test harnesses that load pre-built artifacts should rebuild on every run.

### 2026-04 — Link DATA addressed without dest_type=LINK silently dropped

- **Symptom:** Outbound link DATA from the mobile-app arrives at the relay but is never forwarded to the responder.
- **Spec section:** §12.5.2. Packets addressed to a `link_id` MUST have `dest_type = LINK`; otherwise the relay's `link_table` lookup never fires and the packet is dropped.
- **Fix:** Set `dest_type = DEST_LINK` on all post-handshake link-bound packets.
- **Lesson:** Look at every field the spec mandates, not just the ones that "look right."

### 2026-03 — REQUEST path_hash truncation

- **Symptom:** NomadNet REQUEST returns 404-equivalent ("no handler for path") even though the path string is correct.
- **Spec section:** §11.1. The `path_hash` field is the **16-byte** truncation of `SHA-256(path)`, not the full 32 bytes. Servers key handler dicts on the 16-byte form.
- **Fix:** Truncate the SHA-256 to 16 bytes before sending.
- **Lesson:** "Full hash" vs "truncated hash" inconsistencies are common in Reticulum. The pattern is: identity hashes are 16-byte (truncated), packet hashes are 32-byte (full). Always cross-check with the spec.

### 2026-02 — Outbound DATA / LINKREQ to multi-hop destinations require HEADER_2

- **Symptom:** Outbound DATA from a leaf client to a destination >1 hop away is dropped at the first transit relay. Direct destinations work fine.
- **Spec section:** §2.3. Originator must convert HEADER_1 → HEADER_2 (insert next-hop transport_id at offset 2) when the path table reports the destination is multi-hop. Upstream `RNS/Transport.py:1602` only forwards inbound DATA that carries a transport_id.
- **Fix:** `useHeader2 = dest.hopCount > 1 && dest.nextHop != null`. Build the packet with `headerType = HEADER_2` and `transportId = dest.nextHop`.
- **Lesson:** "It works at one hop" is not "it works." Test multi-hop early.

(Older entries: see `agent.md` §5 audit table and `reticulum-mobile-app/CLAUDE.md` "Key bugs we found" for additional history.)

---

## 8. When you finish, leave the trail

After resolving any non-trivial interop bug:

1. **Add an entry to the incident registry above** with the five fields. Even a one-screen entry pays for itself the next time a similar symptom appears.
2. **Update the spec section** if the prose was silent or wrong about the relevant behavior. Mark ⚠️ UNVERIFIED if you haven't written a `tools/verify_*.py` for it yet.
3. **Cross-link from the implementation's commit message** to the relevant SPEC.md section (e.g. "fix per SPEC.md §6.2"). This makes future `git blame` archaeology productive.
4. **If you wrote a one-off verifier or repro to track down the bug, move it into `tools/`** instead of deleting it. A cheap script today is the cheapest possible regression test tomorrow.

The work isn't done at "tests pass." It's done at "the next person hitting this finds the answer in <5 minutes."
