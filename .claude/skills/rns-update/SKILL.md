---
name: rns-update
description: Check for new upstream RNS / LXMF releases, run the verifier suite, sample citation drift, and propose pin bumps. Read-only by default — applies edits only on user confirmation.
disable-model-invocation: true
allowed-tools:
  - Bash
  - Read
  - Edit
  - Grep
  - Glob
  - WebFetch
---

# rns-update

Skill for keeping `reticulum-specifications` aligned with upstream RNS / LXMF releases. Runs on demand; not scheduled.

## What this repo is (context for any future you)

This is a byte-level Reticulum/LXMF wire-format spec at `SPEC.md`, with runtime verifiers under `tools/` that lock the spec's claims against actually-installed upstream Python (`pip install rns lxmf`). The currently-pinned upstream version lives in `tools/requirements.txt`. The spec frontmatter and a handful of READMEs / docstrings name the same version label, so a pin bump is a multi-file edit.

**Upstream is in transition.** RNS 1.2.4 (May 2026) was announced as "probably the last release also published to GitHub" — pip continues "at least until `rnpkg` is complete and RNS is completely self-hosting." After that, **new RNS releases will only be available over the Reticulum network itself** (via `rngit` for source, `rnpkg` for packages). PyPI showing no newer version does NOT necessarily mean "no new releases" — it may mean upstream has fully migrated. The watch-list in `todo.md` ("Upstream distribution shift") is the migration plan; the skill below is the pre-migration tool. When pip-channel checks come up empty for a suspiciously long time (say, more than a couple of months), assume migration has happened and switch to the Reticulum-network path described in step 9.

## Steps

### 1. Read the current pin

Read `tools/requirements.txt`. Note the `rns==X.Y.Z` and `lxmf==A.B.C` lines.

### 2. Check upstream

Run these in parallel:

```bash
pip index versions rns  2>&1 | head -1
pip index versions lxmf 2>&1 | head -1
```

The first line of each output names the latest version, e.g. `rns (1.2.4)`. If `pip index` is unavailable on this system, fall back to `pip install rns== 2>&1 | head -1` which prints the available-versions list in its error message.

### 3. Decide whether to proceed

- **Both pinned versions already match latest on PyPI:**
  - Read the date of the latest PyPI release if you can (PyPI JSON: `https://pypi.org/pypi/rns/json`, look at `releases[<version>][0].upload_time`). If the most-recent PyPI upload is **more than ~60 days old**, that is suspicious given upstream's cadence and the "last GitHub release" announcement — surface this and skip ahead to step 9 (Reticulum-network path) before concluding "nothing to do".
  - Otherwise report `No new releases on PyPI — repo still aligned with rns==X.Y.Z / lxmf==A.B.C` and stop.
- **A newer version exists on PyPI:** continue with steps 4-8.

### 4. Surface release notes before upgrading

Use WebFetch to pull the GitHub release notes for the bumped package(s):

- `https://github.com/markqvist/Reticulum/releases/tag/<NEW_RNS_VERSION>`
- `https://github.com/markqvist/LXMF/releases/tag/<NEW_LXMF_VERSION>`

Scan for any of: `header`, `packet`, `IFAC`, `signing`, `signature`, `ratchet`, `link`, `resource`, `msgpack`, `wire`, `protocol`, `breaking`. Flag any matches as **possible spec impact** in your report — those phrases mean the verifier suite below is the load-bearing check.

If WebFetch fails (e.g. once upstream stops mirroring releases to GitHub), fall back to PyPI's release page: `https://pypi.org/project/rns/<NEW_RNS_VERSION>/`.

Show the user:

```
Current pin: rns 1.2.4 / lxmf 0.9.7
Latest:      rns X.Y.Z / lxmf A.B.C
Release-note phrases of interest: <flagged items, or "none">
Proceed with upgrade? (waiting for confirmation)
```

Wait for the user to confirm before running pip.

### 5. Upgrade and run the verifier suite

```bash
pip install --upgrade rns==<X.Y.Z> lxmf==<A.B.C>
```

Then run every verifier — they're independent and can run in parallel:

```bash
for f in tools/verify_*.py; do echo "=== $f ==="; python "$f" 2>&1 | tail -5; done
```

Collect PASS/FAIL per script.

- **Any FAIL:** stop. Report the failures with the offending verifier output. Tell the user this is a wire-format / behavior change that needs spec attention before the pin is bumped. Offer to spawn an Explore agent to identify what changed in upstream. Do **not** edit `tools/requirements.txt` or any version label.
- **All PASS:** continue.

### 6. Citation drift sanity check

Spot-check five anchor citations against the freshly-installed upstream source. Find the install path with `python -c "import RNS, os; print(os.path.dirname(RNS.__file__))"`. The anchors:

| Citation | Should still be |
|---|---|
| `RNS/Packet.py:246` | `self.header_type = (self.flags & 0b01000000) >> 6` |
| `RNS/Transport.py:994` | `def transmit(interface, raw):` |
| `RNS/Transport.py:1330` | `def inbound(raw, interface=None):` |
| `RNS/Identity.py:509` | `def validate_announce(packet, only_validate_signature=False):` |
| `RNS/Destination.py:282` | line constructing `random_hash` from `get_random_hash()[0:5]+int(time.time()).to_bytes(5, "big")` |

Use `Read` with `offset` / `limit` to peek at each line. Report which (if any) anchors have drifted.

- **No drift:** good signal. The pin bump is mechanical. Continue to step 7.
- **Drift detected:** the new version moved code around. The pin bump is mechanically still safe (verifiers passed) but the SPEC.md citations elsewhere likely need a re-anchor pass — *do not attempt this within the skill*. Tell the user a full re-anchor (similar in scope to commit `cfd0d82`) is recommended before bumping the pin, and offer to walk through it as a separate task.

### 7. Propose the pin bump (do NOT apply yet)

List the proposed edits to the user:

1. `tools/requirements.txt` — `rns==1.2.4` → `rns==<X.Y.Z>`, same for lxmf
2. `SPEC.md` — `**Last verified against:** \`RNS 1.2.4\` / \`LXMF 0.9.7\`` → bump
3. `tools/README.md` — `Populated against RNS 1.2.4 / LXMF 0.9.7:` → bump
4. `test-vectors/README.md` — same line, same bump
5. Verifier docstrings naming a specific RNS/LXMF version (grep for `RNS 1\.|LXMF 0\.` under `tools/`)

Show each as a unified diff. Ask the user to confirm.

### 8. Apply and report

On confirmation, apply the edits via `Edit`. **Do not commit** — leave the working tree dirty for the user to review and commit. Report:

- Verifier results (X passed, 0 failed)
- Drift status (none / which anchors moved)
- Files edited
- Suggested next step: `git diff` then commit when satisfied

### 9. Reticulum-network path (post-migration fallback)

This branch fires when PyPI looks frozen (latest upload ≫ 60 days old) or when the user explicitly says they want to pull from the Reticulum-network channel instead of pip. **Most of this is to-be-implemented** — the skill's job here is to stop guessing, surface what's true, and hand the user a checklist:

1. Confirm a local Reticulum node is running with internet reach (per `todo.md` watch-list item 1).
2. Check whether `rnpkg install` / `rnpkg upgrade` exist yet — try `rnpkg --help` and look for `install` / `upgrade` subcommands. As of RNS 1.2.4, `rnpkg` is a stub with only config / version flags. If those subcommands appear, that's the new canonical channel — bump the skill instructions when that lands.
3. If `rnpkg` is still a stub, fall back to `rngit`: the upstream Reticulum source repo will be published at a `rngit` destination hash. Look in `tools/sources.md` (file may not exist yet) for the recorded hash. If neither file nor hash exist, tell the user the migration prep work in `todo.md` ("Upstream distribution shift") needs to land first.
4. If a newer source tree is reachable, capture its version, do a manual `pip install -e <local-checkout>` against it, then re-enter step 5 (verifier suite).
5. **`rsg` signature verification:** once pulling outside PyPI, the source needs an `rsg` signature check before being trusted. The verifier for that doesn't exist yet (item 4 in the watch-list). Until it does, treat anything pulled this way as "promising but unverified" — note that explicitly in the report.

The point of this branch is to fail gracefully rather than pretend everything's fine when upstream has moved. Tell the user clearly: PyPI looks dormant, here's what we'd need to do to switch channels, here's what's not built yet.

### Skipping conditions

- If `tools/requirements.txt` is missing, this repo isn't ready for pinning yet — abort with a one-line note.
- If the `pip index` lookup fails AND PyPI is unreachable, abort with the network error (don't conclude migration — could just be a transient network problem).
- If the user declines at any confirmation prompt, exit cleanly without partial edits.

## What this skill does NOT do

- It does **not** auto-commit. The user does that.
- It does **not** do a full citation re-anchor pass. That's a much bigger surgical edit (see commit `cfd0d82` for what one looks like) and belongs to a separate session.
- It does **not** add `Spec corrections` entries in `README.md`. That section is reserved for cases where a previous spec revision was *wrong* — a routine pin bump doesn't qualify.
- It does **not** touch `flows/` files. Those have their own per-file version pins; updating them is part of the larger re-anchor pass, not a routine pin bump.
