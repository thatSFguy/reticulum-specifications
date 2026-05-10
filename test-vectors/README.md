# Test vectors

Known-good byte sequences that any Reticulum-compatible implementation should be able to round-trip in both directions.

## Status

Populated against RNS 1.2.4 / LXMF 0.9.7:

- ✅ `identities.json` — Alice + Bob identity vectors (regenerator: `../tools/regen_identities.py`, verifier: `../tools/verify_destination_hash.py`).
- ✅ `announces.json` — two announce vectors (no-ratchet + with-ratchet) signed by Alice (regenerator: `../tools/regen_announces.py`, verifier: `../tools/verify_announce_roundtrip.py`).
- ✅ `lxmf.json` — two opportunistic-LXMF vectors Alice → Bob (regenerator: `../tools/regen_lxmf.py`, verifier: `../tools/verify_lxmf_opportunistic.py`).
- ✅ `links.json` — full Link handshake vector (LINKREQUEST + LRPROOF + derived session key) Alice → Bob, plus an LRRTT packet (§6.4.2) emitted from the initiator with pinned IV and `rtt_seconds = 0.05` (regenerator: `../tools/regen_links.py`, verifiers: `../tools/verify_link_handshake.py`, `../tools/verify_link_lrrtt.py`).

All four files are byte-deterministic across runs: regenerators pin every random source (ephemeral keys, IVs, `random_hash` prefix + timestamp, LXMF timestamp) so the output is reproducible against a fixed upstream RNS / LXMF version.

See [`../agent.md`](../agent.md) §5 and [`../todo.md`](../todo.md) for the remaining bootstrap task list.

## Format (proposed)

Each vector lives in a per-domain JSON file, e.g.:

- `identities.json` — Alice + Bob with `encPriv`, `sigPriv`, `ratchetPriv` (hex), plus the derived `publicKey`, `identityHash`, `destinationHash` for `lxmf.delivery`
- `announces.json` — full hex of a signed announce packet, plus the inputs that produced it (display_name, ratchetPub, etc.)
- `lxmf.json` — sender + recipient identity, plaintext, expected ciphertext bytes
- `links.json` — LINKREQUEST + LRPROOF + derived session keys

Each entry should include:

```json
{
  "description": "Alice's lxmf.delivery announce with ratchet, display_name='AliceTest'",
  "inputs": { ... },
  "expected_bytes_hex": "...",
  "rns_version_at_generation": "1.2.0",
  "generator_script": "tools/regen_announces.py"
}
```

The `generator_script` is the file in `../tools/` that, when run against upstream RNS, regenerates `expected_bytes_hex`. Keeping the generator alongside the vector lets a future contributor verify the vector still matches a newer upstream RNS.

## What needs to round-trip

For the spec to claim "an implementation that passes all test vectors interoperates with upstream", the vectors must cover:

1. **Identity construction** — given the same private-key inputs, derive the same public key, identity hash, destination hash.
2. **Announce build + parse** — build a signed announce; verify the same bytes come back through upstream's parser; verify upstream-built announces parse correctly.
3. **Token encrypt + decrypt** — bidirectional, with both ratchet and long-term keys.
4. **Opportunistic LXMF** — full plaintext → ciphertext → plaintext round-trip, signature valid both ways.
5. **Link handshake** — LINKREQUEST built by client A, LRPROOF computed by upstream as B, both arrive at the same `link_id` and session keys.
6. **Link-delivered LXMF** — body packed by client, decrypted + parsed by upstream.

A separate vector set for FAILURE cases is also useful: malformed announces, expired ratchets, mismatched signatures. An implementation should reject those as a regression-prevention measure.
