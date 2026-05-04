# Verifier scripts

Self-contained Python scripts that test claims in [`../SPEC.md`](../SPEC.md) against the upstream RNS / LXMF Python stack.

## Conventions

- Each script verifies one claim or one related cluster of claims.
- Exit code 0 on PASS, non-zero on FAIL.
- Print a one-line PASS/FAIL summary plus a unified diff or hex dump on mismatch.
- Reference the SPEC.md section the script verifies in a docstring at the top.

## Required environment

```
pip install rns lxmf
```

The scripts read `RNS.__version__` at startup and print it in their output so a future reader can tell which RNS version a verification ran against.

## Status

Populated against RNS 1.2.0 / LXMF 0.9.6:

| Script | Verifies SPEC.md section | Status |
|---|---|---|
| `verify_destination_hash.py` | §1.1, §1.2, §1.3 — identity composition, `dest_hash = SHA256(name_hash \|\| identity_hash)[:16]`, on-disk private-key round-trip via `to_file`/`from_file` | ✅ |
| `verify_packet_header.py` | §2.1, §2.2, §2.3 — flag byte layout, HEADER_1/HEADER_2 form, originator HEADER_1→HEADER_2 conversion via upstream `Transport.outbound` | ✅ |
| `verify_token_crypto.py` | §3 — Token encrypt/decrypt, HKDF salt = identity_hash, HMAC-then-AES order, PKCS#7 padding | ✅ |
| `verify_announce_app_data.py` | §4.3 — LXMF announce app_data 2-element form, parser tolerance | ✅ |
| `verify_announce_roundtrip.py` | §4.1, §4.2, §4.5 — announce body layout, signature, dest_hash recompute, tamper rejection | ✅ |
| `verify_lxmf_opportunistic.py` | §5.1, §5.2, §5.5, §5.6 — full identity → encrypt → decrypt → parse round-trip | ✅ |
| `verify_proof_packet.py` | §6.5 — implicit (64B) and explicit (96B) proof body forms, validator length-dispatch | ✅ |
| `verify_link_handshake.py` | §6.1, §6.2, §6.3, §6.6 — LINKREQUEST/LRPROOF body order, link_id derivation, signalling | ✅ |
| `verify_path_request.py` | §1.2 well-known hashes, §7.1 LXMF path-preamble gating | ✅ |
| `verify_rnode_split.py` | §8.3 — RNode air-frame split-packet TX/RX state machines | ✅ |
| `verify_msgpack_quirk.py` | §9.3 — encoding name as bytes vs str affects upstream parsing | ✅ |
| `verify_stamps.py` | §5.7 — workblock determinism, PoW stamp search/validate, ticket shortcut | ✅ |
| `verify_ratchet_dedup.py` | §7.3 / §4.5 step 6.3 — confirms replay defence is keyed on `random_blob`, NOT on `(dest_hash, ratchet_pub)` | ✅ |
| `regen_identities.py` | regenerates `test-vectors/identities.json` | ✅ |

See [`../agent.md`](../agent.md) §5 and [`../todo.md`](../todo.md) for the remaining priority order.
