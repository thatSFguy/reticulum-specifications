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

Empty placeholder. See [`../agent.md`](../agent.md) §5 for the priority order.

Initial scripts to write:

| Script | Verifies SPEC.md section |
|---|---|
| `verify_destination_hash.py` | §1.2 — `dest_hash = SHA256(name_hash || identity_hash)[:16]` |
| `verify_packet_header.py` | §2.1, §2.2 — flag byte layout + HEADER_1/HEADER_2 round-trip |
| `verify_announce_roundtrip.py` | §4 — announce build matches upstream `Identity().announce()` bytes |
| `verify_token_crypto.py` | §3 — Token encrypt/decrypt against upstream `RNS.Cryptography.Token` |
| `verify_lxmf_opportunistic.py` | §5.1, §5.5 — opportunistic LXMF body bytes match upstream |
| `verify_link_handshake.py` | §6 — LINKREQUEST + LRPROOF + session key match upstream |
| `verify_path_request.py` | §7.1, §7.2 — path-request payload format |
| `verify_msgpack_quirk.py` | §9.3 — encoding name as bytes vs str affects upstream parsing |
