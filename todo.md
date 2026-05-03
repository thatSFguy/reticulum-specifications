# TODO

Outstanding work for the spec repo.

## Outreach

- [ ] **File a community-documentation issue on `markqvist/Reticulum`.**
      Link this repo as a community-maintained byte-level spec. Ask
      whether the maintainer would like to bless / link from the
      official Reticulum manual. Frame it as a complement to (not a
      replacement for) the existing operator-focused docs.

## Test infrastructure

- [ ] **Bootstrap `test-vectors/`** with the existing vectors from
      `reticulum-mobile-app/reference/test-vectors.json`. Convert to
      the proposed JSON format documented in `test-vectors/README.md`,
      adding the regenerator scripts so future contributors can
      verify vectors against newer upstream RNS releases.

- [ ] **Write the priority verifier scripts** listed in
      `tools/README.md`, in this order (highest interop value first):
      1. `verify_destination_hash.py` — pure-function check, no RNS state needed
      2. `verify_packet_header.py` — bit layout + HEADER_1/HEADER_2 round-trip
      3. `verify_announce_roundtrip.py` — closes the SPEC.md §4 gap
      4. `verify_token_crypto.py` — closes SPEC.md §3 gap
      5. `verify_lxmf_opportunistic.py` — closes SPEC.md §5 gap
      6. `verify_link_handshake.py` — closes SPEC.md §6 gap
      7. `verify_path_request.py` — closes SPEC.md §7.1, §7.2 gaps
      8. `verify_msgpack_quirk.py` — closes SPEC.md §9.3 gap

      Each verifier should remove its corresponding `⚠️ UNVERIFIED` /
      `🔮 SPECULATION` callout in `SPEC.md` (per `agent.md` §1).

## Open `⚠️ UNVERIFIED` items in SPEC.md

These need either a runtime test or a stronger upstream source citation
to remove their markers:

- [ ] **§2.3 Originator HEADER_1 → HEADER_2 conversion.** Need a
      verifier that exercises `RNS.Transport.outbound` with a known
      multi-hop path table and shows the wire bytes change.

- [ ] **§4.3 The 3-element `[name, stamp_cost, [capabilities]]`
      app_data variant.** Need a captured upstream emission with the
      capabilities field present, ideally with `SF_COMPRESSION` set.

- [ ] **§7.1 path? always precedes LXMF DATA.** Verify whether peers
      ALWAYS issue path? before sending LXMF, or only when the path
      table entry is stale. Run a controlled test with a fresh path
      and a known-stale path.

- [ ] **§7.4 Ratchet ring count default = 8.** Find the upstream
      source citation (`RNS/Identity.py`, search for `RATCHET_COUNT`
      or similar). Update SPEC.md with the file + line, OR replace
      with the actual measured value if different.

## Spec polishing (lower priority)

- [ ] **Split `SPEC.md` into per-layer files** as the document grows
      past ~1500 lines. Suggested layout per `README.md`:
      `00-overview.md`, `01-packet-header.md`, `02-identity.md`,
      `03-announce.md`, `04-token-crypto.md`, `05-lxmf.md`,
      `06-link.md`, `07-resource.md`, `08-transport.md`,
      `09-paths-and-discovery.md`, `10-implementation-gotchas.md`.

- [ ] **Add a "last-verified-against-rns" line** to SPEC.md
      frontmatter (per `agent.md` §7) so readers know which RNS
      version the spec was tested against.

- [ ] **Document the Reticulum Resource fragmentation protocol** —
      currently absent from SPEC.md but needed for multi-packet LXMF
      over Link (NomadNet pages > 1 MTU, large file transfers).

- [ ] **Document the Propagation `/get` pull protocol** for offline
      message retrieval. Used by Sideband when peers are out of range.
