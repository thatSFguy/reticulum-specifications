# TODO

Outstanding work for the spec repo.

## Outreach

- [ ] **File a community-documentation issue on `markqvist/Reticulum`.**
      Link this repo as a community-maintained byte-level spec. Ask
      whether the maintainer would like to bless / link from the
      official Reticulum manual. Frame it as a complement to (not a
      replacement for) the existing operator-focused docs.

## Test infrastructure

- [x] **Bootstrap `test-vectors/identities.json`** — Alice + Bob
      identities populated against RNS 1.2.0. Regenerator at
      `tools/regen_identities.py`.
- [ ] **Bootstrap remaining test-vectors files** (`announces.json`,
      `lxmf.json`, `links.json`) with the existing vectors from
      `reticulum-mobile-app/reference/test-vectors.json`. Convert to
      the proposed JSON format documented in `test-vectors/README.md`,
      adding the regenerator scripts so future contributors can
      verify vectors against newer upstream RNS releases.

- [ ] **Write the priority verifier scripts** listed in
      `tools/README.md`, in this order (highest interop value first):
      1. [x] `verify_destination_hash.py` — pure-function check, no RNS state needed
      2. [x] `verify_packet_header.py` — bit layout + HEADER_1/HEADER_2 round-trip + originator HEADER_1→HEADER_2 conversion
      3. [ ] `verify_announce_roundtrip.py` — closes the SPEC.md §4 gap (partial coverage in `verify_announce_app_data.py`)
      4. [ ] `verify_token_crypto.py` — closes SPEC.md §3 gap
      5. [ ] `verify_lxmf_opportunistic.py` — closes SPEC.md §5 gap
      6. [ ] `verify_link_handshake.py` — closes SPEC.md §6 gap
      7. [x] `verify_path_request.py` — closes SPEC.md §7.1, §7.2 gaps
      8. [ ] `verify_msgpack_quirk.py` — closes SPEC.md §9.3 gap

      Each verifier should remove its corresponding `⚠️ UNVERIFIED` /
      `🔮 SPECULATION` callout in `SPEC.md` (per `agent.md` §1).

## Open `⚠️ UNVERIFIED` items in SPEC.md

These need either a runtime test or a stronger upstream source citation
to remove their markers:

- [x] **§2.3 Originator HEADER_1 → HEADER_2 conversion.** Verified
      against RNS 1.2.0 by `tools/verify_packet_header.py`, which
      seeds `Transport.path_table` with a multi-hop entry and confirms
      the converted wire bytes via stubbed `Transport.transmit`.
      Citation updated to `RNS/Transport.py:1074-1083`.

- [x] **§4.3 The 3-element `[name, stamp_cost, [capabilities]]`
      app_data variant.** Verified against LXMF 0.9.6 by
      `tools/verify_announce_app_data.py`. Finding: in this LXMF
      version the producer emits a 2-element form only (the
      `supported_functionality` line at `LXMF/LXMRouter.py:999` is
      dead code); the parser is prepared for a 3-element form via
      `compression_support_from_app_data`. SPEC.md §4.3 updated to
      describe the actual current behavior.

- [x] **§7.1 path? always precedes LXMF DATA.** Verified against
      LXMF 0.9.6 by `tools/verify_path_request.py`. Finding: the
      preamble fires only when `not has_path()` AND method is
      OPPORTUNISTIC; the retry path can fire a second `request_path`
      after `MAX_PATHLESS_TRIES` (`LXMRouter.py:2571+`). SPEC.md §7.1
      rewritten accordingly. Also fixed a documentation bug in §1.2
      (path-request name_hash column).

- [x] **§7.4 Ratchet ring count default = 8.** False — actual upstream
      default is `Destination.RATCHET_COUNT = 512` at
      `RNS/Destination.py:85` in RNS 1.2.0, with
      `RATCHET_INTERVAL = 30*60` (line 90) and
      `RATCHET_EXPIRY = 60*60*24*30` (`RNS/Identity.py:69`).
      SPEC.md §7.4 corrected.

## Open `⚠️` items needing a runtime verifier

- [ ] **`tools/verify_rnode_split.py` to lock in §8.3.** The RNode
      air-frame split-packet protocol is now documented in SPEC.md §8.3
      against direct citations in `markqvist/RNode_Firmware/Framing.h`,
      `Config.h`, `Utilities.h`, and `RNode_Firmware.ino`, plus the
      clean-room reimplementation in `thatSFguy/reticulum-lora-repeater/src/Radio.cpp`.
      A runtime verifier would: build a 300-byte synthetic Reticulum
      packet, run it through a Python implementation of the TX-side
      header rules, and confirm the byte-level frames match what
      `RNode_Firmware.ino:716-742` would emit (header byte high nibble
      random + low-nibble FLAG_SPLIT bit, both frames sharing the same
      header, split point at 255 bytes total per LoRa frame). RX-side
      verifier should drive the state-table at SPEC.md §8.3 and confirm
      the four reassembly cases.

- [ ] **Lock in the §6.2 / §6.3 corrections with `verify_link_handshake.py`.**
      The wire-byte order of the LRPROOF body (`signature || responder_X25519_pub || signalling`,
      not `link_id || responder_X25519_pub || signature || signalling`) and
      the `link_id` derivation offsets (`N=2` for HEADER_1, `N=18` for HEADER_2,
      not 18/34) were corrected against direct upstream source citations
      (`RNS/Link.py:376`, `RNS/Packet.py:354-361`) in `SPEC.md` §6.2/§6.3
      while writing `flows/send-link-lxmf.md`. They are source-cited but
      not yet exercised by a runtime verifier. Add `tools/verify_link_handshake.py`
      that drives an upstream LINKREQUEST → LRPROOF → ACTIVE handshake and
      asserts byte-level layouts + `link_id` invariance under HEADER_1↔HEADER_2.

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
