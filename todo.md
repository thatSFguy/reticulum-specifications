# TODO

Outstanding work for the spec repo.

## Outreach

- [ ] **File a community-documentation issue on `markqvist/Reticulum`.**
      Link this repo as a community-maintained byte-level spec. Ask
      whether the maintainer would like to bless / link from the
      official Reticulum manual. Frame it as a complement to (not a
      replacement for) the existing operator-focused docs.

- [ ] **File a `random_hash` interop issue on `attermann/microReticulum`.**
      `src/Destination.cpp:270-272` emits 10 fully-random bytes
      where upstream Python emits 5 random + 5 BE-uint40 unix_seconds
      (§4.1, §9.10). Effect: Python RNS path-table replacement
      `RNS/Transport.py:1721-1745` rejects fresh announces from
      Python sources as "stale" once a microReticulum announce has
      populated the random_blob set, because the random tail is
      interpreted as a far-future timestamp. Workaround documented
      in §9.10; the durable fix is implementing the TODO comment in
      the upstream source — even seconds-since-boot is preferable
      to random bytes since path-table comparisons care about
      ordering, not absolute time.

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

- [ ] **`tools/verify_proof_packet.py` to lock in §6.5.** Run two
      side-by-side scenarios against upstream RNS: opportunistic DATA
      with `use_implicit_proof = True` (default) and with `= False`,
      capture the resulting PROOF packet's body length, and assert
      it's 64 / 96 respectively with the matching content layout.
      Also exercise a Link DATA proof and confirm it's always 96B
      regardless of the config setting. Lock in the §6.5 wire shapes.

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

## Spec gaps for a functional client (priority-ordered)

The items below are missing pieces that prevent a client built only from
this spec (plus the existing flows/) from interoperating with upstream.
Tier 1 = required to talk at all to the mesh as a leaf LXMF client.
Tier 2 = required for a client that's actually useful (chat that works
in the wild). Tier 3 = required to act as a transport node / relay.

Where I've already done the source reading, I've left the file/line
citations inline so whoever picks the item up can start without
re-research.

### Tier 1 — required for a barebones leaf LXMF client to interop

- [x] **`flows/receive-announce.md` + SPEC.md §4.5 announce validation
      rules.** Done. SPEC.md §4.5 covers the MUST validation rules
      (body parse with `context_flag` branch, signed_data
      reconstruction, signature verification, dest_hash recomputation,
      public-key collision rejection, blackhole list, cache update
      order, PATH_RESPONSE handling). `flows/receive-announce.md` walks
      the chronology end-to-end. Side fixes: SPEC.md §4.1 corrected
      (`random_hash` is 5 random bytes + 5 bytes big-endian uint40
      unix_seconds, not 10 random bytes); SPEC.md §2.5 contexts table
      now lists `0x0B PATH_RESPONSE`.
- [x] **SPEC.md §10 / `flows/send-resource.md`: Reticulum Resource
      fragmentation.** Done. SPEC.md §10 covers the wire-level MUST
      rules: 13 sub-sections from "when Resource runs" through wire
      contexts (ADV / REQ / RESOURCE / HMU / PRF / ICL / RCL),
      hashmap collision-guard, sliding window, multi-segment cutover
      at MAX_EFFICIENT_SIZE = 1 MiB - 1, and the encryption-then-split
      layering. `flows/send-resource.md` walks the chronology in 10
      steps with a wire-byte ladder diagram. Side fixes during the
      drafting: SPEC.md §2.5 contexts table now lists ALL upstream
      contexts (was missing all RESOURCE_*, REQUEST/RESPONSE,
      COMMAND, CHANNEL, LINKIDENTIFY, LINKCLOSE, LRRTT entries) and
      corrects KEEPALIVE from 0xFD (which is actually LINKPROOF) to
      0xFA per `RNS/Packet.py:87`. SPEC.md §6.5 wording updated to
      use the correct LINKPROOF context name. The previously-existing
      §10 "Test vectors" and §11 "Source map" were renumbered to §11
      and §12 to put §10 in the protocol-stack flow.
- [x] **SPEC.md §6.5 expansion: regular (non-LRPROOF) PROOF body.**
      Done. SPEC.md §6.5 now has six sub-sections covering explicit
      (96B `packet_hash || signature`) vs implicit (64B
      `signature`-only) forms, the upstream default
      (`Reticulum.__use_implicit_proof = True` per
      `RNS/Reticulum.py:259` — opportunistic DATA proofs default to
      the implicit form on the wire), the Link DATA proof exception
      (always explicit per `RNS/Link.py:383-394`), the
      length-dispatch receiver-side, where the proof packet is
      addressed (`packet_hash[:16]` as a synthetic ProofDestination
      vs `link.link_id` for Link proofs), wire-byte ladders for both
      forms. The previously-misleading SPEC §2.5 entry for
      `LINKPROOF (0xFD)` is corrected — it's a defined-but-unused
      constant in RNS 1.2.0; the actual proof packets carry
      `context = NONE (0x00)`. todo for `tools/verify_proof_packet.py`
      moves to "needs a runtime verifier" section.
- [x] **SPEC.md §6 sub-section: 3-byte MTU/mode signalling field.**
      Done. SPEC.md §6.6 covers the full 24-bit packed format
      (3-bit mode in the top of byte 0, 21-bit MTU in the low 21
      bits), the encode/decode primitives, the seven defined modes
      (only `MODE_AES256_CBC = 0x01` is enabled in RNS 1.2.0; six
      others are reserved for AES-128, AES-256-GCM, OTP, and the
      post-quantum migration), the responder-side MTU clamp
      mechanism (an in-place rewrite of the LINKREQUEST data buffer
      so the LRPROOF signed_data carries the clamped value but the
      link_id stays invariant), the length-only presence detection,
      and the inclusion-in-signed_data trap that breaks link
      handshakes when one side emits signalling and the other
      doesn't. §6.1 and §6.2 inline references updated to point at
      §6.6 for the bit layout. Existing §6.6 "Source" renamed to §6.7.
- [x] **SPEC.md §7.2 expansion + new flow `flows/path-discovery.md`:
      path-response announce vs periodic announce.** Done. SPEC.md
      §7.2 now has six sub-sections: parse rules for the path-request
      packet, tag-based dedup via `discovery_pr_tags`, the five-way
      dispatch in `Transport.path_request` (local responder /
      transit-knows-path / local-client-forward / discovery-recursive
      / drop), the path-response announce wire format (regular
      announce body + `context = PATH_RESPONSE = 0x0B`), the
      `PR_TAG_WINDOW = 30s` body-cache mechanism that lets multiple
      relays receive the same wire bytes for dedup convergence,
      timing rules (`PATH_REQUEST_GRACE = 0.4s` + `PATH_REQUEST_RG =
      1.5s` for roaming-mode), and a minimum-leaf-responsibility
      summary. `flows/path-discovery.md` walks the 9-step chronology
      with two wire-byte ladders (single-hop leaf-owns-target and
      two-hop transit-relay-knows-path).
- [x] **SPEC.md §1.3 expansion: identity on-disk format.** Done — and
      the previous wording was actually wrong about the byte order!
      Empirically verified by reading `Identity.get_private_key()` at
      `RNS/Identity.py:694-698` and `load_private_key` at line 706-717,
      then round-tripping `to_file(path)` and reading back the bytes
      against `test-vectors/identities.json`: the on-disk order is
      X25519_priv(32) || Ed25519_priv(32), **same** as the public_key
      concatenation, NOT opposite as the previous spec text claimed.
      Implementations following the prior wording would have corrupted
      identity files when interoperating with upstream Python RNS.
      §1.3 now covers: 64-byte raw blob with no header/version/checksum/
      encryption; the from_bytes HAZARD note (raw random bytes skip the
      `cryptography` library's keypair invariants); cross-implementation
      portability is automatic since there's nothing in the file but
      the bytes; a ⚠️ "Spec correction" callout warning future readers
      that prior revisions had this wrong. `tools/verify_destination_hash.py`
      gets a new §1.3 round-trip section that writes via `to_file`,
      reads back, asserts the byte slice matches the test vector, and
      reloads via `from_file` to confirm identity_hash invariance.

### Tier 2 — required for a client to be useful in the wild

- [ ] **SPEC.md: Propagation node protocol.** Offline message retrieval
      via store-and-forward propagation nodes. Without this, every
      message requires both peers online simultaneously. Authoritative
      source: `LXMF/LXMRouter.py::process_propagated`, the
      `lxmf.propagation` peering exchange (`peer()` / `sync()` between
      nodes — `LXMRouter.py:1892+, 2118+`). The `propagated` method is
      already in `LXMessage.py` but the wire protocol between
      propagation nodes is undocumented. Cross-flow:
      `flows/send-propagated-lxmf.md` (already a `⏳` entry in
      `flows/README.md`).
- [x] **SPEC.md §6 expansion: KEEPALIVE / link teardown protocol.**
      Done in §6.7 (old §6.7 Source moved to §6.8). Five
      sub-sections: KEEPALIVE wire form (`0xFA` context, initiator-
      originated `0xFF` ping → responder `0xFE` pong, body
      Token-encrypted), cadence (`RTT × 205.7` clamped to `[5,360]s`),
      STALE→CLOSED watchdog transitions, LINKCLOSE wire form
      (`0xFC` context, body = 16-byte `link_id` Token-encrypted with
      `plaintext == link_id` auth check), teardown reason codes
      (`TIMEOUT/INITIATOR_CLOSED/DESTINATION_CLOSED`), and the
      six-step minimum-receiver-responsibility recipe.
- [ ] **SPEC.md §5.x (new): LXMF stamps + tickets for spam control.**
      `LXMF.Stamp` (proof-of-work field in the optional 5th element of
      the msgpack payload), `FIELD_TICKET` lookup. Modern Sideband 1.x
      treats missing-stamp messages as spam in the UI. Spec currently
      doesn't mention stamps at all. Authoritative source:
      `LXMF/LXMessage.py::validate_stamp`, `LXMF/LXMRouter.py:1741-1774`
      (the stamp-check branch in `lxmf_delivery`).
- [ ] **SPEC.md §13 (new): NomadNet page protocol.** Distinct from
      LXMF — pages fetched over a Link with `context = CTX_REQUEST (0x09)`
      / `CTX_RESPONSE (0x0a)` (already in §2.5 contexts table). Request
      body is a path string + field map; response is a body bytes blob.
      Without this, a client can do LXMF chat but can't render NomadNet
      content (nodes serving content, telemetry, micron pages).
- [ ] **SPEC.md §1.4 (new): GROUP destinations.** `RNS.Destination.GROUP`
      type uses symmetric AES-256-CBC with a pre-shared key; different
      encrypt/decrypt paths in `RNS/Destination.py:601+` (`prv` is a
      symmetric-key wrapper, not an X25519 priv). Almost no clients
      implement this but the protocol allows it.
- [ ] **SPEC.md §8.4 (new): CSMA / airtime tracking.** LoRa-only —
      carrier-sense + random backoff that prevents transmitter
      collisions on shared channel. The clean-room repeater explicitly
      flags "no CSMA" as a phase-2 simplification. A serious LoRa
      client needs `RNS.Reticulum.ANNOUNCE_CAP`-aware backoff and the
      `airtime_bins` accounting from `RNode_Firmware.ino:683-712`.
- [ ] **SPEC.md §8.5 (new): RNode KISS configuration handshake.**
      Beyond §8.3 (split-packet protocol), a client opening an RNode
      drives `CMD_DETECT` / `CMD_FREQUENCY` / `CMD_BANDWIDTH` /
      `CMD_SF` / `CMD_CR` / `CMD_TXPOWER` / `CMD_RADIO_STATE` over KISS
      to bring up the radio. All defined in `RNode_Firmware/Framing.h:24-95`.
      Spec just says "send Reticulum packets via CMD_DATA" — that's
      not enough.
- [x] **SPEC.md §6.5 second sub-bullet: implicit vs explicit proof
      mode.** Done as part of the §6.5 expansion (Tier 1 #3). The
      length-dispatch validator at `PacketReceipt.validate_proof`
      and the `should_use_implicit_proof()` config switch are
      documented in §6.5.1-§6.5.2 with full citations.

### Tier 3 — required to act as a transport node / relay

- [ ] **SPEC.md §7.7 (new): DATA forwarding rules.** Forwarding non-
      local DATA per `path_table[dest][NEXT_HOP]`, with hop increment,
      MTU-fit check, blackhole avoidance, and IFAC re-signing.
      Currently mentioned only obliquely in §2.3 / §7.6. The full
      forwarding logic is the bulk of `RNS/Transport.py::inbound`'s
      ~800-line dispatch table at lines 1499-1620. The repeater repo
      patches microReticulum to enable this — see commit
      `Add DATA and PROOF forwarding patches for transport repeating`.
- [ ] **SPEC.md §4.6 (new): ANNOUNCE rebroadcasting.** Including the
      announce-cap (`RNS.Reticulum.ANNOUNCE_CAP`, default 2% airtime),
      the announce queue, the `path_responses` cache, and the
      `random_blob` history that lets a relay drop replays. Most of
      `RNS/Transport.py:1196-1300, 1810-1969`.
- [ ] **SPEC.md §7.8 (new): path table management.** TTL-based expiry
      (`Transport.AP_PATH_TIME`, `ROAMING_PATH_TIME`, `DESTINATION_TIMEOUT`),
      eviction on stale-link, persistence-across-reboot file format.
      Hooks: `RNS/Transport.py:747-769` (stale_paths accumulator) and
      the `paths` file under `storagepath`.
- [ ] **SPEC.md §7.9 (new): tunnels and shared-instance protocol.**
      `tunnels`, `discovery_path_requests`, `RNS/Reticulum.py::is_connected_to_shared_instance`
      — how a process talks to a co-resident `rnsd`. Spec's §7.6
      covers one symptom (TCP OUT default) but not the actual
      shared-instance wire format.
- [ ] **SPEC.md §6.x (new): reverse table + link transport.** When a
      Link's path crosses a relay, the relay must forward both
      directions of every Link DATA + PROOF using
      `Transport.reverse_table` (`RNS/Transport.py:2087-2204`).
      Distinct from path-table forwarding — different lookup, different
      lifecycle.

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
