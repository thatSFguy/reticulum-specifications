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
- [x] **Bootstrap `test-vectors/announces.json`** — two vectors
      (no-ratchet + with-ratchet) signed by Alice. Regenerator at
      `tools/regen_announces.py` (deterministic via patched
      `Identity.get_random_hash` + module-local `time.time` shim).
- [x] **Bootstrap `test-vectors/lxmf.json`** — two opportunistic
      LXMF vectors Alice → Bob, full plaintext + Token-encrypted
      ciphertext. Regenerator at `tools/regen_lxmf.py` (deterministic
      via patched `LXMessage.timestamp`, ephemeral X25519, and
      Token CBC IV).
- [x] **Bootstrap `test-vectors/links.json`** — Link handshake
      vector with deterministic ephemerals. Regenerator at
      `tools/regen_links.py`. Records LINKREQUEST + LRPROOF wire
      bytes plus the derived session key both sides must agree on.

- [x] **Write the priority verifier scripts** listed in
      `tools/README.md` — all eight done plus three follow-ons
      (`verify_proof_packet.py`, `verify_rnode_split.py`,
      `verify_stamps.py`, `verify_ratchet_dedup.py`). Status table
      lives in `tools/README.md`.

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

- [x] **`tools/verify_proof_packet.py` locks in §6.5.** Done.
- [x] **`tools/verify_rnode_split.py` locks in §8.3.** Done.
- [x] **`tools/verify_link_handshake.py` locks in §6.2 / §6.3.** Done.

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

- [x] **SPEC.md §5.8: Propagation node protocol.** Offline message retrieval
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
- [x] **SPEC.md §5.x (new): LXMF stamps + tickets for spam control.**
      `LXMF.Stamp` (proof-of-work field in the optional 5th element of
      the msgpack payload), `FIELD_TICKET` lookup. Modern Sideband 1.x
      treats missing-stamp messages as spam in the UI. Spec currently
      doesn't mention stamps at all. Authoritative source:
      `LXMF/LXMessage.py::validate_stamp`, `LXMF/LXMRouter.py:1741-1774`
      (the stamp-check branch in `lxmf_delivery`).
- [x] **SPEC.md §11 (new): REQUEST/RESPONSE protocol covers NomadNet pages.** Distinct from
      LXMF — pages fetched over a Link with `context = CTX_REQUEST (0x09)`
      / `CTX_RESPONSE (0x0a)` (already in §2.5 contexts table). Request
      body is a path string + field map; response is a body bytes blob.
      Without this, a client can do LXMF chat but can't render NomadNet
      content (nodes serving content, telemetry, micron pages).
- [x] **SPEC.md §1.4 (new): GROUP destinations.** Done. Five
      sub-sections: key generation (`Token.generate_key()` 64-byte
      AES-256 default), wire format (Token form same as Link-derived
      `iv || ciphertext || hmac`, no eph_pub prefix because no ECDH),
      destination hash recipe with optional identity disambiguation,
      on-disk format (raw key bytes, no header/encryption/checksum),
      and a why-rarely-used note covering forward-secrecy gaps and
      key-distribution being unsolved at the protocol layer.
- [x] **SPEC.md §8.4 (new): RNode KISS configuration handshake.**
      Done. Full bring-up sequence: command-byte inventory, the
      `CMD_DETECT`/`DETECT_REQ`/`DETECT_RESP` exchange, 4-byte
      big-endian encoding for `FREQUENCY`/`BANDWIDTH`, single-byte
      payloads for `TXPOWER`/`SF`/`CR`/`RADIO_STATE`, the 12-step
      bring-up recipe, and the receive sidecar metadata format
      (`RSSI = byte - 157`, `SNR = signed Q6.2 / 4`).
- [x] **SPEC.md §8.5 (new): CSMA / airtime tracking.** Done as a
      follow-on to §8.4. Airtime caps via `CMD_ST_ALOCK` /
      `CMD_LT_ALOCK` (2-byte big-endian uint16 of `limit_percent ×
      100`), `Reticulum.ANNOUNCE_CAP = 2.0` default; pre-TX carrier
      sense is firmware-private and not exposed to the host — host
      clients don't implement their own LBT, but native-LoRa clients
      (e.g. the repeater repo) need the algorithm from
      `RNode_Firmware.ino:683-712`.
- [x] **SPEC.md §6.5 second sub-bullet: implicit vs explicit proof
      mode.** Done as part of the §6.5 expansion (Tier 1 #3). The
      length-dispatch validator at `PacketReceipt.validate_proof`
      and the `should_use_implicit_proof()` config switch are
      documented in §6.5.1-§6.5.2 with full citations.

### Tier 3 — required to act as a transport node / relay (DONE)

All five Tier 3 items consolidated into SPEC.md §12 "Transport-relay
behaviour" (single section, seven sub-sections) since they share state
(path_table, announce_table, link_table, reverse_table, tunnels,
discovery_path_requests):

- [x] **DATA forwarding rules** — §12.2 covers the three-case branch
      on remaining_hops (>1 forward as HEADER_2 with new transport_id;
      ==1 strip transport_id and forward as HEADER_1 broadcast; ==0
      local destination, just bump hops). LINKREQUEST gets an extra
      link_table entry and the §6.6 MTU clamp; non-LINKREQUEST DATA
      gets a reverse_table entry.
- [x] **ANNOUNCE rebroadcasting** — §12.3 covers the announce_table
      retransmit queue, per-interface ANNOUNCE_CAP throttling and
      announce_queue, random_blob replay defence with MAX_RANDOM_BLOBS
      sliding-window cap, and the PATH_RESPONSE short-circuit.
- [x] **Path table management** — §12.4 covers the entry shape, three
      TTL constants by interface mode (AP/ROAMING/default 30 days),
      stale-paths eviction in Transport.jobs, and persistence to
      storagepath/paths.
- [x] **Tunnels and shared-instance protocol** — §12.6 covers
      discovery_path_requests recursive search, the tunnels[] state
      that survives interface flap, and the shared-instance wire
      protocol (just regular Reticulum packets over a TCP loopback;
      what's "shared" is the Transport state, not the wire format).
- [x] **Reverse-table link transport** — §12.5 covers LRPROOF
      forwarding via link_table, Link DATA forwarding in both
      directions once the link_table entry is validated, and PROOF
      receipt forwarding via reverse_table (one-shot pop on use).

## Developer-experience gaps (would save real implementers real time)

The following aren't strictly wire-format issues — they're things that
bite anyone building a clean-room client. Listed in rough priority
order: top three save the most debugging hours.

- [x] **§13 (new): Threading / concurrency model.** Done in §13.
      Five sub-sections covering long-running threads (jobloop,
      count_traffic, per-link watchdog, per-resource watchdog,
      per-interface RX, per-handler dispatch), full lock inventory
      table, callback-thread guarantees with race notes, and
      implementation-private timing constants. (Reticulum is
      heavily threaded: `Transport.jobs` periodic loop, per-Link
      watchdog daemon threads, per-Resource transfer threads,
      announce-handler callbacks fire on fresh daemon threads,
      lock inventory (`Transport.path_table_lock`,
      `Transport.announce_table_lock`, `Identity.known_destinations_lock`,
      etc). A client built single-threaded mostly works for
      opportunistic LXMF but breaks on Resource transfers and Link
      keepalives. #1 cause of "my client compiles and almost works
      but is flaky." Roundup of which loop runs when, what callbacks
      fire on which thread, what locks must be held to mutate which
      state.

- [x] **§14 (new): Failure-mode → root-cause cheatsheet.** Done.
      Eight tables (Identity/announce, Token crypto / opportunistic
      LXMF, Link establishment / proofs, Resource transfers, Path
      discovery, Transport / framing, LXMF specifics, Concurrency)
      keyed by symptom, pointing at root-cause section + relevant
      verifier. Closes with the §9.9 "rx-log every inbound packet"
      diagnostic. §9 lists
      gotchas by cause; this would be the inverse-index, organised
      by symptom. Worked examples like:
        - "messages send but no PROOF returns" → §6.5
          implicit/explicit length mismatch
        - "links establish then disconnect within a minute" →
          §6.7 KEEPALIVE not implemented or wrong sentinel byte
        - "first contact works but every subsequent send fails" →
          §7.5 periodic re-announce missing
        - "Sideband announces validate but mine don't" →
          §4.1 random_hash timestamp not encoded (§9.10)
        - "everything works on TCP but breaks on RNode" →
          §8.4 KISS handshake or §8.3 split-packet protocol bug
      High value because debugging Reticulum is a known multi-hour
      exercise; this would shortcut diagnosis to seconds.

- [x] **§15 (new): Time / clock requirements roundup.** Done.
      Seven sub-sections covering three clock kinds (wall time vs
      boot-relative monotonic vs hi-res monotonic), what's required
      vs recommended vs optional, the no-RTC strategy for
      `random_hash` timestamps (boot-relative is fine; random
      bytes are the §9.10 bug), wall-time-only LXMF features
      (ticket expiry can't substitute), and an explicit
      what-fails / what-works inventory for clockless devices
      with their interop consequences. Currently
      scattered across §4.1 (random_hash timestamp), §9.6 (clockless
      LXMF senders), §5.7 (ticket expiry), §6.7 (RTT-driven keepalive),
      §7.5 (re-announce cadence). A no-RTC device (Faketec, RAK4631
      stock, Heltec_T114) needs a clear "what fails / what works /
      how to substitute monotonic-seconds" roundup so embedded
      implementers don't have to hunt for the constraints.

- [x] **§6.8 (new): Channel mode (`CHANNEL = 0x0E` context).** Done.
      Six sub-sections: wire form (6-byte BE header msgtype+sequence+
      length followed by payload, Token-encrypted by link session
      key), reserved SystemMessageTypes (`SMT_STREAM_DATA = 0xff00`),
      MSGTYPE registration via `Channel.register_message_type`,
      reliable delivery via the standard §6.5 PROOF mechanism plus
      a sliding window, when-to-use-Channel-vs-Resource-vs-REQUEST
      decision matrix. Old §6.8 Source moved to §6.9.
      Multiplexed-application-data channel that runs over an
      established Link, distinct from DATA/REQUEST/RESPONSE.
      `RNS/Channel.py` is the reference. NomadNet uses it for the
      "channel" API beyond simple page fetches. Currently only a
      one-line entry in §2.5; deserves its own §6.x sub-section
      with body format and lifecycle.

- [x] **§8.6 (new): AutoInterface multicast discovery.** Done.
      Seven sub-sections: IPv6 multicast group derivation from
      `SHA256(group_id)` with scope/address-type bits, default
      UDP ports (29716 discovery / 29717 unicast probe / 42671 data),
      discovery cadence constants, discovery announce body format
      (msgpack with group_hash + MTU + optional IFAC seal),
      post-discovery data flow as plain unicast UDP on the data
      port carrying full Reticulum packets, IFAC integration,
      source map. HW_MTU = 1196 (Ethernet-MTU-friendly). UDP
      multicast on a known group/port for LAN auto-detection of
      peers. Specific multicast group, port, magic bytes, beacon
      cadence. `RNS/Interfaces/AutoInterface.py` is the reference.
      Needed for any client that wants to participate in
      auto-discovered LAN meshes (the "share_instance" deployment
      pattern with multiple physical hosts).

- [x] **§16 (new): Bounded-state inventory.** Done. Eight sub-section
      tables covering per-node Transport state, per-interface state,
      per-destination, per-Link, per-Resource, identity caches,
      LXMF-level, Channel state — every memory-bounded structure across
      the protocol with its cap and pointer to the explanatory section.
      Closes with explicit guidance for embedded targets (~64KB-RAM
      class) on what to bound, what to reject, and what to skip
      (transport-mode operation). A single table of every
      memory-bounded structure across the protocol with its cap:
      `MAX_RANDOM_BLOBS = 32`, `Transport.max_pr_tags = 32000`,
      `Interface.MAX_HELD_ANNOUNCES = 256`, `Destination.RATCHET_COUNT
      = 512`, `Identity.known_destinations` (unbounded — the gotcha
      itself), `Transport.MAX_HASHLIST_LENGTH`, `Resource.WINDOW_MAX_FAST
      = 75`, `LXMRouter.propagation_entries` (operator-bounded), etc.
      Critical for embedded targets where heap is finite. Mostly
      implicit in §4.5 / §7.x / §10 / §12 today; a single appendix
      table would be a quick reference card.

## Spec polishing (lower priority)

- [x] **Navigation polish for `SPEC.md`** — at ~3300 lines, splitting
      into per-layer files would have broken ~37 cross-references
      (flow docs, verifier docstrings, agent.md, README) for
      relatively little reader benefit. Picked the lighter polish
      instead: a collapsible Table of Contents at the top of the
      doc with anchor links to every H2 + H3, plus a `<details>`
      wrap on §11.6 (NomadNet specifics — informational/non-normative,
      and the longest H3 sub-tree in the document). Helper script at
      `tools/_gen_toc.py` regenerates the ToC if headings change.

- [x] **Add a "last-verified-against-rns" line** to SPEC.md
      frontmatter (per `agent.md` §7). Done — `RNS 1.2.0 / LXMF
      0.9.6` is now in the document header.

- [x] **`tools/verify_stamps.py`** runtime-locks §5.7. Done.
      Verifies workblock determinism (confirms exactly 768 KiB at
      3000 rounds), PoW search-and-validate at target_cost=4 (fast),
      `LXMessage.validate_stamp` end-to-end accepts/rejects PoW
      stamps, and the ticket shortcut path:
      `SHA256(ticket || message_id)` is accepted with a matching
      ticket and rejected with a wrong one.
