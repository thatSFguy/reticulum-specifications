# Reticulum Wire Specifications

A byte-level reference for implementing Reticulum-compatible clients. This document focuses on what implementations need to interop with the canonical Python implementation ([`markqvist/Reticulum`](https://github.com/markqvist/Reticulum) and [`markqvist/LXMF`](https://github.com/markqvist/LXMF)) plus the existing client ecosystem (Sideband, Nomadnet, MeshChat, the various firmware projects).

**Last verified against:** `RNS 1.4.2` / `LXMF 1.1.1` / `RNode_Firmware` (master at the spec's last revision date). Each section's source citations were re-checked against these versions; runtime verifiers in [`tools/`](tools/) lock the wire-format claims in against actually-running upstream code. When you upgrade past these, re-run every `tools/verify_*.py` and look for `FAIL`s.

Source citations refer to the standard `pip install rns lxmf` install layout (`RNS/`, `LXMF/`).

<details>
<summary><b>Contents</b> — click to expand the per-section table of contents (regenerate with <code>python tools/_gen_toc.py</code>)</summary>

<!-- TOC: regenerate via `python tools/_gen_toc.py` -->

- [1. Identity and destination hashes](#1-identity-and-destination-hashes)
  - [1.1 Identity composition](#11-identity-composition)
  - [1.2 Destination hash](#12-destination-hash)
  - [1.3 Private key on-disk format](#13-private-key-on-disk-format)
  - [1.4 GROUP destinations (symmetric-key alternative to SINGLE)](#14-group-destinations-symmetric-key-alternative-to-single)
- [2. Packet header](#2-packet-header)
  - [2.1 Flag byte layout](#21-flag-byte-layout)
  - [2.2 Two header forms](#22-two-header-forms)
  - [2.3 Originator HEADER_1 → HEADER_2 conversion](#23-originator-header_1-header_2-conversion)
  - [2.4 Hop count](#24-hop-count)
  - [2.5 Context byte](#25-context-byte)
  - [2.6 Source](#26-source)
- [3. Token cryptography (modified Fernet)](#3-token-cryptography-modified-fernet)
  - [3.1 Wire format](#31-wire-format)
  - [3.2 Encrypt steps (opportunistic)](#32-encrypt-steps-opportunistic)
  - [3.3 Decrypt steps](#33-decrypt-steps)
  - [3.4 Source](#34-source)
- [4. Announce wire format](#4-announce-wire-format)
  - [4.1 Packet body](#41-packet-body)
  - [4.2 Signed data](#42-signed-data)
  - [4.3 `app_data` format for LXMF delivery destinations](#43-app_data-format-for-lxmf-delivery-destinations)
  - [4.4 Announce filtering by `name_hash`](#44-announce-filtering-by-name_hash)
  - [4.5 Announce validation rules (receive side)](#45-announce-validation-rules-receive-side)
  - [4.6 `rrc.hub` announce app_data (Reticulum Relay Chat)](#46-rrchub-announce-app_data-reticulum-relay-chat)
- [5. LXMF wire format](#5-lxmf-wire-format)
  - [5.1 Opportunistic delivery (single Reticulum DATA packet)](#51-opportunistic-delivery-single-reticulum-data-packet)
  - [5.2 Direct delivery (over an established Reticulum Link)](#52-direct-delivery-over-an-established-reticulum-link)
  - [5.3 `msgpack_payload`](#53-msgpack_payload)
  - [5.4 Source/destination semantics](#54-sourcedestination-semantics)
  - [5.5 Signed data](#55-signed-data)
  - [5.6 Signature verification — msgpack variant tolerance](#56-signature-verification-msgpack-variant-tolerance)
  - [5.7 LXMF stamps and tickets (anti-spam)](#57-lxmf-stamps-and-tickets-anti-spam)
  - [5.8 Propagation node protocol (offline message store-and-forward)](#58-propagation-node-protocol-offline-message-store-and-forward)
  - [5.9 LXMF field constants and helper specifiers](#59-lxmf-field-constants-and-helper-specifiers)
  - [5.10 Source](#510-source)
- [6. Reticulum Link protocol](#6-reticulum-link-protocol)
  - [6.1 LINKREQUEST (initiator → responder)](#61-linkrequest-initiator-responder)
  - [6.2 LRPROOF (responder → initiator)](#62-lrproof-responder-initiator)
  - [6.3 link_id derivation](#63-link_id-derivation)
  - [6.4 Session keys and link activation](#64-session-keys-and-link-activation)
  - [6.5 Packet receipts (regular `PROOF` packets)](#65-packet-receipts-regular-proof-packets)
  - [6.6 MTU and mode signalling (3-byte trailer on LINKREQUEST and LRPROOF)](#66-mtu-and-mode-signalling-3-byte-trailer-on-linkrequest-and-lrproof)
  - [6.7 KEEPALIVE and link teardown](#67-keepalive-and-link-teardown)
  - [6.8 Channel mode (`CHANNEL = 0x0E`)](#68-channel-mode-channel-0x0e)
  - [6.9 Source](#69-source)
- [7. Transport behavior — the parts that bite](#7-transport-behavior-the-parts-that-bite)
  - [7.1 Path requests: peers send `path?` before opportunistic LXMF when no path is known](#71-path-requests-peers-send-path-before-opportunistic-lxmf-when-no-path-is-known)
  - [7.2 Responding to path requests](#72-responding-to-path-requests)
  - [7.3 Ratchet rotation (forward-secrecy hygiene, not dedup)](#73-ratchet-rotation-forward-secrecy-hygiene-not-dedup)
  - [7.4 Ratchet ring (inbound decrypt tolerance)](#74-ratchet-ring-inbound-decrypt-tolerance)
  - [7.5 Periodic re-announce](#75-periodic-re-announce)
  - [7.6 `TCPServerInterface.OUT` is True by default in practice](#76-tcpserverinterfaceout-is-true-by-default-in-practice)
  - [7.7 Source](#77-source)
- [8. Transport framing](#8-transport-framing)
  - [8.1 KISS (BLE / serial / RNode link)](#81-kiss-ble-serial-rnode-link)
  - [8.2 HDLC (TCP / `rnsd TCPServerInterface`)](#82-hdlc-tcp-rnsd-tcpserverinterface)
  - [8.3 RNode air-frame header and split-packet protocol](#83-rnode-air-frame-header-and-split-packet-protocol)
  - [8.4 RNode KISS configuration handshake](#84-rnode-kiss-configuration-handshake)
  - [8.5 RNode CSMA / airtime accounting](#85-rnode-csma-airtime-accounting)
  - [8.6 AutoInterface multicast discovery (LAN auto-detect)](#86-autointerface-multicast-discovery-lan-auto-detect)
- [9. Implementation gotchas](#9-implementation-gotchas)
  - [9.1 LXMF `source_hash` is the destination hash, not the identity hash](#91-lxmf-source_hash-is-the-destination-hash-not-the-identity-hash)
  - [9.2 Web Crypto and JCA AES-CBC auto-pad PKCS#7 — do not pad manually](#92-web-crypto-and-jca-aes-cbc-auto-pad-pkcs7-do-not-pad-manually)
  - [9.3 RNS bundles `umsgpack` — encode display names as `bytes`, not `str`](#93-rns-bundles-umsgpack-encode-display-names-as-bytes-not-str)
  - [9.4 Display name preservation across re-announces](#94-display-name-preservation-across-re-announces)
  - [9.5 Self-announce echo](#95-self-announce-echo)
  - [9.6 Clockless sender timestamps](#96-clockless-sender-timestamps)
  - [9.7 Periodic re-announce is non-optional](#97-periodic-re-announce-is-non-optional)
  - [9.8 The destination hash uses the bare app-name string](#98-the-destination-hash-uses-the-bare-app-name-string)
  - [9.9 Diagnostic: rx-log every inbound packet at the engine entry](#99-diagnostic-rx-log-every-inbound-packet-at-the-engine-entry)
  - [9.10 microReticulum `random_hash` lacks the timestamp half](#910-microreticulum-random_hash-lacks-the-timestamp-half)
- [10. Resource fragmentation protocol](#10-resource-fragmentation-protocol)
  - [10.1 When Resource runs](#101-when-resource-runs)
  - [10.2 Initiator-side preparation](#102-initiator-side-preparation)
  - [10.3 Wire packet contexts used during a Resource transfer](#103-wire-packet-contexts-used-during-a-resource-transfer)
  - [10.4 RESOURCE_ADV — the advertisement](#104-resource_adv-the-advertisement)
  - [10.5 RESOURCE_REQ — receiver requests parts](#105-resource_req-receiver-requests-parts)
  - [10.6 RESOURCE part packets](#106-resource-part-packets)
  - [10.7 RESOURCE_HMU — hashmap update](#107-resource_hmu-hashmap-update)
  - [10.8 RESOURCE_PRF — final proof](#108-resource_prf-final-proof)
  - [10.9 RESOURCE_ICL / RESOURCE_RCL — cancellation](#109-resource_icl-resource_rcl-cancellation)
  - [10.10 Sliding window and rate adaptation](#1010-sliding-window-and-rate-adaptation)
  - [10.11 Multi-segment resources](#1011-multi-segment-resources)
  - [10.12 Compression and encryption layering](#1012-compression-and-encryption-layering)
  - [10.13 Source map for §10](#1013-source-map-for-10)
- [11. REQUEST/RESPONSE protocol (NomadNet pages, propagation `/get`, custom RPC)](#11-requestresponse-protocol-nomadnet-pages-propagation-get-custom-rpc)
  - [11.1 Wire form — REQUEST (initiator → server)](#111-wire-form-request-initiator-server)
  - [11.2 Wire form — RESPONSE (server → initiator)](#112-wire-form-response-server-initiator)
  - [11.3 Path hash collision avoidance](#113-path-hash-collision-avoidance)
  - [11.4 Authorization (`allow` modes)](#114-authorization-allow-modes)
  - [11.5 RequestReceipt — initiator-side state machine](#115-requestreceipt-initiator-side-state-machine)
  - [11.6 NomadNet specifics (informational, not normative)](#116-nomadnet-specifics-informational-not-normative)
  - [11.7 Source map](#117-source-map)
- [12. Transport-relay behaviour](#12-transport-relay-behaviour)
  - [12.1 The `transport_enabled` toggle](#121-the-transport_enabled-toggle)
  - [12.2 DATA forwarding rules](#122-data-forwarding-rules)
  - [12.3 ANNOUNCE rebroadcasting](#123-announce-rebroadcasting)
  - [12.4 Path table management](#124-path-table-management)
  - [12.5 Reverse-table link transport](#125-reverse-table-link-transport)
  - [12.6 Tunnels and shared-instance protocol](#126-tunnels-and-shared-instance-protocol)
  - [12.7 Source map for §12](#127-source-map-for-12)
- [13. Threading and concurrency model](#13-threading-and-concurrency-model)
  - [13.1 Long-running threads](#131-long-running-threads)
  - [13.2 Lock inventory](#132-lock-inventory)
  - [13.3 Callback-thread guarantees (and lack thereof)](#133-callback-thread-guarantees-and-lack-thereof)
  - [13.4 Implementation-private constants](#134-implementation-private-constants)
  - [13.5 Source map](#135-source-map)
- [14. Failure modes — symptom → root cause](#14-failure-modes-symptom-root-cause)
  - [Identity / announce](#identity-announce)
  - [Token crypto / opportunistic LXMF](#token-crypto-opportunistic-lxmf)
  - [Link establishment / proof receipts](#link-establishment-proof-receipts)
  - [Resource transfers (large bodies)](#resource-transfers-large-bodies)
  - [Path discovery](#path-discovery)
  - [Transport / framing](#transport-framing)
  - [LXMF specifics](#lxmf-specifics)
  - [Concurrency](#concurrency)
  - [When all else fails](#when-all-else-fails)
- [15. Time and clock requirements](#15-time-and-clock-requirements)
  - [15.1 Three clock kinds](#151-three-clock-kinds)
  - [15.2 Required: monotonic seconds (every implementation)](#152-required-monotonic-seconds-every-implementation)
  - [15.3 Recommended: monotonic-with-no-skew across announces (timestamp encoding)](#153-recommended-monotonic-with-no-skew-across-announces-timestamp-encoding)
  - [15.4 Recommended: wall time (LXMF-level)](#154-recommended-wall-time-lxmf-level)
  - [15.5 Optional: high-resolution monotonic for diagnostics](#155-optional-high-resolution-monotonic-for-diagnostics)
  - [15.6 What fails on a no-RTC, no-NTP-sync device](#156-what-fails-on-a-no-rtc-no-ntp-sync-device)
  - [15.7 Source map](#157-source-map)
- [16. Bounded-state inventory (memory limits at a glance)](#16-bounded-state-inventory-memory-limits-at-a-glance)
  - [16.1 Per-node state caps](#161-per-node-state-caps)
  - [16.2 Per-interface state caps](#162-per-interface-state-caps)
  - [16.3 Per-destination state caps](#163-per-destination-state-caps)
  - [16.4 Per-Link state caps](#164-per-link-state-caps)
  - [16.5 Per-Resource state caps](#165-per-resource-state-caps)
  - [16.6 Identity/cryptography caches](#166-identitycryptography-caches)
  - [16.7 LXMF-level caps](#167-lxmf-level-caps)
  - [16.8 Channel state caps](#168-channel-state-caps)
  - [16.9 What this means for embedded targets](#169-what-this-means-for-embedded-targets)
- [17. Implementation taxonomy: who needs which sections](#17-implementation-taxonomy-who-needs-which-sections)
  - [17.1 The three categories](#171-the-three-categories)
  - [17.2 Section relevance by category](#172-section-relevance-by-category)
  - [17.3 Worked example: §2.3 originator HEADER_1→HEADER_2 conversion](#173-worked-example-23-originator-header_1header_2-conversion)
  - [17.4 Pragmatic implication](#174-pragmatic-implication)
  - [17.5 Application protocols layered over Reticulum](#175-application-protocols-layered-over-reticulum)
- [18. Test vectors](#18-test-vectors)
- [19. Source map](#19-source-map)

<!-- /TOC -->

</details>

---

## 1. Identity and destination hashes

### 1.1 Identity composition

A Reticulum identity is two keypairs concatenated:

```
public_key  = X25519_pub(32) || Ed25519_pub(32)        // 64 bytes
private_key = X25519_priv(32) || Ed25519_priv(32)      // 64 bytes
```

X25519 for ECDH (encryption / shared-secret derivation), Ed25519 for signatures.

```
identity_hash = SHA256(public_key)[:16]                // 16 bytes truncated
```

The 16-byte truncation is consistent across all hashes Reticulum stores on the wire (destinations, link IDs, packet hashes, etc.). The full SHA-256 is used internally for signing inputs but never appears in headers.

### 1.2 Destination hash

The 16-byte destination hash that appears in packet headers and announces is:

```
name_hash = SHA256(full_app_name_string)[:10]
dest_hash = SHA256(name_hash || identity_hash)[:16]
```

Where `full_app_name_string` is e.g. `"lxmf.delivery"`, `"nomadnetwork.node"`, `"rnstransport.path.request"`. **The hex-encoded identity hash is NOT part of the input** — only the plain ASCII app-name string. This is the `identity=None` branch of upstream's `expand_name()` function (`RNS/Destination.py`). The identity hex appears only in the human-readable `Destination.name` debug string.

Common pre-computed `name_hash` values:

| 10-byte hex | App name |
|---|---|
| `6ec60bc318e2c0f0d908` | `lxmf.delivery` |
| `e03a09b77ac21b22258e` | `lxmf.propagation` |
| `213e6311bcec54ab4fde` | `nomadnetwork.node` |
| `0ad8bff9ff75737c058e` | `nomadnetwork.gossip` |
| `9efb9c771eeb5ae90ea6` | `rnstransport.broadcasts` |
| `4848a053c16415bed6c8` | `rnstransport.remote.management` |
| `7926bbe7dd7f9aba88b0` | `rnstransport.path.request` (resulting `dest_hash` with `identity=None`: `6b9f66014d9853faab220fba47d02761`) |

### 1.3 Private key on-disk format

`RNS.Identity.to_file(path)` writes the raw 64-byte private-key blob with **no header, no version byte, no checksum, no encryption**. The byte order is the **same** as the public_key concatenation in §1.1 — verified by `tools/verify_destination_hash.py`'s existing `Identity.from_bytes` round-trip:

```
prv_bytes_blob  =  X25519_priv(32) || Ed25519_priv(32)         // 64 bytes total
```

`Identity.get_private_key()` at `RNS/Identity.py:723-728` returns this exact concatenation:

```python
def get_private_key(self):
    return self.prv_bytes + self.sig_prv_bytes
    #      ^^^^^^^^^^^^^   X25519 priv (set at line 679 from X25519PrivateKey.generate())
    #                       ^^^^^^^^^^^^^^^   Ed25519 priv (set at line 682)
```

`Identity.load_private_key(prv_bytes)` at line 706-717 slices it back the same way:

```python
self.prv_bytes     = prv_bytes[:32]   # X25519
self.sig_prv_bytes = prv_bytes[32:]   # Ed25519
```

`to_file` is a thin wrapper that writes `get_private_key()` to the path; `from_file` reads back with no extra parsing.

#### File-system facts

- **Size:** exactly 64 bytes. No magic, no length prefix.
- **Encryption:** none. Anyone with read access can fully impersonate the identity.
- **Permissions:** upstream doesn't `chmod` the file; clients are expected to put it in a directory protected by OS permissions (`~/.reticulum/storage` on Linux/macOS, `%APPDATA%/Reticulum/storage` on Windows by default).
- **Filename:** caller-controlled. RNS itself uses `transport_identity` for the transport node and lets app-level callers choose for delivery destinations (LXMF puts these in `LXMF.LXMRouter.storagepath`).

#### Constructing from raw bytes — `from_bytes` HAZARD

`Identity.from_bytes(prv_bytes)` at line 611-623 takes the same 64-byte concat and reconstitutes an `Identity`. The upstream docstring explicitly warns:

> **HAZARD!** Never use this to generate a new key by feeding random data in prv_bytes.

The reason: `X25519PrivateKey.from_private_bytes` and `Ed25519PrivateKey.from_private_bytes` both accept arbitrary 32-byte values without scalar clamping or rejection — a clean-room implementation that feeds raw random data into `from_bytes` skips the keypair-generation invariants enforced by the upstream `cryptography` library's `.generate()` methods (e.g. X25519 scalar clamping per RFC 7748 §5). Always generate fresh keys via the `cryptography` (or equivalent) library's keypair generator, then concatenate; never invent your own bytes.

#### Cross-implementation portability

The format is portable across implementations because there's nothing in it but the raw bytes. A 64-byte file written by Python RNS is byte-identical to one written by any clean-room implementation that follows this section, and both produce the same `identity_hash` and `lxmf.delivery` `destination_hash` when fed back through §1.1 and §1.2 — test vectors at [`test-vectors/identities.json`](test-vectors/identities.json) demonstrate the round-trip against RNS 1.2.4.

> ⚠️ **Spec correction:** Earlier revisions of this section described the on-disk order as Ed25519 first, X25519 second ("opposite of the public_key concatenation"). That was wrong — verified by re-running `Identity.to_file` and reading back the bytes against the test vector at `test-vectors/identities.json`, the actual order is X25519 first, Ed25519 second, identical to the public_key order. Implementations following the prior spec wording would have corrupted identity files when interoperating with upstream Python RNS.

### 1.4 GROUP destinations (symmetric-key alternative to SINGLE)

Most Reticulum traffic — including all LXMF — uses `SINGLE` destinations with the X25519 ECDH + Ed25519 signing scheme described above. There is also a **`GROUP`** destination type (`RNS.Destination.GROUP = 0x01`, in the `dest_type` field of the packet header per §2.1) that uses a **pre-shared symmetric key** instead, intended for closed channels where every participant should be able to decrypt every message without per-recipient ECDH.

#### 1.4.1 Key generation

`Destination.create_keys()` for `GROUP` calls `Token.generate_key()` (`RNS/Cryptography/Token.py:53-56`):

```python
@staticmethod
def generate_key(mode=AES_256_CBC):
    if   mode == AES_128_CBC: return os.urandom(32)    # 16B signing + 16B encryption
    elif mode == AES_256_CBC: return os.urandom(64)    # 32B signing + 32B encryption
```

The default is AES-256-CBC, so the symmetric key is **64 random bytes**, split into:

```
signing_key     = key[ 0..32]      // HMAC-SHA256 input
encryption_key  = key[32..64]      // AES-256-CBC key
```

A clean-room implementation that needs to interop with a GROUP destination must use AES-256-CBC by default and derive the same split. AES-128-CBC mode (32-byte key, 16/16 split) is supported by the `Token` class but no upstream caller currently selects it for GROUPs.

#### 1.4.2 Wire format

GROUP destinations encrypt and decrypt via `Token.encrypt` / `Token.decrypt` — **the same Token format used by Link-derived encryption** (§3.1, the no-ephemeral-pub form):

```
wire_body  =  iv(16) || aes_ciphertext || hmac_sha256(32)
```

There is **no ephemeral_pub prefix** because there is no ECDH — every participant already shares the same `(signing_key, encryption_key)` pair. The format is identical to a Link DATA payload after the link is established (§6.4). Reticulum's `Token` class is shared across both code paths; see `RNS/Destination.py:601-609` and `:645-653` for GROUP encrypt/decrypt, and `RNS/Cryptography/Token.py:87-114` for the underlying primitive.

#### 1.4.3 Destination hash for GROUP

GROUP destinations use the same `dest_hash` recipe as SINGLE (§1.2) — `SHA256(name_hash || identity_hash)[:16]` — with two wrinkles:

- The constructor accepts an `identity` argument optionally. If provided, `identity_hash = SHA256(identity.public_key)[:16]` per §1.1; the resulting `dest_hash` is keyed to that identity's public key as well as the group name. Different identities → different group destinations even with the same name.
- If `identity` is not provided (`None`), `dest_hash = SHA256(name_hash)[:16]` (same recipe as PLAIN destinations — see the `path-request` example in §1.2).

The identity (if any) does NOT participate in encryption — it's purely a way to disambiguate group destinations sharing a name across owners. The actual encryption uses the symmetric key from §1.4.1.

#### 1.4.4 On-disk format

`Destination.get_private_key()` for GROUP returns `self.prv_bytes` — the 64 (or 32) raw key bytes. `Destination.load_private_key(key)` accepts the same. There is no canonical file path or filename — the application chooses where to store the symmetric key, and is responsible for distributing it to every group member out of band.

Like the SINGLE identity file (§1.3), the GROUP key file has **no header, no encryption-at-rest, no checksum**. Anyone with read access can fully impersonate the group.

#### 1.4.5 Why most clients don't bother

GROUP destinations are rarely seen in the wild because:

- LXMF doesn't use them (every chat is one-to-one between SINGLE destinations, even in multi-party rooms — those are application-layer constructs).
- NomadNet pages use SINGLE destinations.
- The forward-secrecy properties of SINGLE (per-message ephemeral X25519 + ratchet rotation per §7.3) are absent for GROUP — once the symmetric key is leaked, every past and future message decryptable by that key is compromised.
- Group key distribution is an unsolved problem at the protocol level — Reticulum doesn't help with this.

A clean-room client that targets LXMF interop only can ignore GROUP destinations entirely. Implementations of `Destination.encrypt`/`decrypt` should still recognize the `GROUP (0x01)` type byte in the packet header to gracefully reject (rather than crash on) inbound packets to a GROUP whose key the receiver doesn't hold.

---

## 2. Packet header

### 2.1 Flag byte layout

Every Reticulum packet starts with a 1-byte flag field:

```
bit 7   : ifac_flag        (0 = open / no IFAC, 1 = IFAC field present)
bit 6   : header_type      (0 = HEADER_1, 1 = HEADER_2)
bit 5   : context_flag     (1 = announce includes a ratchet pubkey)
bit 4   : transport_type   (0 = BROADCAST, 1 = TRANSPORT)        — the official manual calls this "propagation_type"
bit 3-2 : destination_type (0 = SINGLE, 1 = GROUP, 2 = PLAIN, 3 = LINK)
bit 1-0 : packet_type      (0 = DATA, 1 = ANNOUNCE, 2 = LINKREQUEST, 3 = PROOF)
```

Each subfield is **1 bit** (or 2 for `destination_type` / `packet_type`). Upstream's parser extracts them with these masks (`RNS/Packet.py:246-250` in RNS 1.4.2):

```python
self.header_type      = (self.flags & 0b01000000) >> 6     # bit 6 only
self.context_flag     = (self.flags & 0b00100000) >> 5
self.transport_type   = (self.flags & 0b00010000) >> 4
self.destination_type = (self.flags & 0b00001100) >> 2
self.packet_type      = (self.flags & 0b00000011)
```

Bit 7 (`ifac_flag`) is set by `Transport.transmit` immediately before transmission when the egress interface has an IFAC identity attached (`RNS/Transport.py:1069-1099`). The setter is unambiguous:

```python
# Set IFAC flag
new_header = bytes([raw[0] | 0x80, raw[1]])    # 0x80 = bit 7
# Assemble new payload with IFAC
new_raw    = new_header + ifac + raw[2:]       # IFAC field is inserted between header and addresses
```

When `ifac_flag = 1`, an `ifac_size`-byte IFAC field appears immediately after byte 2 of the header — i.e. between the `hops` byte and the start of `ADDRESSES`. `ifac_size` is interface-configured and ranges from `IFAC_MIN_SIZE = 1` byte (`RNS/Reticulum.py:148-152`) up to 64 bytes (full Ed25519 signature). The receiving side strips the IFAC after verification and rebuilds the un-IFACed packet for upstream processing (`RNS/Transport.py:1443-1467`).

> ⚠️ **Spec correction.** Earlier revisions of this section (through commit [`8c4d550`](https://github.com/thatSFguy/reticulum-specifications/commit/8c4d550)) treated `header_type` as a 2-bit field occupying bits 7-6, with bit 7 reserved. That was wrong: bit 7 has always been the IFAC flag (`Transport.transmit` line 1081), and `header_type` is 1 bit at position 6. The official manual §4.6.3 documents the correct layout. Implementations that followed the prior wording will mis-parse IFAC-protected packets as `header_type = 2 or 3` and reject them. Surfaced by the reporter on [issue #4](https://github.com/thatSFguy/reticulum-specifications/issues/4) item #1.

### 2.2 Two header forms

```
HEADER_1: flags(1) hops(1) dest_hash(16) context(1) data(...)        // min 19 bytes
HEADER_2: flags(1) hops(1) transport_id(16) dest_hash(16) context(1) data(...)   // min 35 bytes
```

`HEADER_2` carries a `transport_id` (the next-hop transport node's identity hash) before the final destination hash. A relay converts a HEADER_1 packet to HEADER_2 by setting bit 6 of flags, inserting its own identity at offset 2, and re-transmitting.

### 2.3 Originator HEADER_1 → HEADER_2 conversion

This is non-obvious and matters: when an **originator** (not a relay) sends a packet to a destination known to be more than 1 hop away, the originator MUST also do the HEADER_2 conversion. From `RNS/Transport.py::outbound` (lines 1152-1183 in RNS 1.4.2; verified by `tools/verify_packet_header.py`):

```python
if path_entry[IDX_PT_HOPS] > 1:
    if packet.header_type == RNS.Packet.HEADER_1:
        new_flags = (RNS.Packet.HEADER_2) << 6 | (Transport.TRANSPORT) << 4 | (packet.flags & 0b00001111)
        new_raw  = struct.pack("!B", new_flags)
        new_raw += packet.raw[1:2]                       # hops byte unchanged
        new_raw += path_entry[IDX_PT_NEXT_HOP]           # 16B transport_id at offset 2
        new_raw += packet.raw[2:]                        # original dest_hash + context + payload
```

Since RNS 1.3.7 the "hops byte unchanged" line carries a conditional: when the node has the `local_hops_delta` privacy option enabled, the emitted hops byte is the node's random delta instead of the packet's own value (`RNS/Transport.py:1157` in RNS 1.4.2) — see §2.4.

For destinations 0 or 1 hops away, the originator may stay HEADER_1 — the receiving rnsd auto-fills the transport_id when the destination matches a local client (`for_local_client` branch at `RNS/Transport.py:1552` in RNS 1.4.2). Implementations that always emit HEADER_1 will silently fail to deliver to multi-hop destinations even with a known path.

### 2.4 Hop count

Byte 1 is `hops`, an 8-bit counter that each transit relay increments by 1. `0` for a packet still on the originator (but see the hops-delta callout below). Valid wire values are `0`–`127`: since RNS 1.3.8, `Packet.unpack` raises on `hops >= Transport.PATHFINDER_M` (= 128, the maximum path length — `RNS/Transport.py:63` in RNS 1.4.2), so a packet arriving with `hops ≥ 128` is dropped as malformed (`RNS/Packet.py:247-248`; verified by `tools/verify_packet_header.py`). Implementations SHOULD enforce the same bound on receive.

> **Hops on the wire are not a trustworthy origin/distance signal —
> the `local_hops_delta` originator-privacy option (RNS ≥ 1.3.7).**
> When a node enables the `[reticulum]` config option
> `local_hops_delta` (default off — `RNS/Reticulum.py:256`, `:510-512`
> in RNS 1.4.2), it picks a random delta in `[2, 7]` once at startup
> (`(random_byte % 6) + 2`, `RNS/Transport.py:240`) and emits packets
> it originates with the hops byte set to that delta instead of `0`.
> The delta applies when `packet.hops == 0`, the destination type is
> not PLAIN or GROUP, and the outbound interface is not a
> shared-instance / local-client interface (`should_apply_delta`,
> `RNS/Transport.py:1361-1364`; apply sites `:1157`, `:1177`,
> `:1190-1191`, `:1347-1350`, plus the shared-instance local-client
> emission sites `:1692`, `:1736`, `:2258`, `:2343`). A HEADER_1
> ANNOUNCE is additionally rewritten to HEADER_2 with the transport
> bit set and the node's own transport identity hash inserted as
> `transport_id` (`mangle_hops(…, transport_insert=True)`,
> `RNS/Transport.py:1367-1369`), making a mangled announce
> indistinguishable from one relayed on behalf of a remote originator.
> Receivers MUST NOT infer "sender is the originator" from
> `hops == 0`/`1`, and MUST NOT treat announce hop counts as exact
> path length — a peer with this option enabled inflates them by a
> constant 2–7. (Link-ID and proof hashing are unaffected: §6.3/§7.2
> already strip the hops byte before hashing.)

### 2.5 Context byte

Single byte after the destination hash (offset 18 for HEADER_1, offset 34 for HEADER_2). Common values:

Full context inventory from `RNS/Packet.py:72-92` (RNS 1.4.2):

| Hex | Name | Used for |
|---|---|---|
| `0x00` | NONE | Generic / opportunistic DATA packet |
| `0x01` | RESOURCE | One part (chunk) of a Resource transfer (§10) |
| `0x02` | RESOURCE_ADV | Resource advertisement |
| `0x03` | RESOURCE_REQ | Resource part request (from receiver to sender) |
| `0x04` | RESOURCE_HMU | Resource hashmap update (next-segment hashmap) |
| `0x05` | RESOURCE_PRF | Resource proof (a PROOF-type packet using this context) |
| `0x06` | RESOURCE_ICL | Resource cancel from the initiator |
| `0x07` | RESOURCE_RCL | Resource cancel from the receiver / reject of an advertisement |
| `0x08` | CACHE_REQUEST | Cache lookup over a Link |
| `0x09` | REQUEST | Link REQUEST (NomadNet page fetch, propagation `/get`) |
| `0x0A` | RESPONSE | Link RESPONSE matching a REQUEST |
| `0x0B` | PATH_RESPONSE | An ANNOUNCE emitted in response to a `path?` request — distinguishes it from a periodic re-announce. Receivers handle the two paths differently (see §7.2 and §4.5) |
| `0x0C` | COMMAND | Channel-style remote-execution command |
| `0x0D` | COMMAND_STATUS | Status reply for a COMMAND |
| `0x0E` | CHANNEL | Link channel multiplexed payload |
| `0xFA` | KEEPALIVE | Link keepalive (sent periodically while a Link is idle) |
| `0xFB` | LINKIDENTIFY | Backchannel-identify proof on an established Link (§5 backchannel) |
| `0xFC` | LINKCLOSE | Link teardown notification |
| `0xFD` | LINKPROOF | Defined but **not actually emitted** by upstream RNS 1.2.4 in this revision. Both `Identity.prove` and `Link.prove_packet` build their proof packets with `context = NONE (0x00)` — the proof-ness is conveyed by `packet_type = PROOF (3)`, not by this context byte. Reserved for a future revision; see §6.5 |
| `0xFE` | LRRTT | Link round-trip-time reply — initiator's link-activation packet (§6.4.2) |
| `0xFF` | LRPROOF | Link request proof (§6.2) |

### 2.6 Source

`RNS/Packet.py` for the constants and `_pack` / `_unpack` methods. `RNS/Transport.py` for the routing-side HEADER_1↔HEADER_2 transitions.

---

## 3. Token cryptography (modified Fernet)

Reticulum's "Token" construction is a modified Fernet used for opportunistic destination encryption (single packet), as well as for derived-key channels on established Links.

### 3.1 Wire format

```
ephemeral_pub(32) || iv(16) || aes_ciphertext(...) || hmac_sha256(32)
```

For Link-derived-key encryption (after the Link handshake has produced a session key), the `ephemeral_pub` prefix is omitted and the wire form is just `iv || ciphertext || hmac`.

### 3.2 Encrypt steps (opportunistic)

1. Generate ephemeral X25519 keypair `(eph_priv, eph_pub)`.
2. ECDH: `shared = X25519(eph_priv, recipient_X25519_pub)`. The recipient's X25519 pub is either their long-term `encPub` (first 32 bytes of public_key) or their currently-announced `ratchet_pub` if present.
3. HKDF-SHA256: `derived = HKDF(shared, salt = recipient_identity_hash, info = "", L = 64)`. **The salt is the recipient's 16-byte identity hash** — not their destination hash, not the ratchet hash.
4. Split: `signing_key = derived[0..32]`, `encryption_key = derived[32..64]`.
5. Random 16-byte IV.
6. AES-256-CBC encrypt plaintext with `encryption_key` and `iv`. **Do NOT manually pad** — the platform AES-CBC API (`AES/CBC/PKCS5Padding` on JCA, Web Crypto's default) auto-pads PKCS#7. Manual padding on top causes 16 garbage bytes of double-padding.
7. `hmac = HMAC-SHA256(signing_key, iv || ciphertext)`.
8. Concatenate as the wire format above.

### 3.3 Decrypt steps

Reverse of encrypt. Critically:

- **Verify HMAC BEFORE attempting decryption** (encrypt-then-MAC; prevents AES padding-oracle attacks).
- A receiver that has multiple candidate X25519 private keys (typically the current ratchet privkey + the long-term identity privkey) should try each in order until one produces a matching HMAC. Senders that haven't seen the receiver's latest ratchet announce will encrypt to the long-term key as a fallback.

### 3.4 Source

`RNS/Cryptography/Token.py` (and the equivalents in vendor crypto modules).

---

## 4. Announce wire format

### 4.1 Packet body

The Reticulum packet header (HEADER_1, packet_type=ANNOUNCE, dest_type=SINGLE, transport_type=BROADCAST) is followed by an announce body:

```
public_key(64) || name_hash(10) || random_hash(10) || [ratchet_pub(32) if context_flag] || signature(64) || app_data(...)
```

The 64-byte `public_key` is the X25519 || Ed25519 concat described in section 1.1.

`random_hash` is **NOT** 10 random bytes — only the first 5 bytes are random; the trailing 5 bytes carry the emission timestamp as a big-endian unsigned 40-bit Unix-seconds integer (`RNS/Destination.py:282`):

```python
random_hash = RNS.Identity.get_random_hash()[0:5] + int(time.time()).to_bytes(5, "big")
```

Transit relays read the timestamp portion via `Transport.timebase_from_random_blob(random_blob) = int.from_bytes(random_blob[5:10], "big")` (`RNS/Transport.py:3272-3273`) to make ordering decisions when an inbound announce carries a higher hop count than the cached path: only newer-emitted announces can refresh the path table (see §4.5). 5 bytes of seconds covers ~34,000 years, so wraparound is not a near-term concern. Implementations MUST emit this exact format, including a clock value that's monotonically non-decreasing across announces from the same destination — clockless sender devices (per §9.6) may end up locked out of long-range path table updates.

> ⚠️ **UNVERIFIED — Known deviation:** `attermann/microReticulum/src/Destination.cpp:270-272` (and therefore every project that uses microReticulum unmodified, including [`thatSFguy/reticulum-lora-repeater`](https://github.com/thatSFguy/reticulum-lora-repeater) and the Faketec sibling project) currently emits 10 fully-random bytes for `random_hash` — the timestamp half is a TODO that never landed:
>
> ```cpp
> //p random_hash = Identity::get_random_hash()[0:5] << int(time.time()).to_bytes(5, "big")
> // CBA TODO add in time to random hash
> Bytes random_hash = Cryptography::random(Type::Identity::RANDOM_HASH_LENGTH/8);
> ```
>
> Python RNS receivers interpret `random_hash[5:10]` as a big-endian uint40 unix_seconds. A uniformly-random uint40 has median value ~5.5×10¹¹ ≈ year 19403 AD, so a microReticulum announce will (with overwhelming probability) appear "far-future" to a Python receiver. Effect: once one such announce populates `path_table[dest][IDX_PT_RANDBLOBS]`, the equal-or-greater-hop branch at `RNS/Transport.py:1854-1882` will reject any real-timestamped announce as "stale" until the path TTL expires. First-contact path-table population is unaffected; the bug only surfaces on path replacement under §4.5 step 6.3. The microReticulum receive side does NOT consult the timestamp half so microReticulum-to-microReticulum traffic is unaffected. The repeater repo's `pre_build.py` patches several microReticulum protocol bugs but not this one (as of [`thatSFguy/reticulum-lora-repeater@95823ad`-vintage upstream](https://github.com/thatSFguy/reticulum-lora-repeater)). Verifying by capture-and-decode against an actual mixed-vendor mesh is the work that would let this callout be removed.

The optional 32-byte `ratchet_pub` (an X25519 public key) is present iff the packet header's `context_flag` bit is 1. Indexing through this layout accordingly is mandatory; see `RNS/Identity.py::validate_announce` for the canonical parser.

### 4.2 Signed data

```
signed_data = dest_hash(16) || public_key(64) || name_hash(10) || random_hash(10) || [ratchet_pub(32)] || app_data
signature   = Ed25519_sign(signed_data, identity.Ed25519_priv)
```

Note that `dest_hash` is INCLUDED in the signed data even though it's not in the wire-format announce body (the receiver gets it from the packet header). The signing key is the Ed25519 half (last 32 bytes) of the identity's `private_key`.

### 4.3 `app_data` format for LXMF delivery destinations

Upstream `LXMF/LXMRouter.py::get_announce_app_data` produces a 3-element msgpack array (verified against LXMF 1.1.1 by `tools/verify_announce_app_data.py`):

```python
# LXMF/LXMRouter.py:1034-1050 in LXMF 1.1.1
supported_functionality = [SF_COMPRESSION]                          # LXMF/LXMF.py:142
peer_data = [display_name, stamp_cost, supported_functionality]     # stamp_cost = None unless 1 ≤ N ≤ 254
return msgpack.packb(peer_data)
```

Wire bytes for `display_name = "Reticulum5"`, `stamp_cost = None`, `supported_functionality = [SF_COMPRESSION]`:

```
93         # fixarray, 3 elements
c4 0a      # bin8, length 10
52 65 74 69 63 75 6c 75 6d 35    # "Reticulum5"
c0         # nil (stamp_cost)
91         # fixarray, 1 element (supported_functionality)
00         # SF_COMPRESSION
```

Encoding the display name as msgpack `bin` (`0xc4 NN`) is required for upstream interop — see section 9.3 below. The stamp_cost field can be `int 0` (`0x00`) or `nil` (`0xc0`); upstream's `stamp_cost_from_app_data` doesn't strict-type-check.

**The third element `[capability_flags]`** (a list; the only flag currently defined is `SF_COMPRESSION = 0x00` at `LXMF/LXMF.py:142`) **is emitted by the LXMF 1.0.x+ producer** — `LXMRouter.py:1047-1048` (LXMF 1.1.1) computes `supported_functionality = [SF_COMPRESSION]` and appends it to `peer_data`. Note this changed: the LXMF 0.9.7 producer computed the list but never appended it, so announces from `≤ 0.9.x` carry only 2 elements. The parser reads the element via `compression_support_from_app_data` (`LXMF/LXMF.py:187-199`): a missing third element, or a non-list third element, is treated as "compression supported"; otherwise support is `SF_COMPRESSION in peer_data[2]`. Receivers MUST therefore accept the 2-element form (older deployments) and the 3-element form (LXMF 1.0.x+) interchangeably.

The parser also tolerates a 1-element msgpack array (just the name) and a raw UTF-8 string ("original announce format" branch at `LXMF/LXMF.py:151-153`) — see `LXMF/LXMF.py::display_name_from_app_data` for all four accepted shapes.

### 4.4 Announce filtering by `name_hash`

When ingesting an announce, clients should distinguish by `name_hash`:

- `lxmf.delivery` (`6ec60bc318e2c0f0d908`) — messagable peers, surface in contacts UI
- `lxmf.propagation` (`e03a09b77ac21b22258e`) — propagation node, surface separately
- `nomadnetwork.node` (`213e6311bcec54ab4fde`) — page-serving NomadNet host
- `rnstransport.broadcasts` / `rnstransport.remote.management` — transport-internal, ignore for user UI
- Any other `name_hash` — non-LXMF custom destination (telemetry beacons, application-specific)

Treating every announce as a contact (the naive default) populates the UI with hundreds of irrelevant rows.

### 4.5 Announce validation rules (receive side)

These are the MUST rules a receiver applies to every inbound announce before considering the announced destination "known". The canonical implementation is `RNS/Identity.py::validate_announce` (line 511-612 in RNS 1.4.2); the dispatch site that calls it is `RNS/Transport.py::inbound` line 1748-1774.

#### 1. Body parse — branch on `context_flag`

The `context_flag` bit (bit 5 of the packet's 1-byte flag field, §2.1) selects between two body layouts. Slice offsets, with `keysize = 64`, `name_hash_len = 10`, `random_hash_len = 10`, `ratchet_size = 32`, `sig_len = 64`:

```
context_flag == 1 (ratchet present):
   public_key   = data[ 0                                     :  64]
   name_hash    = data[ 64                                    :  74]
   random_hash  = data[ 74                                    :  84]
   ratchet_pub  = data[ 84                                    : 116]
   signature    = data[116                                    : 180]
   app_data     = data[180                                    :    ]   # may be empty

context_flag == 0 (no ratchet):
   public_key   = data[ 0                                     :  64]
   name_hash    = data[ 64                                    :  74]
   random_hash  = data[ 74                                    :  84]
   signature    = data[ 84                                    : 148]
   app_data     = data[148                                    :    ]   # may be empty
```

A client that uses a fixed offset for `signature` regardless of the flag silently rejects every ratchet-bearing announce as having a bad signature.

#### 2. Signature verification

Reconstruct the signed_data exactly per §4.2:

```
signed_data = destination_hash || public_key || name_hash || random_hash || ratchet || app_data
```

Where `ratchet` is `b""` (empty, **not** absent) when `context_flag == 0`, and `app_data` is `b""` when not present in the packet. `destination_hash` comes from the **outer packet header**, NOT from the announce body — re-using the body bytes as the dest_hash would let a sender forge announces for arbitrary destinations.

Verify the 64-byte signature with the announced public_key's Ed25519 half (last 32 bytes). Reject on failure.

#### 3. `destination_hash` recomputation

Recompute the dest_hash from the announced inputs:

```
identity_hash    = SHA256(public_key)[:16]
expected_hash    = SHA256(name_hash || identity_hash)[:16]
```

Reject the announce iff `expected_hash != packet.destination_hash` (the value from the outer header). This catches both random hash collisions and active spoofing attempts that pair a valid signature with an unrelated dest_hash. (`RNS/Identity.py:562-565`).

#### 4. Public-key collision rejection

If the receiver already has a different public_key cached for this `destination_hash` (from a prior announce), the new announce MUST be rejected with a critical-severity log even if the signature is otherwise valid. Per the upstream comment: "In reality, this should never occur, but in the odd case that someone manages a hash collision, we reject the announce" (`RNS/Identity.py:569-575`).

This rule means: **first-announcer-wins for any given destination_hash** within a receiver's lifetime. A peer who loses their identity material and regenerates with the same display name + app_name will produce a different identity_hash → different destination_hash → no collision. A peer who tries to *replace* their announced public key under the same destination_hash, however, gets rejected — the real defense against this class of attack.

#### 5. Blackhole list check

Before everything else, check `RNS.Transport.blackholed_identities`. An identity_hash on the blackhole list is dropped silently regardless of signature validity (`RNS/Identity.py:551-554`). This is operator-controlled state, not a wire feature.

#### 6. Caching the announce contents

On a fully validated announce, the receiver MUST update its caches in this order:

1. **`known_destinations[destination_hash]`** ← `[recv_time, packet_hash, public_key, app_data, last_used]` — populates the table that `RNS.Identity.recall(dest_hash)` reads when constructing outbound destinations (`RNS/Identity.py::remember`, line 101-113). Without this, every subsequent outbound message to this peer fails because no public key is available for Token encryption.
2. **`known_ratchets[destination_hash]`** ← `ratchet_pub` (only if `context_flag == 1` and `ratchet_pub != b""`) — `Identity._remember_ratchet`, line 395-428. The ratchet is also persisted to disk under `{storagepath}/ratchets/{hexhash}` for use across restarts.
3. **`path_table`** entry update or insertion (see §4.6 — TBD when the relay rebroadcast spec lands), gated by:
   - `random_blob` (= `random_hash`) not in the cached `random_blobs` history for this destination — cheap replay defence (`RNS/Transport.py:1832, 1865, 1876`).
   - Hop count comparison against any existing entry: equal-or-fewer hops always win; more hops win only if the cached path has expired or the new announce's emission timestamp (from `random_hash[5:10]`) is more recent than every cached blob's timestamp (`RNS/Transport.py:1821-1882`).

#### 7. `PATH_RESPONSE` distinction

An announce whose outer packet `context == PATH_RESPONSE (0x0B)` is the responder's reply to a recent `path?` request, not a periodic re-announce. Validation is identical (rules 1-6 above), but listener dispatch differs:

- The default behavior of `Transport.announce_handlers` registered via `RNS.Transport.register_announce_handler` is to **skip** path-response announces unless the handler sets `receive_path_responses = True` on itself (`RNS/Transport.py:2089-2092`).
- The path table population path is the same either way — both regular and path-response announces refresh the path entry — so a leaf client that ignores PATH_RESPONSE entirely at the application layer still benefits from the path-table side effect.

#### 8. Implementation-private behavior (SHOULD)

These are not wire-spec MUST rules but most working clients implement them; without them the implementation will misbehave in busy meshes:

- **Per-interface ingress rate limiting.** When the inbound announce rate on an interface exceeds `IC_BURST_FREQ_NEW = 6 Hz` (interfaces less than 2 hours old) or `IC_BURST_FREQ = 35 Hz` (older), and the announced destination is **not** in `path_table` and **not** in `path_requests`, the announce is held in the interface's `held_announces` dict for later release rather than processed immediately. Released later in lowest-hop-count-first order. (`RNS/Interfaces/Interface.py:60-200`.) Without this, a flood of unknown-destination announces can drown out everything else.
- **`random_blob` history cap.** The cached `random_blobs` list per destination is bounded by `Transport.MAX_RANDOM_BLOBS` (= 64 in RNS 1.4.2 at `RNS/Transport.py:99`) to keep the path table from growing without bound under a long-lived destination's announce stream (`RNS/Transport.py:1943`).
- **Self-announce filter.** §9.5 — drop announces where `destination_hash` matches one of the receiver's own destinations to avoid populating its own contact list with itself.

#### 9. Source map for §4.5

| File | What it pins down |
|---|---|
| `RNS/Identity.py:511-612` | `validate_announce` — body parse, signed_data, sig verify, dest_hash recompute, collision check |
| `RNS/Identity.py:101-113` | `Identity.remember` — `known_destinations` update |
| `RNS/Identity.py:410-443` | `_remember_ratchet` — ratchet persistence |
| `RNS/Transport.py:1748-2129` | inbound dispatch for `packet_type == ANNOUNCE`: quick sig check, ingress limiting, path table population, handler dispatch |
| `RNS/Transport.py:3272-3289` | `timebase_from_random_blob`, `announce_emitted` |
| `RNS/Interfaces/Interface.py:60-200` | ingress-limit constants, `should_ingress_limit`, `hold_announce`, `process_held_announces` |
| `RNS/Packet.py:83` | `PATH_RESPONSE = 0x0B` context constant |

### 4.6 `rrc.hub` announce app_data (Reticulum Relay Chat)

Reticulum Relay Chat hubs announce a destination on the `rrc.hub`
aspect — `name_hash = SHA256("rrc.hub")[:10] = ac9fd3a81e4036f86e1d`.
Unlike §4.3 (LXMF delivery), the `app_data` is **not** a msgpack
`[name, cost]` array, and the two hub implementations disagree on
its shape:

- **`rrcd`** — the Python reference hub. `app_data` is a **CBOR**
  (RFC 8949) map: `{"proto": "rrc", "v": 1, "hub": <hub_name>}` —
  CBOR, *not* msgpack, because RRC's wire codec (`rrcd/codec.py`,
  Python `cbor2`) is CBOR throughout. The human hub name is the
  `"hub"` key's value (a text string); `"proto"` is always `"rrc"`
  and `"v"` is the app_data schema version (`1`). Source: `rrcd`
  `service.py` — `app_data = encode({"proto": "rrc", "v": 1, "hub":
  self.config.hub_name})`, where `encode` is the CBOR encoder.
- **`reticulum-relay-chat`** — the Go hub. `app_data` is the hub name
  as **plain UTF-8 bytes**, unwrapped. Source:
  `internal/service/service.go` — `BuildAnnounce(id, "rrc.hub",
  []byte(s.cfg.Hub.Name), ...)`.

> ⚠️ **CBOR-vs-msgpack gotcha.** A CBOR 3-entry map begins with byte
> `0xa3`. In msgpack `0xa3` is `fixstr` of length 3 — so a client that
> blindly msgpack-decodes the `rrcd` app_data reads the next three
> bytes (`0x65 0x70 0x72`, the CBOR text-string header of `"proto"`
> plus its first two characters) as the 3-character string `"epr"`.
> Decode `rrc.hub` app_data with a CBOR decoder, keyed on the
> `rrc.hub` name_hash — do not feed it to the LXMF (msgpack) app_data
> parser.

A client listing RRC hubs should resolve the name as: the `"hub"`
value when `app_data` CBOR-decodes to a map; else a bare UTF-8 string
(the Go hub's shape); else a generic "RRC hub" label. The same name
is also delivered authoritatively in the RRC `WELCOME` body key
`B_WELCOME_HUB` once a session is established.

---

## 5. LXMF wire format

LXMF has two delivery methods with **different** plaintext layouts.

### 5.1 Opportunistic delivery (single Reticulum DATA packet)

Plaintext (after Token decryption):

```
source_hash(16) || signature(64) || msgpack_payload(...)
```

The recipient's destination_hash is **stripped** (the outer Reticulum packet's `dest_hash` already conveys it; including it would waste bytes).

### 5.2 Direct delivery (over an established Reticulum Link)

```
destination_hash(16) || source_hash(16) || signature(64) || msgpack_payload(...)
```

Full layout. The Link's session key encrypts the whole blob.

### 5.3 `msgpack_payload`

A msgpack array of 4 elements (5th optional):

```python
[timestamp_seconds_double, title_bytes, content_bytes, fields_dict]
# optional 5th element: stamp (varies)
```

Times are seconds-since-Unix-epoch as a double-precision float. Title and content are msgpack `bin` (Python `bytes`). Fields is a msgpack map; usually `{}` for plain text, but used for attachments, stickers, etc.

### 5.4 Source/destination semantics

`source_hash` is the SENDER's **destination hash** (`SHA256(name_hash || identity_hash)[:16]`), NOT the raw identity hash. A common implementation bug is to write the identity_hash here; the recipient then can't look the sender up in their contacts (which are keyed by destination_hash).

### 5.5 Signed data

```
hashed_part  = destination_hash(16) || source_hash(16) || msgpack_payload
message_hash = SHA256(hashed_part)
signed_data  = hashed_part || message_hash
signature    = Ed25519_sign(signed_data, sender_identity.Ed25519_priv)
```

For opportunistic delivery, `destination_hash` is the recipient's destination hash (from the outer packet header, not from the LXMF body).

The `msgpack_payload` MUST be the exact bytes received on the wire — not a decode-then-re-encode — when computing `message_hash`. The same value is reused as the LXMF `message_id` (workblock input for stamps in §5.7, target identifier for reactions in §5.9.8 and replies in §5.9.9). A receiver that re-encodes will compute a divergent identifier for any message whose `fields` map does not round-trip byte-identically — most commonly reply messages — which breaks both the §5.6 path-1 raw-signature check and any relay rewrite-cache keyed on the value. For a stamped message (§5.7.1) the raw payload on the wire is a 5-element array; the hash is over the first 4 elements, which requires a byte-canonical re-pack per §5.6.1.

### 5.6 Signature verification — msgpack variant tolerance

Different msgpack encoders produce subtly different byte sequences for the same logical value (e.g. integer encoding choice, string vs bin selection). The signer signed over THEIR encoder's output. A receiver should try verifying against:

1. The **raw** msgpack bytes from the wire as-received (`msgpack_payload` exactly).
2. A **stripped** re-encoded version (decode then re-encode the first 4 elements, omitting the optional stamp field).

If either matches, the signature is valid. Strict raw-only verification fails interop with anything that's been through a msgpack re-encode somewhere in the chain.

#### 5.6.1 Canonical encoder for senders

RNS bundles `umsgpack` (`RNS/vendor/umsgpack.py`) and uses it for every signing input on the upstream Python side. Senders SHOULD produce signing-input bytes that match `umsgpack`'s output for the LXMF payload types so receivers' path-1 (raw) verification succeeds and the path-2 (decode + re-encode) fallback stays defensive rather than load-bearing:

| Logical type | umsgpack canonical form |
|---|---|
| Python `str` / UTF-8 text | `str` family — `fixstr` / `str8` / `str16` / `str32`, smallest that fits |
| Python `bytes` | `bin` family — `bin8` / `bin16` / `bin32`, smallest that fits |
| Integer | smallest signed integer envelope that fits — positive fixint, `uint8`/`16`/`32`/`64`, negative fixint, `int8`/`16`/`32`/`64` (per umsgpack's `_pack_integer`) |
| Float | `float64` always (9 bytes including the type byte) — never `float32`, even for integer-valued doubles |
| Map | sorted-by-insertion-order — umsgpack preserves input order, does NOT lex-sort keys |

Mismatches most often originate from integer width (a timestamp encoded as `uint32` by one library and `float64` by another round-trips the same logical value but produces different bytes) and from JS encoders that prefer `str` for byte strings or `float32` for non-integer numbers. Implementing `umsgpack`'s "minimum width that fits" rule for ints and "always float64" rule for floats is sufficient for byte-identical signature inputs against upstream Python LXMF.

### 5.7 LXMF stamps and tickets (anti-spam)

`LXMF.LXMessage.payload[4]` (the optional 5th element of the msgpack body — see §5.3) is a **stamp**: a proof-of-work value that lets a recipient gate inbound messages against unsolicited senders. Modern Sideband installs (≥ 1.x) treat unstamped messages as low-trust and may drop them at the application layer.

#### 5.7.1 Stamp wire format

`LXMessage.STAMP_SIZE = HASHLENGTH//8 = 32 bytes` (`LXMF/LXStamper.py`). The stamp is appended to the payload msgpack array as the 5th element only if the receiver requires one or the sender has an outbound ticket. Wire form is just 32 raw bytes inside a `bin8/bin16` msgpack envelope.

When stripping the stamp during signature verification (§5.6), the receiver removes element [4] from the unpacked array and re-encodes the first 4 elements as `packed_payload` for hash computation. This is what lets a sender add or remove a stamp without invalidating the Ed25519 signature.

#### 5.7.2 Stamp generation (proof-of-work)

`LXMF/LXStamper.py::generate_stamp(message_id, target_cost)` and `::stamp_valid(stamp, target_cost, workblock)`. The algorithm:

1. **Workblock construction** — expensive HKDF-driven memory inflation:
   ```python
   def stamp_workblock(material, expand_rounds=3000):       # WORKBLOCK_EXPAND_ROUNDS
       workblock = b""
       for n in range(expand_rounds):
           workblock += RNS.Cryptography.hkdf(
               length=256,
               derive_from=material,
               salt=RNS.Identity.full_hash(material + msgpack.packb(n)),
               context=None)
       return workblock                                     # 768 KiB total
   ```
   `material` is the 32-byte `message_id` (= `SHA256(dest_hash || src_hash || msgpack_payload)`). 3000 rounds of 256-byte HKDF produces a 768 KiB workblock — designed to be cache-unfriendly enough that GPU/ASIC speedup is limited.

2. **Stamp search** — find a 32-byte value such that `SHA256(workblock || stamp)` has at least `target_cost` leading zero bits:
   ```python
   def stamp_valid(stamp, target_cost, workblock):
       target = 1 << (256 - target_cost)
       return int.from_bytes(SHA256(workblock + stamp), "big") <= target
   ```
   The `target_cost` is the Hamming-distance-from-2^256 in bit-leading-zeros — `target_cost = 8` means the result must be ≤ `2^248`, i.e. start with at least 8 zero bits.

3. **Stamp value** — for received valid stamps, `stamp_value(workblock, stamp)` returns the actual leading-zero count, which can exceed the recipient's required cost. Exceeded cost = "extra effort spent" and is exposed to the application for prioritization.

The default `WORKBLOCK_EXPAND_ROUNDS = 3000` (regular stamps), `WORKBLOCK_EXPAND_ROUNDS_PN = 1000` (propagation-node stamps — cheaper because store-and-forward already throttles), `WORKBLOCK_EXPAND_ROUNDS_PEERING = 25` (peering keys between propagation nodes — even cheaper).

#### 5.7.3 Tickets — pre-shared shortcut around proof-of-work

A **ticket** is a 16-byte (`TICKET_LENGTH = TRUNCATED_HASHLENGTH//8`) shared secret a recipient hands to a known sender, letting them skip the PoW step. With a ticket, the "stamp" becomes:

```python
stamp = SHA256(ticket || message_id)[:32]      # truncated to STAMP_SIZE
```

(`LXMessage.py::get_stamp` line 297). The recipient validates by trying every ticket they've issued the sender against the inbound stamp:

```python
# LXMessage.py::validate_stamp line 270-280
for ticket in tickets:
    if self.stamp == RNS.Identity.truncated_hash(ticket + self.message_id):
        self.stamp_value = LXMessage.COST_TICKET
        return True
```

`COST_TICKET` is a sentinel value (not a real cost) that just marks "valid by ticket".

Tickets are exchanged via the **`FIELD_TICKET = 0x0C`** key in the `fields` dict of an inbound message:

```python
# LXMRouter.lxmf_delivery, line 1741-1752
if message.signature_validated and FIELD_TICKET in message.fields:
    ticket_entry = message.fields[FIELD_TICKET]   # [expires_unix_seconds, ticket_bytes]
    if type(ticket_entry) == list and len(ticket_entry) > 1:
        if time.time() < ticket_entry[0]:
            self.remember_ticket(message.source_hash, ticket_entry)
```

Format: `fields[FIELD_TICKET] = [expires_unix_seconds(int), ticket(bytes, 16)]`. Stored under the sender's `source_hash` in the receiver's persistent ticket cache. Subsequent outbound messages from the receiver to the same sender automatically use this ticket via `LXMessage.outbound_ticket`. Tickets expire at `expires_unix_seconds`; expired tickets are evicted and the next outbound message falls back to PoW.

#### 5.7.4 The full stamp-cost field inventory

LXMF announces (§4.3) carry a `stamp_cost` integer in the `app_data` msgpack array's element [1]. A receiver tells potential senders "you must do this much PoW to message me" by setting their delivery destination's `stamp_cost` and re-announcing. Senders who get this announce store the cost in `RNS.Identity.known_destinations[dest_hash][3].app_data` and apply it to outbound messages via `LXMRouter.outbound_stamp_costs`.

When a receiver gets a message:

- If `delivery_destination.stamp_cost == None`: no stamp required; messages without one are accepted.
- If `delivery_destination.stamp_cost != None` AND the inbound message has no valid stamp AND `_enforce_stamps == True`: the message is **dropped** (`LXMRouter.py:1871-1872`).
- If `_enforce_stamps == False` (default): the message is accepted regardless, and the application is told via `message.stamp_valid` whether the stamp checked out.

A clean-room implementation that doesn't implement stamps at all will:
- Successfully send to peers with `stamp_cost = None`.
- Be silently rejected by peers with `stamp_cost != None` AND `_enforce_stamps`.
- Be flagged as "untrusted" / "spam" in receiver UIs that promote stamp validation to a UX signal even without enforcement.

For interop coverage today, "implement PoW for outbound; tolerate-but-don't-validate inbound" is the minimum. Full ticket support is a Tier-3 nice-to-have.

#### 5.7.5 Source map

| File | What |
|---|---|
| `LXMF/LXStamper.py:18-46` | `stamp_workblock`, `stamp_value`, `stamp_valid` |
| `LXMF/LXMessage.py:41` | `TICKET_LENGTH = 16` |
| `LXMF/LXMessage.py:270-291` | `validate_stamp` (ticket-then-PoW dispatch) |
| `LXMF/LXMessage.py:293-324` | `get_stamp` (ticket-or-PoW emission) |
| `LXMF/LXMRouter.py:1837-1910` | inbound dispatch — ticket cache + stamp validation + drop logic |
| `LXMF/LXMF.py:19` | `FIELD_TICKET = 0x0C` constant |

### 5.8 Propagation node protocol (offline message store-and-forward)

A **propagation node** is an LXMF node configured to accept and store messages on behalf of recipients who are temporarily offline, then deliver them when the recipient comes back online and asks. Without propagation nodes, every message requires both peers online simultaneously — a fatal assumption for mobile / mesh-edge deployments. Propagation nodes form a peer mesh that syncs messages between themselves so a recipient can retrieve mail from any one of them.

The `PROPAGATED` LXMF method (`LXMessage.py:423-441`, mentioned in `flows/send-link-lxmf.md` step 3) submits a message to a propagation node rather than directly to the recipient. The propagation node stores it and offers it to peers via §5.8.2 sync, and to the recipient via §5.8.3 retrieval.

#### 5.8.1 The `lxmf.propagation` destination

Every propagation node registers a SINGLE destination of name `lxmf.propagation` (`LXMRouter.py:190`):

```python
self.propagation_destination = RNS.Destination(
    self.identity, IN, SINGLE, APP_NAME, "propagation",
)
```

Per §1.2, the well-known `name_hash` is `e03a09b77ac21b22258e` (`SHA256("lxmf.propagation")[:10]`). The propagation node's identity is its own — different propagation nodes have different identity hashes and therefore different destination hashes. Receivers of `lxmf.propagation` announces filter by name_hash to surface "propagation node available" UI separately from "messageable peer available" UI per §4.4.

A propagation node registers request handlers across **two** destinations, not one (`LXMRouter.py:669-676`; verified by `tools/verify_lxmf_peer_constants.py`):

| Path | Constant | Destination | Allow | Purpose |
|---|---|---|---|---|
| `/offer` | `LXMPeer.OFFER_REQUEST_PATH` | `lxmf.propagation` | `ALLOW_ALL` | Peer-to-peer message-set offer (§5.8.2) |
| `/get` | `LXMPeer.MESSAGE_GET_PATH` | `lxmf.propagation` | `ALLOW_ALL` | Client message retrieval (§5.8.3) |
| `/pn/get/stats` | `LXMRouter.STATS_GET_PATH` | `lxmf.propagation.control` | `ALLOW_LIST` | Operator stats query |
| `/pn/peer/sync` | `LXMRouter.SYNC_REQUEST_PATH` | `lxmf.propagation.control` | `ALLOW_LIST` | Operator-triggered sync push |
| `/pn/peer/unpeer` | `LXMRouter.UNPEER_REQUEST_PATH` | `lxmf.propagation.control` | `ALLOW_LIST` | Operator-triggered peer removal |

The two public paths (`/offer`, `/get`) are the interop surface and are the only ones an ordinary client or peer uses. The three `/pn/…` control paths are registered on a **separate** destination — `RNS.Destination(identity, IN, SINGLE, "lxmf", "propagation", "control")`, name_hash `4576672b3f55049c2e46` — whose `allowed_list` is `[self.identity.hash]`, i.e. the node's own operator identity and nobody else. A client MUST NOT expect to reach them on the `lxmf.propagation` destination hash, and an implementation that omits them entirely is still spec-compliant for interop; they exist so an operator can drive their own node remotely.

All five are reached over an active Reticulum Link via the §11 REQUEST/RESPONSE protocol. The link must be `identify()`-d first in every case: `/offer` and `/get` use the identity to decide *whose* mail is being offered or fetched, and the control paths reject an unidentified link with `ERROR_NO_IDENTITY` before any allow-list check (`LXMRouter.py:843-844`, `:855-856`).

Both control-path handlers that take an argument (`/pn/peer/sync`, `/pn/peer/unpeer`) expect `data` to be a bare 16-byte peer destination hash — not a msgpack wrapper — and return `ERROR_INVALID_DATA` for any other type or length, `ERROR_NOT_FOUND` if that hash isn't a current peer, and `True` on success (`LXMRouter.py:843-866`).

#### 5.8.2 Peer-to-peer sync via `/offer`

Two propagation nodes that have peered with each other periodically sync. The initiator sends an `/offer` REQUEST whose `data` is:

```python
data = [peering_key(32), [transient_id_1, transient_id_2, ...]]
```

Where:

- `peering_key` is a 32-byte proof-of-work key per §5.8.4.
- `transient_id_N` is the 16-byte hash of an LXM (`= SHA256(lxmf_data)[:16]` — the truncated hash of the full encrypted LXMF body) that the offering node has and thinks the receiving node might want.

The receiving node validates the peering_key, then for each `transient_id`:

- If it already has the message in `propagation_entries`: skip.
- Otherwise: add to `wanted_ids`.

Then returns one of three response shapes (`LXMRouter.py:2320-2328`):

| Response | Meaning |
|---|---|
| `False` (boolean) | Peer already has every offered message; no transfer needed. |
| `True` (boolean) | Peer wants every offered message. |
| `[wanted_id_1, ...]` (list) | Peer wants the listed subset only. |

If the response indicates the peer wants any messages, the offering node packs them into a Resource (§10) and sends:

```python
resource_data = msgpack.packb([time.time(), [lxmf_data_1, lxmf_data_2, ...]])
RNS.Resource(resource_data, link, callback=...)
```

The Resource contains the **full encrypted LXMF bodies** — the bytes that were signed and encrypted by the original sender; the propagation nodes never decrypt them. The receiving node writes each one to its propagation store under its `transient_id` key.

Error responses (`LXMPeer.py:24-31`):

| Constant | Hex | Meaning |
|---|---|---|
| `ERROR_NO_IDENTITY` | `0xf0` | Link wasn't `identify()`-d before the offer arrived. Initiator should retry with `link.identify()`. |
| `ERROR_NO_ACCESS` | `0xf1` | Peer rejected (e.g. `from_static_only=True` on the receiver). |
| `ERROR_INVALID_KEY` | `0xf3` | Peering key failed proof-of-work validation. |
| `ERROR_INVALID_DATA` | `0xf4` | Offer payload didn't match the expected `[key, [ids]]` shape. |
| `ERROR_INVALID_STAMP` | `0xf5` | Inbound stamp failed validation. |
| `ERROR_THROTTLED` | `0xf6` | Peer is rate-limiting; postpone for `PN_STAMP_THROTTLE` (default 30 minutes). |
| `ERROR_NOT_FOUND` | `0xfd` | Control paths only: the 16-byte hash passed to `/pn/peer/sync` or `/pn/peer/unpeer` is not a current peer. |
| `ERROR_TIMEOUT` | `0xfe` | Request timed out. |

> ⚠️ There is a gap at `0xf2` — upstream defines no constant for it. Values are **not** contiguous;
> implementations MUST use the literal values above rather than deriving them from an enumeration order.

#### 5.8.3 Client retrieval via `/get`

A regular LXMF client (Sideband, NomadNet client, custom) retrieves stored messages with an `/get` REQUEST whose `data` is:

```python
data = [wanted_ids, have_ids, optional_transfer_limit_kb]
```

Where:

- **`wanted_ids = None`** AND **`have_ids = None`** triggers a **listing query**: the propagation node returns `[transient_id_1, transient_id_2, ...]` of every message it holds for the requesting identity, sorted by size ascending.
- **`wanted_ids`** is a list of transient_ids the client wants delivered. Propagation node responds with a Resource (or single packet if small enough) carrying `msgpack.packb([time.time(), [lxmf_data_1, ...]])`.
- **`have_ids`** is a list of transient_ids the client confirms it has stored locally. Propagation node deletes those from its store. (Equivalent to "ack and purge".)
- **`optional_transfer_limit_kb`** lets the client cap the transfer size — propagation node skips messages that would exceed the cap.

Common usage: client first sends `/get` with `[None, None]` to get the list, picks which ones it wants based on size, then sends `/get` with `[wanted_subset, prior_subset_to_purge]` to fetch the new ones and acknowledge previously-fetched ones.

The propagation node only returns messages whose `propagation_entries[tid][0] == requester's destination_hash` (`LXMRouter.py:1510, 1535`) — each message is keyed to its intended recipient and the propagation node is structurally unable to deliver it to the wrong address. The LXMF body is still encrypted to the recipient's public key as a defence-in-depth.

#### 5.8.4 Peering keys (PoW for peer-to-peer auth)

Two propagation nodes that want to peer must each compute a peering key for the relationship (`LXStamper.py::validate_peering_key` and `stamp_workblock` with `WORKBLOCK_EXPAND_ROUNDS_PEERING = 25`):

```python
peering_id = self.identity.hash + remote_identity.hash    # 32 bytes (16 + 16)
workblock  = stamp_workblock(peering_id, expand_rounds=25)
peering_key = (find any 32B value such that
               SHA256(workblock || peering_key)
               has at least target_cost leading zero bits)
```

`target_cost` is the receiving node's `peering_cost` (announced in element [5][2] of the propagation announce app_data, see §5.8.5). With only 25 rounds of HKDF expansion (vs 3000 for regular message stamps in §5.7), the workblock is ~6 KiB and peering keys can be computed in milliseconds. Peering keys are amortized: computed once between two propagation nodes and reused for every subsequent `/offer` for the lifetime of the peering.

#### 5.8.5 Propagation node announce app_data

Distinct from §4.3 (which is for `lxmf.delivery`). For `lxmf.propagation` announces, `LXMRouter.get_propagation_node_app_data` (line 324-336) emits a 7-element msgpack array:

```python
announce_data = [
    False,                                  # [0] legacy-LXMF-PN-support flag (always False now)
    int(time.time()),                       # [1] node timebase (unix seconds, big-int)
    node_state,                             # [2] bool — accepting messages right now?
    propagation_per_transfer_limit,         # [3] int — per-transfer cap in KB
    propagation_per_sync_limit,             # [4] int — per-sync incoming cap in KB
    [stamp_cost, stamp_cost_flexibility,
     peering_cost],                         # [5] list of three ints
    metadata,                               # [6] dict — operator-supplied node metadata
]
return msgpack.packb(announce_data)
```

Element [5] sub-fields:

| Index | Name | Meaning |
|---|---|---|
| `[5][0]` | `stamp_cost` | PoW cost (leading zero bits) for client `/get` retrieval stamps |
| `[5][1]` | `stamp_cost_flexibility` | Tolerance — client stamps within this many bits below `stamp_cost` are still accepted |
| `[5][2]` | `peering_cost` | PoW cost for peering keys per §5.8.4 |

Receivers parse this via `pn_announce_data_is_valid` (`LXMF/LXMF.py:191-206`), which insists on exactly 7 elements with type-correct positions. **A client that misparses element [5] as a single integer (rather than a 3-element list) silently fails to compute the right peering / retrieval stamp and is rejected** — this is the most common interop break in custom propagation-node implementations.

#### 5.8.6 Source map

| File | What |
|---|---|
| `LXMF/LXMRouter.py:190` | propagation_destination construction |
| `LXMF/LXMRouter.py:324-336` | propagation announce app_data shape |
| `LXMF/LXMRouter.py:669-670` | `/offer` and `/get` handler registration |
| `LXMF/LXMRouter.py:1426-1500` | `message_get_request` handler (client `/get`) |
| `LXMF/LXMRouter.py:2145-2200` | `offer_request` handler (peer `/offer`) |
| `LXMF/LXMPeer.py:14-31` | request-path, peer-state and error-response constants |
| `LXMF/LXMPeer.py:373-489` | initiator-side `/offer` flow |
| `LXMF/LXStamper.py::validate_peering_key` | peering-key PoW validation |
| `LXMF/LXMF.py:191-206` | `pn_announce_data_is_valid` parser |

### 5.9 LXMF field constants and helper specifiers

The `fields` dict inside an LXMF message (the 4th element of the msgpack array described in §5.3) is keyed by 1-byte integers. Upstream `LXMF/LXMF.py` (verified against LXMF 1.1.1 by `tools/verify_lxmf_fields.py`) defines the following allocations.

#### 5.9.1 Top-level `fields` dict keys

Sender and receiver agree on these keys; each value's structure is field-specific (described below where it matters at byte level).

| Key | Constant | Purpose |
|---|---|---|
| `0x01` | `FIELD_EMBEDDED_LXMS` | A list of further LXMF messages embedded inside this one (used for forwarding / bundling). |
| `0x02` | `FIELD_TELEMETRY` | A single telemetry snapshot (Sideband telemetry — see Sideband for the inner format; LXMF is opaque to the contents). |
| `0x03` | `FIELD_TELEMETRY_STREAM` | A list of telemetry snapshots (history flush). |
| `0x04` | `FIELD_ICON_APPEARANCE` | Sender-supplied avatar / appearance hint. |
| `0x05` | `FIELD_FILE_ATTACHMENTS` | A list of attached files (multiple attachments per message). See §5.9.7 for the wire shape. |
| `0x06` | `FIELD_IMAGE` | Single embedded image — `[extension_string, image_bytes]`. See §5.9.2 for the wire shape. |
| `0x07` | `FIELD_AUDIO` | Single embedded audio clip — `[mode_byte, audio_bytes]`. Mode byte chooses the codec; see §5.9.3. |
| `0x08` | `FIELD_THREAD` | Conversation thread ID (links related messages). |
| `0x09` | `FIELD_COMMANDS` | List of commands the sender is requesting the receiver execute (Sideband node/command protocol). |
| `0x0A` | `FIELD_RESULTS` | List of results for commands previously requested via `FIELD_COMMANDS`. |
| `0x0B` | `FIELD_GROUP` | Group / channel association metadata. |
| `0x0C` | `FIELD_TICKET` | Stamp ticket grant — `[expires_unix_seconds(int), ticket_bytes(16)]`. See §5.7 for the anti-spam protocol. |
| `0x0D` | `FIELD_EVENT` | Event-style payload (alert, state change). |
| `0x0E` | `FIELD_RNR_REFS` | Reticulum Node Registry references. |
| `0x0F` | `FIELD_RENDERER` | Renderer hint for the message `content` body — see §5.9.4 for accepted values. |
| `0x30` | `FIELD_REPLY_TO` | Reply threading — raw 32-byte target `message_id`. See §5.9.9. |
| `0x31` | `FIELD_REPLY_QUOTE` | Optional quoted content (UTF-8) for the reply identified by `FIELD_REPLY_TO`. See §5.9.9. |
| `0x40` | `FIELD_REACTION` | Tap-back reaction — dict `{REACTION_TO, REACTION_CONTENT}`. See §5.9.8. |
| `0x41` | `FIELD_COMMENT` | Marks this message as a comment on another — dict `{COMMENT_FOR}`. See §5.9.10. |
| `0x42` | `FIELD_CONTINUATION` | Marks this message as a continuation of another — dict `{CONTINUATION_OF}`. See §5.9.11. |
| `0xFB` | `FIELD_CUSTOM_TYPE` | App-defined type identifier accompanying `FIELD_CUSTOM_DATA`. |
| `0xFC` | `FIELD_CUSTOM_DATA` | App-defined opaque data — meaning given by `FIELD_CUSTOM_TYPE`. |
| `0xFD` | `FIELD_CUSTOM_META` | App-defined metadata alongside `FIELD_CUSTOM_DATA`. |
| `0xFE` | `FIELD_NON_SPECIFIC` | Development / unstructured payload — not for production. |
| `0xFF` | `FIELD_DEBUG` | Debug payload — not for production. |

> ⚠️ **UNVERIFIED:** the byte-level shape of `FIELD_EMBEDDED_LXMS`, `FIELD_TELEMETRY*`, `FIELD_COMMANDS`, `FIELD_RESULTS`, `FIELD_GROUP`, `FIELD_EVENT`, and `FIELD_RNR_REFS` is not described here because no test vectors have been captured against upstream Sideband emissions for these. The constants are verified (see `tools/verify_lxmf_fields.py`) but the value structures are application-defined and not pinned by LXMF itself. Future PRs should add per-field byte layouts as test vectors arrive. (`FIELD_FILE_ATTACHMENTS` was on this list until 2026-05-18 — its shape is now documented in §5.9.7 from upstream Sideband source.)

#### 5.9.2 `FIELD_IMAGE` (`0x06`) value shape

```
fields[0x06] = [extension_string(bytes-or-str), image_bytes(bytes)]
```

The `extension_string` is the lowercase file extension WITHOUT a leading dot ("jpg", "png", "webp"). The `image_bytes` is the raw image file content. Receivers must tolerate the extension arriving as either msgpack `str` (`0xa0..0xbf` / `0xd9..0xdb`) or msgpack `bin` (`0xc4..0xc6`) — different encoders pick differently. See §9.3 for the `str`-vs-`bin` distinction and §10 for how images larger than a single Reticulum DATA packet are delivered via Resource over a Link.

#### 5.9.3 `FIELD_AUDIO` (`0x07`) value shape

```
fields[0x07] = [mode_byte(int), audio_bytes(bytes)]
```

`mode_byte` is one of the `AM_*` constants defined in `LXMF/LXMF.py` (verified by `tools/verify_lxmf_fields.py`):

| Byte | Constant | Codec | Notes |
|---|---|---|---|
| `0x01` | `AM_CODEC2_450PWB` | Codec2 450 bps pseudo-wideband | |
| `0x02` | `AM_CODEC2_450` | Codec2 450 bps | |
| `0x03` | `AM_CODEC2_700C` | Codec2 700C | |
| `0x04` | `AM_CODEC2_1200` | Codec2 1200 bps | |
| `0x05` | `AM_CODEC2_1300` | Codec2 1300 bps | |
| `0x06` | `AM_CODEC2_1400` | Codec2 1400 bps | |
| `0x07` | `AM_CODEC2_1600` | Codec2 1600 bps | |
| `0x08` | `AM_CODEC2_2400` | Codec2 2400 bps | |
| `0x09` | `AM_CODEC2_3200` | Codec2 3200 bps | |
| `0x10` | `AM_OPUS_OGG` | Opus in OGG container | |
| `0x11` | `AM_OPUS_LBW` | Opus low-bandwidth | |
| `0x12` | `AM_OPUS_MBW` | Opus medium-bandwidth | |
| `0x13` | `AM_OPUS_PTT` | Opus push-to-talk profile | |
| `0x14` | `AM_OPUS_RT_HDX` | Opus realtime half-duplex | |
| `0x15` | `AM_OPUS_RT_FDX` | Opus realtime full-duplex | |
| `0x16` | `AM_OPUS_STANDARD` | Opus standard | |
| `0x17` | `AM_OPUS_HQ` | Opus high-quality | |
| `0x18` | `AM_OPUS_BROADCAST` | Opus broadcast | |
| `0x19` | `AM_OPUS_LOSSLESS` | Opus lossless | |
| `0xFF` | `AM_CUSTOM` | Client-detected — inspect `audio_bytes` to determine the codec |

#### 5.9.4 `FIELD_RENDERER` (`0x0F`) value shape

```
fields[0x0F] = renderer_byte(int)
```

One of the `RENDERER_*` constants:

| Byte | Constant | Rendering |
|---|---|---|
| `0x00` | `RENDERER_PLAIN` | Plain text — no formatting |
| `0x01` | `RENDERER_MICRON` | NomadNet Micron markup (see NomadNet docs) |
| `0x02` | `RENDERER_MARKDOWN` | CommonMark / GitHub-flavored Markdown |
| `0x03` | `RENDERER_BBCODE` | BBCode-style tags |

Implementations should fall back to `RENDERER_PLAIN` for any unknown renderer byte rather than rejecting the message.

#### 5.9.5 Propagation-node metadata keys

Distinct from the top-level `fields` dict, these `PN_META_*` keys are used inside the `fields[0x02]` element of a propagation-node announce (§5.8.5 element [2]) or in `/get`-flow metadata responses. Upstream marked these unstable until the LXMF 1.0.0 release; as of LXMF 1.1.1 the allocations below are confirmed unchanged (verified by `tools/verify_lxmf_fields.py`), but the upstream **value types** remain a soft contract — code defensively.

| Byte | Constant | Purpose |
|---|---|---|
| `0x00` | `PN_META_VERSION` | Propagation protocol version |
| `0x01` | `PN_META_NAME` | Operator-supplied node name |
| `0x02` | `PN_META_SYNC_STRATUM` | Sync tier in the propagation mesh |
| `0x03` | `PN_META_SYNC_THROTTLE` | Operator-imposed sync throttle |
| `0x04` | `PN_META_AUTH_BAND` | Auth requirement (open / restricted / private) |
| `0x05` | `PN_META_UTIL_PRESSURE` | Utilization back-pressure hint |
| `0xFF` | `PN_META_CUSTOM` | Operator-defined extensions |

> ⚠️ **UNVERIFIED:** the value type for each `PN_META_*` key is not yet pinned by this spec — upstream still treats them as a soft contract. Implementations should preserve unknown keys round-trip rather than dropping them.

#### 5.9.6 Functionality signalling keys

For announce-level capability negotiation:

| Byte | Constant | Meaning |
|---|---|---|
| `0x00` | `SF_COMPRESSION` | Sender supports compressed message bodies (see §10.12) |

#### 5.9.7 `FIELD_FILE_ATTACHMENTS` (`0x05`) value shape

```
fields[0x05] = [ [filename(str-or-bytes), file_bytes(bytes)], ... ]
```

A list of attachments — one LXMF message may carry more than one
file. Each attachment is itself a 2-element list: element `[0]` is the
file name, element `[1]` is the raw file content. As with `FIELD_IMAGE`
(§5.9.2) the file name may arrive as msgpack `str` or `bin` depending
on the encoder — receivers must tolerate both (see §9.3).

The file name is **sender-controlled and untrusted**. Upstream Sideband
strips `../` from it on receive (`sbapp/ui/messages.py`:
`filename = str(attachment[0]).replace("../", "")`); receivers MUST
sanitise it — reject or strip path separators, `..` segments and
control characters — before display or save, and never let it
influence a write path. The extension is likewise untrusted: do not
auto-open or auto-execute an attachment based on its claimed type.

Files larger than a single Reticulum DATA packet are delivered as a
Resource over a Link, identically to large `FIELD_IMAGE` payloads
(§10).

Source: `markqvist/Sideband` `sbapp/sideband/core.py`
(`fields[LXMF.FIELD_FILE_ATTACHMENTS] = [attachment]`, where each
`attachment = [filename, filedata]`) and `sbapp/ui/messages.py`
(receive side indexes `attachment[0]` filename / `attachment[1]`
bytes). Confirmed from upstream source 2026-05-18; a captured wire
test vector would further pin the msgpack `str`-vs-`bin` choice.

#### 5.9.8 `FIELD_REACTION` (`0x40`): tap-back reactions

Official as of LXMF 1.0.0 (2026-05-28): `FIELD_REACTION = 0x40` (`LXMF/LXMF.py:25`). A reaction is a standalone LXMF message whose `fields[0x40]` is a msgpack dict keyed by 1-byte integers (`LXMF/LXMF.py:109-110`):

```
fields[0x40] = {
  0x00: <raw 32-byte target LXMF message_id>,   # REACTION_TO
  0x01: <reaction content, UTF-8 bytes>,         # REACTION_CONTENT (typically one emoji)
}
```

- `REACTION_TO` (`0x00`) is the canonical LXMF `message_id` (= `message_hash` of §5.5; the same value used as the workblock input for stamps in §5.7) — the **raw 32 bytes** per the §5.5 normative rule, NOT hex-encoded. A decode-re-encode diverges for any non-trivial `fields` map (including reply-carrying messages, §5.9.9) and the reaction misses the relay rewrite-cache for that target.
- `REACTION_CONTENT` (`0x01`) is the reaction content as UTF-8 bytes — typically a single emoji, but not constrained to one; upstream leaves sanitization to the client.
- The reaction carries **no explicit reactor identity** — attribution is the carrying LXMF's own source identity (its `source_hash` / signing identity), not a field inside the dict.
- The carrying LXMF has empty `content` and empty `title`; `fields[0x40]` IS the entire payload.
- Receivers MUST aggregate by (reactor-identity, `REACTION_CONTENT`) with dedup and SHOULD NOT render the reaction-carrying LXMF as a separate bubble.
- **Bytes/str tolerance.** msgpack values may arrive as `str` or `bin` depending on encoder. Receivers MUST accept both — same precedent as §5.6 for the LXMF signature.
- **Inner-map decode tolerance.** The `fields[0x40]` value is a msgpack map. Strongly-typed decoders may surface it as an integer-keyed or `Any`-keyed map (`Map<Long, Any>` / `Map<Any?, Any?>`, `map[any]any`, etc.), depending on the runtime msgpack library and the key types seen on the wire. Receivers MUST tolerate this via a runtime cast that does not depend on the outer map's static key type. A silent type-assertion failure produces a no-log no-error drop indistinguishable on the receive side from "the message never arrived."
- **Relay routing.** If the target message arrived over a Link whose validated §6.7.6 LINKIDENTIFY peer differs from the LXMF body's `source_hash`, the reaction-carrying LXMF MUST egress to the link peer's destination hash, not `source_hash`; otherwise the reaction bypasses the relay's fanout and is delivered direct to the original sender instead of the relay group.

#### 5.9.9 `FIELD_REPLY_TO` (`0x30`) + optional `FIELD_REPLY_QUOTE` (`0x31`): reply-to threading

> ✅ **Official as of LXMF 1.0.0** (2026-05-28): `FIELD_REPLY_TO = 0x30` (`LXMF/LXMF.py:23`) and `FIELD_REPLY_QUOTE = 0x31` (`:24`).

```
fields[0x30] = <raw 32-byte LXMF message_id (NOT hex-encoded)>
fields[0x31] = <UTF-8 quoted content>     # optional
```

- `fields[0x30]` IS the canonical LXMF `message_id` from §5.7 — the raw 32 bytes on the wire, not a hex-encoded string. The `message_id` MUST be computed over raw wire payload bytes per §5.5; a decode-re-encode diverges for reply messages (their `fields` map is non-trivial) and breaks any relay rewrite-cache keyed on the value.
- `fields[0x31]` (optional) carries the quoted text for offline-receiver fallback so the recipient can render a quote preview even when the original message hasn't arrived locally. Useful on intermittent links; SHOULD be omitted when the sender doesn't want to pay the airtime.
- The raw-bytes branches (`fields[0x30]`, `fields[0x31]`) are not maps, but receivers MUST still tolerate both `bytes` and `str` carriers per §5.6 in case an encoder ships the hash hex-encoded by mistake.
- **Relay routing.** Same as §5.9.8 — if the target message arrived over a Link whose §6.7.6 LINKIDENTIFY peer differs from `source_hash`, the reply-carrying LXMF MUST egress to the link peer's destination hash.

#### 5.9.10 `FIELD_COMMENT` (`0x41`): message-as-comment

Official as of LXMF 1.0.0 (`FIELD_COMMENT = 0x41`, `LXMF/LXMF.py:26`). Marks the carrying message as a comment on another message. The comment text itself is carried as the normal LXM `content`, so a client that doesn't support comments simply renders it as an ordinary message (upstream rationale, `LXMF/LXMF.py:111-117`).

```
fields[0x41] = {
  0x00: <raw 32-byte target LXMF message_id>,   # COMMENT_FOR
}
```

- `COMMENT_FOR` (`0x00`, `LXMF/LXMF.py:118`) is the canonical LXMF `message_id` of the commented-on message — raw 32 bytes per §5.5, NOT hex-encoded.
- The same inner-map decode tolerance and `bytes`/`str` carrier tolerance described in §5.9.8 apply.

#### 5.9.11 `FIELD_CONTINUATION` (`0x42`): message-as-continuation

Official as of LXMF 1.0.0 (`FIELD_CONTINUATION = 0x42`, `LXMF/LXMF.py:27`). Marks the carrying message as a continuation of an earlier message. As with comments, the continuation text is carried as the normal LXM `content`, so unsupporting clients render it as an ordinary message (upstream rationale, `LXMF/LXMF.py:120-125`).

```
fields[0x42] = {
  0x00: <raw 32-byte target LXMF message_id>,   # CONTINUATION_OF
}
```

- `CONTINUATION_OF` (`0x00`, `LXMF/LXMF.py:126`) is the canonical LXMF `message_id` of the continued message — raw 32 bytes per §5.5, NOT hex-encoded.
- The same inner-map decode tolerance and `bytes`/`str` carrier tolerance described in §5.9.8 apply.

### 5.10 Source

`LXMF/LXMessage.py` for pack/unpack; `LXMF/LXMF.py` for the app_data extraction helpers and the field/audio/renderer constants enumerated in §5.9; `LXMF/LXStamper.py` for stamps; `LXMF/LXMRouter.py` for receive-side stamp/ticket dispatch and propagation handlers; `LXMF/LXMPeer.py` for the propagation peer-to-peer state machine.

---

## 6. Reticulum Link protocol

A Link is an ephemeral encrypted channel between two destinations, established via a 2-packet handshake (LINKREQUEST → LRPROOF) and used afterward for full-duplex DATA.

### 6.1 LINKREQUEST (initiator → responder)

A regular packet with `packet_type = LINKREQUEST (2)`, `dest_type = SINGLE`, addressed to the responder's destination hash. Body:

```
initiator_X25519_pub(32) || initiator_Ed25519_pub(32) || [signalling(3)]
```

Both initiator-side keys are **fresh ephemeral keys** (not the initiator's long-term identity). The optional 3-byte signalling field encodes a packed 21-bit MTU and 3-bit link mode — see §6.6 for the bit layout and the negotiation rules. Receivers detect its presence by body length: `len(data) == 64` means no signalling, `len(data) == 67` means signalling present.

### 6.2 LRPROOF (responder → initiator)

A `packet_type = PROOF (3)` with `context = 0xff`, addressed to the link itself — i.e. `dest_hash` in the packet header is the 16-byte `link_id` (`RNS/Packet.py:182-184`: when context is `LRPROOF`, `header += destination.link_id` and the body is appended unencrypted).

Body (`proof_data` at `RNS/Link.py:371`):

```
signature(64) || responder_X25519_pub(32) || [signalling(3)]
```

Only the responder's X25519 is fresh-ephemeral; the responder signs with its **long-term** Ed25519 private key (asymmetric with the initiator). The responder's long-term Ed25519 public key is **not** sent on the wire — both sides already know it from the responder's prior announce, and it is included implicitly in the signature input. Signature input (`RNS/Link.py:368-369` for the signer, `:412` for the validator):

```
signed_data = link_id || responder_X25519_pub || responder_long_term_Ed25519_pub || [signalling]
```

The full wire packet is therefore: `flags(1) || hops(1) || link_id(16) || context=0xff(1) || signature(64) || responder_X25519_pub(32) || [signalling(3)]`.

The signalling slot, when present, carries the responder's `confirmed_mtu` and the link mode in a 24-bit packed integer — see §6.6. Receivers detect its presence by length: body 96 vs 99 bytes. **Critical for interop:** the signalling bytes (when present) MUST be included in `signed_data` exactly where shown above; an implementation that signs without them on a peer that emits them — or vice versa — fails signature validation and the link never establishes. This is the most common cause of link-handshake failures with mixed-version peers.

### 6.3 link_id derivation

```
link_id = SHA256(hashable_part_of_LINKREQUEST_packet)[:16]
```

`hashable_part` is built by `Packet.get_hashable_part` (`RNS/Packet.py:354-361`):

```
hashable_part = byte(flags & 0x0F) || raw[N:]
   where N = 2  for HEADER_1   (strip flags + hops)
         N = 18 for HEADER_2   (strip flags + hops + transport_id)
```

The "hashable part" deliberately strips `header_type`, `context_flag`, `transport_type` (top 4 bits of flags — modifiable by transit relays), the `hops` byte (modified by every relay), and (for HEADER_2) the `transport_id` (added by the originator and re-written by each relay). What remains in both cases is the low nibble of flags + dest_hash + context + body, so the resulting `link_id` is the same whether the LINKREQUEST is hashed at the initiator (HEADER_1) or at the responder after one or more transport relays (HEADER_2). Both sides agree on the 16-byte ID.

For LINKREQUEST packets specifically, the trailing signalling bytes (if present, indicated by `len(packet.data) > Link.ECPUBSIZE` in `link_id_from_lr_packet` at `RNS/Link.py:336-342`) are stripped from the END of `hashable_part` before hashing, so the link_id is invariant under MTU-discovery signalling.

### 6.4 Session keys and link activation

After the LINKREQUEST/LRPROOF exchange completes, both peers must (a) derive matching link session keys, (b) drive the link state machine to `ACTIVE`, and (c) settle on the wire conventions for all subsequent traffic on the link. The three subsections below cover each step. Skipping any of them silently breaks interop in distinct ways: §6.4.1 wrong → no peer can decrypt anything; §6.4.2 omitted → the responder never reaches `ACTIVE` and silently drops all link DATA; §6.4.3 wrong on multi-hop → packets are dropped at the destination's transport filter.

#### 6.4.1 Session key derivation

Both sides compute:

```
shared       = X25519(my_ephemeral_priv, peer_ephemeral_pub)
session_key  = HKDF(shared, salt = link_id, info = "", L = 64)
signing_key  = session_key[0..32]
encrypt_key  = session_key[32..64]
```

Subsequent DATA packets on the link use the Link-derived-key Token format (section 3.1, no ephemeral_pub prefix).

#### 6.4.2 LRRTT — initiator's link-activation packet

After validating the responder's LRPROOF and deriving session keys, the initiator MUST send a Link Round-Trip Time packet to the responder before transmitting any application DATA. The wire form is:

| Field | Value |
|---|---|
| `header_type` | `HEADER_1` |
| `packet_type` | `DATA (0x00)` |
| `destination_type` | `LINK (0x03)` |
| `dest_hash` | `link_id` |
| `context` | `LRRTT (0xFE)` |
| body (plaintext) | `umsgpack.packb(rtt_seconds)` — a single msgpack float64 (9 bytes) carrying the initiator's measured RTT in seconds (LRREQ-send to LRPROOF-receive) |
| body (wire) | the plaintext above, encrypted with the link's session keys per §3.1 (link form Token, no `eph_pub` prefix) |

Source: `RNS/Link.py:435-437` constructs and sends the packet immediately after LRPROOF validation:

```python
rtt_data   = umsgpack.packb(self.rtt)
rtt_packet = RNS.Packet(self, rtt_data, context=RNS.Packet.LRRTT)
rtt_packet.send()
```

The responder uses receipt of LRRTT as the trigger to transition its link state from `HANDSHAKE` to `ACTIVE` (`RNS/Link.py:516-538`). The initiator transitions independently upon LRPROOF validation (`Link.py:424-426`); the responder MUST NOT transition before LRRTT arrives. The responder routes context `LRRTT` to `Link.rtt_packet()` from its main `receive()` dispatch at `RNS/Link.py:1015-1018`.

`Link.rtt_packet()` is also the only path on the responder side that fires the `link_established` callback (`Link.py:532-533`). Without that callback, application layers cannot install link-state policies that depend on `ACTIVE` — most importantly, LXMF's `LXMRouter.delivery_link_established` (`LXMF/LXMRouter.py:1956-1962`) only calls `link.set_resource_strategy(ACCEPT_APP)` from this callback. Until that strategy is installed, the responder's `Link.receive()` hits the silent-drop branch `elif self.resource_strategy == Link.ACCEPT_NONE: pass` (`RNS/Link.py:1087`) on every inbound `RESOURCE_ADV`, and any oversize LXMF delivered as a Resource is discarded with no log line at default levels. This is silent, end-to-end, default-config message loss for an initiator that completes LRPROOF and immediately sends RESOURCE_ADV without first sending LRRTT.

The exact RTT value reported is non-load-bearing: the responder takes `max(its_own_measurement, initiator_reported)` (`Link.py:522`). Implementations that don't have an accurate RTT measurement at this point may report a coarse estimate or zero — the responder's measurement carries forward when the initiator reports a smaller value. The value is, however, included in the encrypted body and so is integrity-bound to the link session keys; a peer that fails to encrypt this body with the correct link keys will fail decrypt and `rtt_packet` returns without transitioning to `ACTIVE`.

#### 6.4.3 Header type for post-handshake DATA and Resource

All packets sent on an active Link — link DATA (`packet_type=DATA`, `context=NONE`), Resource control packets (`context` ∈ {`RESOURCE_ADV (0x02)`, `RESOURCE_REQ (0x03)`, `RESOURCE_HMU (0x04)`, `RESOURCE_ICL (0x06)`, `RESOURCE_RCL (0x07)`}), Resource part packets (`context=RESOURCE (0x01)`), and link control packets (`KEEPALIVE`, `LRRTT`, `LINKCLOSE`, `LINKIDENTIFY`, `REQUEST`, `RESPONSE`, `CHANNEL`) — MUST be emitted with `header_type=HEADER_1` and no `transport_id`, regardless of whether the responder is reachable directly or through one or more transit relays.

This is asymmetric to the LINKREQUEST that established the link. LINKREQUEST is destination-hash-routed via `path_table` and therefore eligible for `HEADER_2` with `transport_id` set to the next-hop relay; the relay's path_table-forwarding branch strips `transport_id` (HEADER_2 → HEADER_1) at the last hop (`RNS/Transport.py:1602-1619`):

```python
if remaining_hops > 1:
    # Just increase hop count and transmit (HEADER_2 preserved)
elif remaining_hops == 1:
    # Strip transport headers and transmit
    new_flags = (RNS.Packet.HEADER_1) << 6 | (Transport.BROADCAST) << 4 | (packet.flags & 0b00001111)
    new_raw  = struct.pack("!B", new_flags)
    new_raw += struct.pack("!B", packet.hops)
    new_raw += packet.raw[(RNS.Identity.TRUNCATED_HASHLENGTH//8)+2:]
```

Once the link exists, post-handshake traffic addressed to `link_id` is routed via `link_table`, not `path_table`. The link_table forwarding branch (`RNS/Transport.py:1704-1739`) does NOT touch the header — it bumps `hops` and forwards the bytes verbatim:

```python
new_raw = packet.raw[0:1]
new_raw += struct.pack("!B", packet.hops)
new_raw += packet.raw[2:]
Transport.transmit(outbound_interface, new_raw)
```

A HEADER_2 link DATA packet would therefore arrive at the destination with `transport_id` intact, where the receiver's `Transport.packet_filter` (`RNS/Transport.py:1383-1385`) drops it as "for another transport instance" because the embedded `transport_id` is the relay's identity, not the receiver's:

```python
if packet.transport_id != None and packet.packet_type != RNS.Packet.ANNOUNCE:
    if packet.transport_id != Transport.identity.hash:
        RNS.log("Ignored packet ... in transport for other transport instance", RNS.LOG_EXTREME)
        return False
```

The drop fires only at `LOG_EXTREME` (level 7) and is invisible at the default `LOG_NOTICE` (level 3); see §9.9.

Upstream RNS does not trip this in practice because its own constructors use `Packet`'s defaults (`HEADER_1`, `transport_id=None`) regardless of multi-hop. The relevant ones, all in `RNS/Resource.py` and `RNS/Link.py`, take the form `RNS.Packet(self.link, body, context=...)` (e.g. `Resource.py:521` for `RESOURCE_ADV`); see `Packet.__init__` at `RNS/Packet.py:122-123` for the default values. Upstream-to-upstream interop therefore never exercises this path. A clean-room implementation that copies the LINKREQUEST multi-hop pattern verbatim — setting `transport_id` on every link-bound packet — silently fails on any link with one or more transit relays in the path. The unit tests for that implementation pass (both sides agree on the same wire mistake) but localhost-rnsd interop with a real upstream destination drops every Resource part.

The asymmetry summarized: the same Link is set up via a `HEADER_2`-eligible LINKREQUEST, but uses `HEADER_1` for everything else once established.

### 6.5 Packet receipts (regular `PROOF` packets)

A `PROOF`-type packet (`packet_type = 3`, `context = NONE (0x00)`) is the receipt that closes the loop on every CTX_NONE DATA packet — both opportunistic DATA addressed to a SINGLE destination and DATA flowing on an active Link. Without it, the sender's `PacketReceipt` never resolves, its retransmit queue fires repeatedly, and on a Link the KEEPALIVE budget is exhausted and the link torn down.

This section specifies the regular PROOF body. Two related proof formats are documented elsewhere and are NOT compatible with this format:

- **`LRPROOF (context = 0xFF)`** is the link-establishment proof (§6.2). Different body, different signature input.
- **`RESOURCE_PRF (context = 0x05)`** is the proof for a completed Resource transfer (§10.8). Different body (`resource_hash || full_proof`), no signature.

#### 6.5.1 Two body formats: explicit vs implicit

Regular PROOFs come in two wire forms (`RNS/Packet.py:398-399`):

```
EXPL_LENGTH = HASHLENGTH//8 + SIGLENGTH//8 = 32 + 64 = 96 bytes
IMPL_LENGTH = SIGLENGTH//8                 =      64 = 64 bytes

explicit body  =  packet_hash(32) || signature(64)
implicit body  =                     signature(64)
```

Where:

- `packet_hash = Identity.full_hash(original_packet.get_hashable_part())` — the full SHA-256 (32 bytes, **not** truncated to 16) of the prove-target packet's hashable part. `get_hashable_part` is the same recipe used for `link_id` derivation in §6.3, so the proof binds to the version of the packet that survived any HEADER_1↔HEADER_2 conversion in transit (the high nibble of flags, hops byte, and any HEADER_2 transport_id are stripped before hashing).
- `signature` is the destination's (or link's) Ed25519 signature **over `packet_hash`**, NOT over the proof body itself. The signing key is the destination's long-term Ed25519 private key for an opportunistic DATA proof, or **the link's Ed25519 signing key** (`Link.sig_prv`, `RNS/Link.py:277` / `:285` in RNS 1.4.2) for a Link DATA proof — the owner identity's long-term key on the responder side, the link's ephemeral Ed25519 keypair on the initiator side. (The HKDF-derived `signing_key` from §6.4.1 is a separate **symmetric HMAC key** for the link Token form §3.1 — it cannot produce an Ed25519 signature and is not used here.)

The two forms are distinguished **purely by length** at the receiver. `PacketReceipt.validate_proof` (`RNS/Packet.py:480-524`) dispatches on `len(proof) == 96` (explicit) vs `len(proof) == 64` (implicit); lengths matching neither are rejected outright. There is no flag bit or context byte that signals which form is being used — wire length is the only signal.

#### 6.5.2 Choosing which form to emit

Sender side, two distinct policies:

**Opportunistic DATA addressed to a SINGLE destination** — `RNS.Identity.prove(packet, destination)` at `RNS/Identity.py:942-953`:

```python
def prove(self, packet, destination=None):
    signature = self.sign(packet.packet_hash)
    if RNS.Reticulum.should_use_implicit_proof():
        proof_data = signature                                  # 64 bytes
    else:
        proof_data = packet.packet_hash + signature             # 96 bytes
    proof = RNS.Packet(destination_or_proof_dest, proof_data,
                       RNS.Packet.PROOF, attached_interface=...)
    proof.send()
```

The default upstream value is `Reticulum.__use_implicit_proof = True` (`RNS/Reticulum.py:256`), so **upstream emits the 64-byte implicit form by default**. The 96-byte explicit form is only emitted when the operator's `[reticulum]` config sets `use_implicit_proof = No`. A clean-room implementation that hardcodes either single form will fail to interop with peers running the other one — receiver-side validators handle both, but a hardcoded sender writing the wrong length to the wire is not negotiable.

**DATA on an active Link** — `RNS.Link.prove_packet(packet)` at `RNS/Link.py:378-389`:

```python
def prove_packet(self, packet):
    signature = self.sign(packet.packet_hash)
    proof_data = packet.packet_hash + signature                 # 96 bytes — always
    proof = RNS.Packet(self, proof_data, RNS.Packet.PROOF)
    proof.send()
```

with the upstream comment `# TODO: Hardcoded as explicit proof for now`. Link DATA proofs are **always** the 96-byte explicit form in RNS 1.4.2 regardless of the `use_implicit_proof` setting, and the matching `validate_link_proof` at `RNS/Packet.py:434-478` has the implicit-form branch commented out with the same note. Today, Link DATA proofs are explicit-only on both ends; an implementation may match this behavior with a single hardcoded length on the link path, but should be ready to revisit if upstream re-enables the implicit branch (no fixed timeline).

#### 6.5.3 Where the proof packet is addressed

The dest_hash position in the proof packet's outer header depends on which side of which transport the proven packet was on:

- **Opportunistic DATA proof:** `dest_hash = packet_hash[:16]` (the 16-byte truncation of the full SHA-256 of the proved packet's hashable part, used as a synthetic `ProofDestination` — `RNS/Packet.py:376-390`). The proof rides through `Transport.outbound` and follows the reverse path home via the receiver's `reverse_table`.
- **Link DATA proof:** `dest_hash = link.link_id` (the 16-byte link id, just like all other Link traffic; `RNS/Packet.py:182-184` notes this position is filled by `destination.link_id` whenever the destination object is a Link). The proof rides on the link itself.

#### 6.5.4 Wire summary

```
explicit form (96 bytes total body):
[ 1B flags ][ 1B hops ][ 16B dest_hash || link_id ][ 1B context=0x00 ]
[ 32B SHA256(get_hashable_part(original_packet)) ]
[ 64B Ed25519_signature(SHA256(get_hashable_part(original_packet))) ]

implicit form (64 bytes total body):
[ 1B flags ][ 1B hops ][ 16B dest_hash || link_id ][ 1B context=0x00 ]
[ 64B Ed25519_signature(SHA256(get_hashable_part(original_packet))) ]
```

Note `context = 0x00 (NONE)` in both cases — the proof-ness is conveyed by `packet_type = PROOF (3)` in the flag byte, not by a context. This is in contrast to LRPROOF (which uses `context = 0xFF`) and RESOURCE_PRF (which uses `context = 0x05`). The `LINKPROOF (0xFD)` context constant defined at `RNS/Packet.py:90` is reserved but not actually used by either prove path in RNS 1.4.2.

#### 6.5.5 Receiver tolerance

A new implementation's PROOF validator MUST accept both 64- and 96-byte bodies for opportunistic DATA proofs (per `validate_proof`'s length-dispatch above) so it interops with peers running either policy. Hardcoding only one form at the validator silently fails on traffic from a peer with the opposite setting. Length-dispatch is also the only place the validator ever distinguishes the two — there is no "I want explicit" hint a sender can express.

A receiver that gets a PROOF whose length matches neither form treats it as malformed and returns `False` from `validate_proof`; no NACK is sent to the originator.

#### 6.5.6 Why this matters for Link interop

After processing each `NONE` DATA packet on an active link, the receiver MUST emit the explicit-form PROOF described above. Without it, the sender's retransmit queue fires and the same packet arrives repeatedly, eventually exceeding the link's KEEPALIVE budget and tearing down the link. This is `Packet.prove_packet` upstream — non-optional for any client that wants to receive content over a Link without spamming the sender.

### 6.6 MTU and mode signalling (3-byte trailer on LINKREQUEST and LRPROOF)

The optional 3-byte `signalling` slot referenced in §6.1 and §6.2 carries two negotiated parameters in a single 24-bit big-endian packed integer: the link MTU (21 bits) and the link mode (3 bits, top of the high byte). When present, the signalling bytes are also included in the LRPROOF's signed_data, so the responder's signature commits to the negotiated values and a peer flipping a bit in transit invalidates the proof.

#### 6.6.1 Wire layout

3 bytes total, big-endian. Byte 0 is split: top 3 bits are `mode`, low 5 bits are the most-significant 5 bits of the 21-bit `mtu`. Bytes 1 and 2 are the remaining 16 bits of `mtu`:

```
byte 0 :  M M M m m m m m       — top 3 bits = mode (0..7), low 5 bits = mtu[20..16]
byte 1 :  m m m m m m m m       — mtu[15..8]
byte 2 :  m m m m m m m m       — mtu[7..0]
```

Encoded by `RNS/Link.py:148-151`:

```python
@staticmethod
def signalling_bytes(mtu, mode):
    if not mode in Link.ENABLED_MODES:
        raise TypeError(f"Requested link mode {Link.MODE_DESCRIPTIONS[mode]} not enabled")
    signalling_value = (mtu & Link.MTU_BYTEMASK) + (((mode << 5) & Link.MODE_BYTEMASK) << 16)
    return struct.pack(">I", signalling_value)[1:]    # big-endian uint32, drop top byte
```

with `MTU_BYTEMASK = 0x1FFFFF` (21 bits) and `MODE_BYTEMASK = 0xE0` (top 3 bits of a byte).

Decoded mode and mtu (from `mode_from_lr_packet` line 171-176, `mtu_from_lr_packet` line 153-157):

```python
mode = (signalling[0] & 0xE0) >> 5
mtu  = ((signalling[0] << 16) + (signalling[1] << 8) + signalling[2]) & 0x1FFFFF
```

The mtu decode trick: the full 24-bit value of all three bytes is masked with the 21-bit `MTU_BYTEMASK`, which strips the top 3 bits (i.e. the mode bits) without any explicit byte 0 masking step. Implementations that use `(signalling[0] & 0x1F) << 16 | …` instead get the same answer.

#### 6.6.2 Mode field

3-bit value (0..7) at the top of byte 0. Defined values, with `RNS/Link.py:125-137`:

| Mode | Name | Status in RNS 1.4.2 | Derived key length |
|---|---|---|---|
| `0x00` | `MODE_AES128_CBC` | Defined, NOT enabled (sender-side will raise `TypeError`) | 32 bytes |
| `0x01` | `MODE_AES256_CBC` | Default; the only enabled mode (`ENABLED_MODES = [0x01]`) | 64 bytes |
| `0x02` | `MODE_AES256_GCM` | Reserved, not enabled | — |
| `0x03` | `MODE_OTP_RESERVED` | Reserved, not enabled | — |
| `0x04`–`0x07` | `MODE_PQ_RESERVED_*` | Reserved for the post-quantum migration; not enabled | — |

The `derived_key_length` at `RNS/Link.py:352-354` is what the HKDF in §6.4 produces, split as `signing_key(32) || encrypt_key(32)` for the AES-256 path or `signing_key(16) || encrypt_key(16)` for the AES-128 path.

A receiver MUST tolerate seeing any 3-bit value in the mode field on inbound traffic — `mode_from_lr_packet` returns the raw integer without validating it against `ENABLED_MODES`. The mode is enforced at handshake time (`Link.handshake` at line 353-368): unknown / disabled modes raise `TypeError` and the link transitions to `CLOSED` rather than `ACTIVE`. Senders MUST NOT emit any mode value not in `ENABLED_MODES` — `signalling_bytes()` raises if you try.

A clean-room implementation today can safely hardcode mode = `0x01` on emit. On receive, it should accept `0x01` and reject the rest as "mode not supported by this implementation" rather than silently treating them as the default — a future RNS version that flips the default to `0x04` (one of the PQ slots) would render a hardcoded-default decoder ambiguous about whether the wire bytes mean "AES_256_CBC" or "the new default".

#### 6.6.3 MTU field

21-bit unsigned integer in the low 21 bits of the 24-bit signalling value. Max representable: `0x1FFFFF = 2,097,151` bytes. Real Reticulum `HW_MTU` values are radically smaller (LoRa: 508; TCP: typical HW MTU ~64 KiB; AutoInterface: matches its bearer). The 21-bit width is forward-looking: it leaves room for future high-bandwidth interfaces without a wire-format change.

When the initiator emits a LINKREQUEST with signalling, the encoded `mtu` is the next-hop interface's `HW_MTU` (`RNS/Link.py:309-314`):

```python
nh_hw_mtu = RNS.Transport.next_hop_interface_hw_mtu(destination.hash)
if RNS.Reticulum.link_mtu_discovery() and nh_hw_mtu:
    signalling_bytes = Link.signalling_bytes(nh_hw_mtu, self.mode)
else:
    signalling_bytes = Link.signalling_bytes(RNS.Reticulum.MTU, self.mode)
```

When the responder emits an LRPROOF with signalling, the encoded `mtu` is the **min** of its own next-hop view and what arrived in the LINKREQUEST. In RNS 1.4.2 the clamp is performed by transit relays in the DATA forwarding path (`RNS/Transport.py:1641-1668`), which rewrite the LINKREQUEST's signalling bytes in place before forwarding so the responder's `Link.validate_request` (`RNS/Link.py:186-200`) sees the already-clamped value:

```python
path_mtu = Link.mtu_from_lr_packet(packet) or Reticulum.MTU
nh_mtu   = receiving_interface.HW_MTU if AUTOCONFIGURE_MTU/FIXED_MTU else Reticulum.MTU
if nh_mtu < path_mtu:
    path_mtu = nh_mtu
    clamped_signalling = Link.signalling_bytes(path_mtu, mode)
    packet.data = packet.data[:-LINK_MTU_SIZE] + clamped_signalling
```

The clamp is rewritten **into the LINKREQUEST packet's data buffer in place** before that packet enters the responder's `Destination.receive` path, so the responder's eventual LRPROOF carries the clamped value, not the originally-requested one. The clamp also affects link_id derivation: `link_id_from_lr_packet` strips trailing signalling bytes before hashing (per §6.3), so this in-place rewrite doesn't change the link_id even though it does change the wire bytes.

The initiator reads `confirmed_mtu` back via `mtu_from_lp_packet` during LRPROOF validation (`RNS/Link.py:404-408`), accepts it as `link.mtu`, and the link's `mdu` (max data unit per packet for §3.1 link-derived Token traffic) is recomputed via `update_mdu()`.

#### 6.6.4 Presence detection — length only

Both directions detect the optional signalling slot **purely by packet body length**:

| Packet | Body length without signalling | Body length with signalling |
|---|---|---|
| LINKREQUEST | `ECPUBSIZE = 64` | `ECPUBSIZE + LINK_MTU_SIZE = 67` |
| LRPROOF     | `SIGLENGTH//8 + ECPUBSIZE//2 = 96` | `... + LINK_MTU_SIZE = 99` |

Where `ECPUBSIZE = 64` is the combined initiator ephemeral X25519 + Ed25519 public key (`Link.py:70`), and `SIGLENGTH//8 = 64` is the responder's Ed25519 signature.

Receivers MUST handle both forms. `validate_request` at `RNS/Link.py:186-190` checks `len(data) == ECPUBSIZE` OR `len(data) == ECPUBSIZE+LINK_MTU_SIZE` and rejects anything else. The same length-dispatch is in `validate_proof` for the LRPROOF side at `RNS/Link.py:404-410`. There is no flag bit signalling presence — wire length is the only signal.

#### 6.6.5 Inclusion in LRPROOF signed_data

Per §6.2, the LRPROOF's signed_data when signalling is present is:

```
signed_data = link_id || responder_X25519_pub || responder_long_term_Ed25519_pub || signalling
```

A clean-room implementation that omits the signalling bytes when present (or includes them when absent) computes a different signed_data than the responder did, fails signature validation, and the link never establishes. This is the most common interop break in this area; cross-check against `RNS/Link.py:368-369` (signer) and `:417` (validator).

#### 6.6.6 Disabling MTU discovery

The `[reticulum]` config option `link_mtu_discovery = No` makes `Reticulum.link_mtu_discovery()` return False, so the initiator skips signalling on outbound LINKREQUESTs (`RNS/Link.py:311-314`). In that case the link uses `Reticulum.MTU` (default 500 bytes) globally, no per-link MTU clamping happens, and all four lengths fall back to the no-signalling sizes in §6.6.4.

A receiver doesn't need its own copy of the disable switch — it just stops seeing trailing signalling bytes from peers that have it disabled. Its own MTU reporting on the LRPROOF return path runs unaffected for peers that send it.

### 6.7 KEEPALIVE and link teardown

A Link goes through five states (`RNS/Link.py:110-114`): `PENDING → HANDSHAKE → ACTIVE → STALE → CLOSED`. `KEEPALIVE` and `LINKCLOSE` are the two control-plane packet types that drive transitions out of `ACTIVE`.

#### 6.7.1 KEEPALIVE (`context = 0xFA`)

Cadence (`RNS/Link.py:795-797`):

```python
def __update_keepalive(self):
    self.keepalive = max(min(self.rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MAX), KEEPALIVE_MIN)
    self.stale_time = self.keepalive * STALE_FACTOR
```

with constants `KEEPALIVE_MAX = 360s`, `KEEPALIVE_MIN = 5s`, `KEEPALIVE_MAX_RTT = 1.75s`, `STALE_FACTOR = 2`. The interval is `RTT × 205.7` clamped to `[5, 360]` seconds. Before the first RTT is measured (set in `validate_proof`), the link uses `KEEPALIVE = KEEPALIVE_MAX = 360s`.

The watchdog (`Link.__watchdog_job`, line 751-821) fires on every active link. When `now >= last_inbound + keepalive` AND the local node is the **initiator**, it emits a KEEPALIVE:

```python
def send_keepalive(self):
    keepalive_packet = RNS.Packet(self, bytes([0xFF]), context=RNS.Packet.KEEPALIVE)
    keepalive_packet.send()
```

Body is a single byte `0xFF` — the "ping" sentinel. **KEEPALIVE is NOT Token-encrypted** — `RNS/Packet.py` `pack()` puts `KEEPALIVE` in its not-encrypted branch alongside `RESOURCE`, `RESOURCE_PRF`, link `PROOF`, and `CACHE_REQUEST` (`self.ciphertext = self.data`, `Packet.py:206-209` in RNS 1.4.2). The wire body is the single sentinel byte in the clear — no IV, no ciphertext expansion, no HMAC.

The **responder** receives this in `Link.receive` at `RNS/Link.py:1149-1153` and answers with the "pong" sentinel (in 1.2.4 the body is `bytes([0xFE])`):

```python
elif packet.context == RNS.Packet.KEEPALIVE:
    if not self.initiator and packet.data == bytes([0xFF]):
        keepalive_packet = RNS.Packet(self, bytes([0xFE]), context=RNS.Packet.KEEPALIVE)
        keepalive_packet.send()
```

So:
- **Ping** = initiator → responder, body `0xFF`.
- **Pong** = responder → initiator, body `0xFE`.
- Only the initiator originates KEEPALIVE traffic. The responder never spontaneously pings.

Both sentinel bytes are arbitrary; what actually matters for keep-alive purposes is that *any* inbound traffic on the link refreshes `last_inbound` (the watchdog's anchor for staleness decisions). KEEPALIVE packets do **not** generate a PROOF receipt — the link-DATA proof path in `RNS/Link.py` `receive()` is gated on `packet.context == RNS.Packet.NONE` (`Link.py:943` in RNS 1.4.2), and KEEPALIVE takes its own branch at line 1123-1127. So a successful ping/pong exchange resets the staleness clock on **both** sides via the two-packet exchange itself: ping → pong (no pong-proof).

A clean-room responder MUST emit the pong on inbound `0xFF`; without it the initiator's watchdog will declare the link stale on the next cycle.

#### 6.7.2 STALE → CLOSED transition

When `now >= last_inbound + stale_time` (= `2 × keepalive`), the watchdog moves the link from `ACTIVE` to `STALE` (line 753-755), then on its next pass emits a teardown packet and transitions to `CLOSED` (line 761-766):

```python
elif self.status == Link.STALE:
    sleep_time = 0.001
    self.__teardown_packet()                  # see §6.7.3
    self.status = Link.CLOSED
    self.teardown_reason = Link.TIMEOUT
    self.link_closed()
```

`teardown_reason` is set to `Link.TIMEOUT` (constant value `0x01`) so the application's `link_closed_callback` can distinguish "the peer went dark" from "the peer cleanly closed".

There is also an explicit-cleanup path: after a STALE-induced teardown the watchdog adds a final grace period of `RTT × KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE` (= `RTT × 4 + 5s`) at line 754 to allow a delayed reply to bring the link back into ACTIVE before final teardown — but in upstream RNS 1.2.4 the `STALE → CLOSED` transition runs immediately on the next watchdog pass without consulting that grace period. The grace constant lives in case a future revision restores the soft-stale window.

#### 6.7.3 LINKCLOSE (`context = 0xFC`)

Either side can cleanly tear down a link by calling `Link.teardown()` (line 662-672), which sends a single LINKCLOSE packet and transitions the local state to `CLOSED`:

```python
def __teardown_packet(self):
    teardown_packet = RNS.Packet(self, self.link_id, context=RNS.Packet.LINKCLOSE)
    teardown_packet.send()
```

Wire form:
- `packet_type = DATA (0)`, `context = 0xFC`, `dest_hash = link_id`.
- Body is the **16-byte link_id**, Token-encrypted by the link's session key.

The peer's receiver path at `RNS/Link.py:1020-1021` calls `teardown_packet(packet)` (line 674-683):

```python
def teardown_packet(self, packet):
    plaintext = self.decrypt(packet.data)
    if plaintext == self.link_id:                # auth check
        self.status = Link.CLOSED
        if self.initiator:
            self.teardown_reason = Link.DESTINATION_CLOSED
        else:
            self.teardown_reason = Link.INITIATOR_CLOSED
        self.link_closed()
```

The body's plaintext **MUST** equal `link_id` for the close to take effect — this is the on-link auth check. A peer that doesn't share the session key can't decrypt the body, and even if it could, the link_id check rejects bodies with arbitrary content. Combined with the Token HMAC, this gives both "encrypted" and "authenticated" guarantees on the teardown signal.

After `link_closed()` (line 685-710) runs:

- All `incoming_resources` and `outgoing_resources` are cancelled (cancels propagate into the §10 Resource state machine).
- The Link's session keys (`self.shared_key`, `self.derived_key`) are zeroed by reassignment to `None` — the upstream comment at line 700-702 notes this is the forward-secrecy property: "encryption keys are purged. New keys will be used if a new link to the same destination is established."
- The `link_closed_callback` registered via `set_link_closed_callback` fires.
- The Link is removed from its destination's `links` list (responders only — initiators don't have a destination-list entry).

#### 6.7.4 Teardown reason codes

`Link.teardown_reason` is set to one of (`RNS/Link.py:116-118`):

| Constant | Hex | Meaning |
|---|---|---|
| `TIMEOUT` | `0x01` | Watchdog STALE → CLOSED transition. No LINKCLOSE was received. |
| `INITIATOR_CLOSED` | `0x02` | This side is the responder; the initiator sent a LINKCLOSE. |
| `DESTINATION_CLOSED` | `0x03` | This side is the initiator; the responder sent a LINKCLOSE. |

These are local-state values, not on the wire — the LINKCLOSE packet itself doesn't carry a reason code. The recipient just infers whether the close came from the other side based on whether they're initiator or responder.

#### 6.7.5 Receiver responsibilities (minimum)

For a clean-room implementation that wants links to survive idle periods longer than a few seconds:

1. Keep a per-link `last_inbound` timestamp updated on every inbound packet on the link (DATA, PROOF, KEEPALIVE — anything).
2. On the **initiator** side, run a watchdog that emits a `0xFF` KEEPALIVE every `link.keepalive` seconds since `last_inbound`. Default `link.keepalive = 360s` is fine until you measure RTT.
3. On the **responder** side, reply to every `0xFF` KEEPALIVE with a `0xFE` KEEPALIVE. Don't originate.
4. On both sides, transition to `CLOSED` if `last_inbound + 2*keepalive` elapses with no traffic, AND emit a `LINKCLOSE` packet so the peer doesn't have to wait for its own watchdog to time out.
5. On every inbound `LINKCLOSE`, decrypt, verify body equals `link_id`, transition to `CLOSED`.
6. On `CLOSED`, zero the session keys and cancel any in-progress Resources.

#### 6.7.6 LINKIDENTIFY (`context = 0xFB`)

A separate Link control DATA packet — not part of the keepalive /
teardown cycle, but documented here alongside the other context-dispatched
Link control packets. Used by the initiator to prove which long-term
identity is making the request without re-running the Link handshake;
§11.6 covers the calling context on the NomadNet REQUEST path.

`Link.identify(identity)` (`RNS/Link.py:454-470` in RNS 1.4.2):

```python
def identify(self, identity):
    if self.initiator and self.status == Link.ACTIVE:
        signed_data = self.link_id + identity.get_public_key()
        signature  = identity.sign(signed_data)
        proof_data = identity.get_public_key() + signature
        proof      = RNS.Packet(self, proof_data, RNS.Packet.DATA,
                                context = RNS.Packet.LINKIDENTIFY)
        proof.send()
```

Wire body (128 bytes):

```
public_key(64) || signature(64)
```

- `public_key` is the initiator's **full 64-byte Identity public key**
  — the same `get_public_key()` that LINKREQUEST and announces use,
  the concatenation of the Ed25519 verification key and the X25519
  encryption key per §3.
- `signature` is `identity.sign(link_id(16) || public_key(64))` — the
  signature is over the link_id concatenated with the public_key,
  NOT over `link_id` alone. The responder verifies with `public_key`
  over that same concatenation.

The packet is a `DATA` packet on the active Link, so it IS
link-encrypted per §3.1 link-derived form like ordinary link DATA —
`context = 0xFB` is NOT in `RNS/Packet.py` `pack()`'s not-encrypted
set, unlike KEEPALIVE (§6.7.1) or link `PROOF` (§6.5).

The responder's `receive()` (`RNS/Link.py:963-982`) decrypts the
body, splits off the 64-byte public_key prefix, reconstructs
`signed_data = link_id || public_key`, verifies the signature, and on
success sets `self.remote_identity` so subsequent REQUEST handlers can
check the caller against per-page allowlists (§11.6).

A clean-room implementation MUST build the payload as
`public_key || signature` (NOT just the signature) and sign the
concatenation `link_id || public_key` (NOT `link_id` alone). Either
mistake makes every `ALLOW_LIST`-protected page return
`DEFAULT_NOTALLOWED`.

### 6.8 Channel mode (`CHANNEL = 0x0E`)

A Channel is a **continuous, bi-directional, message-typed stream** on top of an established Link. Distinct from §11 REQUEST/RESPONSE (single-shot, client-server) and §10 Resources (large unidirectional transfers): Channel messages are short, can flow in either direction at any time, and carry an application-defined type byte the receiver dispatches on. NomadNet uses it for its "channel" API (live chat over a Link), and any application can register custom message types via `RNS.Channel.Channel.register_message_type`.

#### 6.8.1 Wire form

A Channel message rides as a single Link DATA packet with `context = CHANNEL (0x0E)`. The body is **6-byte fixed-prefix header + variable-length payload** (`RNS/Channel.py:130-133`):

```
msgtype(2)  ||  sequence(2)  ||  length(2)  ||  data(length bytes)
```

All three header fields are **big-endian unsigned 16-bit integers** (Python `struct.pack(">HHH", msgtype, sequence, length)`):

| Field | Width | Meaning |
|---|---|---|
| `msgtype` | uint16 BE | Application-defined message type. Distinguishes the payload schema. |
| `sequence` | uint16 BE | Per-direction sequence number, starting at 0 and incrementing each emission. Wraps at 65536. |
| `length` | uint16 BE | Length in bytes of the payload that follows. |

The whole 6-byte header + payload is the Link DATA packet's **plaintext**, which is then Token-encrypted by the link's session key (§3.1 link-derived form, no eph_pub prefix) before transmission.

#### 6.8.2 Reserved system message types

`RNS/Channel.py:45-46`:

```python
class SystemMessageTypes(enum.IntEnum):
    SMT_STREAM_DATA = 0xff00
```

`0xff00` is reserved for upstream's stream-over-channel implementation. Application-defined message types should stay in the `0x0000..0xfeff` range to avoid collisions with reserved system types. There's no centralized registry — each Link's `Channel` instance maintains its own `message_factories` dict mapping `msgtype` to a constructor.

#### 6.8.3 MSGTYPE registration

Both endpoints of a Link must register matching message types via `Channel.register_message_type(message_class)` before they can send or receive that type. The constructor must implement:

```python
class MyMessage(MessageBase):
    MSGTYPE = 0x1234           # uint16 in [0x0000, 0xfeff]
    def pack(self) -> bytes: ...
    def unpack(self, raw: bytes): ...
```

A receiver that gets a `msgtype` it didn't register raises `ChannelException(ME_NOT_REGISTERED)` and drops the message. A sender that tries to send a class without `MSGTYPE` defined raises `ChannelException(ME_NO_MSG_TYPE)`.

#### 6.8.4 Reliable delivery

Channel uses the standard §6.5 mandatory PROOF receipt mechanism for each message — every Channel DATA packet generates a PROOF, and the sender's `Channel` retries on timeout up to a per-packet limit. Reliability is the main reason to use Channel over plain Link DATA: the application doesn't need to implement its own retransmit logic.

The receiver-side `Channel` uses a **sliding window** with the same window-growth dynamics as §10 Resources (`Channel.WINDOW = 2` initial, with rate-thresholded growth/shrink). Sequence numbers in the channel header let the receiver detect gaps and request retransmits; out-of-order arrivals are buffered until the gap fills.

#### 6.8.5 When to use Channel vs the alternatives

| Use case | Best mechanism |
|---|---|
| One-shot small request → one-shot small response | §11 REQUEST/RESPONSE |
| One-shot large transfer (file, page) | §10 Resource |
| Continuous bi-directional small messages (chat, telemetry stream, command/event flow) | §6.8 Channel |
| Continuous bi-directional large transfers | §10 Resources sequenced in time, OR Channel with `SMT_STREAM_DATA` chunks |

A clean-room client that only implements opportunistic LXMF can ignore Channel entirely. NomadNet-aware clients need it for the channel API; custom-RPC applications may prefer it over §11 for its bi-directional nature.

#### 6.8.6 Source map

| File | What |
|---|---|
| `RNS/Channel.py:113-148` | `Envelope` — wire-form pack/unpack |
| `RNS/Channel.py:151-...` | `Channel` — windowed reliable delivery on a Link |
| `RNS/Channel.py:45-46` | `SMT_STREAM_DATA = 0xff00` reserved system type |
| `RNS/Channel.py:253-260` | `register_message_type` — per-Link MSGTYPE dispatch table |
| `RNS/Packet.py:86` | `CHANNEL = 0x0E` context constant |

### 6.9 Source

`RNS/Link.py`, `RNS/Packet.py::prove`, `RNS/Identity.py::prove`, `RNS/PacketReceipt.py::validate_proof`, `RNS/Channel.py`.

---

## 7. Transport behavior — the parts that bite

### 7.1 Path requests: peers send `path?` before opportunistic LXMF when no path is known

The path-request preamble in upstream LXMF is **conditional, not unconditional** (verified by `tools/verify_path_request.py` against LXMF 1.1.1):

```python
# LXMF/LXMRouter.py::handle_outbound, ~line 1777
if not RNS.Transport.has_path(destination_hash) and lxmessage.method == LXMessage.OPPORTUNISTIC:
    RNS.log("Pre-emptively requesting unknown path for opportunistic ...", RNS.LOG_DEBUG)
    RNS.Transport.request_path(destination_hash)
    lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
```

In other words: a `path?` is sent before the LXM **only when no entry exists in `Transport.path_table`** for the target — `has_path()` is just a key-presence check via `LXMRouter.handle_outbound`. Existing-but-stale path entries are NOT replaced by this preamble; LXMF instead leans on the periodic `Transport.jobs` cycle to evict expired path entries (`stale_paths` accumulator at `RNS/Transport.py:780+`), after which the next outbound LXM rediscovers the unknown-path branch and triggers the `request_path`. A second `request_path` is issued from the retry path (`LXMRouter.py:2736+`) once `lxmessage.delivery_attempts >= MAX_PATHLESS_TRIES`, so on a flaky path peers can see multiple `path?` retransmits without intervening DATA — that matches BLE-trace observations.

The timing constants governing the preamble and the retry loop are class-level on `LXMRouter` (`LXMF/LXMRouter.py:30-34` in LXMF 1.1.1; verified by `tools/verify_path_request.py`):

| Constant | Value | Role |
|---|---|---|
| `PATH_REQUEST_WAIT` | `7` s | Deferral after issuing the `path?` preamble (or a retry-path `request_path`) before the next delivery attempt. |
| `DELIVERY_RETRY_WAIT` | `10` s | Wait between delivery attempts when a path is known but the prior attempt produced no delivery proof. Constant across attempts — no exponential backoff. |
| `MAX_DELIVERY_ATTEMPTS` | `5` | Delivery attempts before the message is marked failed. |
| `MAX_PATHLESS_TRIES` | `1` | Attempts without a path before the retry loop fires the second `request_path` above. |

The full per-message retry state machine consuming these constants is walked in [`flows/lxmf-outbound-retry.md`](flows/lxmf-outbound-retry.md).

A `path?` request itself is a regular DATA packet (verified by `tools/verify_path_request.py`):

- `dest_hash = SHA256(SHA256("rnstransport.path.request")[:10])[:16] = 6b9f66014d9853faab220fba47d02761`
- `dest_type = PLAIN`, `transport_type = BROADCAST`, `header_type = HEADER_1`, `context = CTX_NONE`
- payload (`RNS/Transport.py::request_path`):
  - **leaf clients** (transport disabled): `target_dest_hash(16) || random_tag(16)` — 32 bytes
  - **transport-enabled originators**: `target_dest_hash(16) || transport_id(16) || random_tag(16)` — 48 bytes — so the responding announce can be routed back along the request's reverse path

### 7.2 Responding to path requests

**Every node — including non-transport leaf clients — that knows the requested target MUST respond by re-announcing.** This is the only way the requester learns a path back. If you implement only the "send a path request" half but not the "respond to incoming requests for our own destination" half, peers can never message you after the path expires (typically within minutes after your last announce).

#### 7.2.1 Path-request packet parse rules

The path-request handler at `RNS/Transport.py:2954-2997` parses inbound packets addressed to `path_request_destination` (the dest_hash in §7.1). The handler is registered as the destination's `packet_callback` at `Transport.py:260`, so any DATA packet to that dest_hash flows through it.

The path-request destination is a **PLAIN destination** with no identity attached, which is why its `dest_hash` derives only from the name: `dest_hash = SHA256(SHA256("rnstransport.path.request")[:10])[:16]` per the PLAIN/GROUP recipe in §1.4.3 (the `identity == None` branch of `Destination.hash` at `RNS/Destination.py:121-130`). The result is a constant — `6b9f66014d9853faab220fba47d02761` — that every node on the mesh resolves identically without needing to discover a per-peer identity first.

```python
def path_request_handler(data, packet):
    if len(data) >= 16:
        destination_hash = data[:16]                                  # mandatory 16B target
        if len(data) > 32:
            requesting_transport_instance = data[16:32]               # optional 16B transport_id
        else:
            requesting_transport_instance = None

        # tag bytes — required, anything past the fixed prefix
        tag_bytes = data[32:] if len(data) > 32 else (data[16:] if len(data) > 16 else None)
        if tag_bytes is None:                                         # tagless requests are dropped
            return
        if len(tag_bytes) > 16:
            tag_bytes = tag_bytes[:16]                                # cap to 16B
```

Three observations that matter for interop:

1. **Tagless requests are dropped.** A path? packet with exactly 16 bytes payload (just `target_dest_hash`, no tag) is logged at DEBUG level and discarded. The tag is what makes the request unique enough to dedup — without it, a relay would loop forever on retransmits of the same packet. A clean-room implementation MUST emit at least one tag byte; the upstream emitter (`RNS.Transport.request_path`) uses 16 random bytes.
2. **The transport_id field is optional and detected by length.** If the payload is exactly 32 bytes the second 16B slot is the tag; if it's >32 bytes the second 16B is `transport_id` and the rest is the tag. This is consistent with the §7.1 description (leaf: 32B; transport: 48B) but the boundary case `len == 32` lands in the leaf-client interpretation.
3. **The tag is capped at 16 bytes.** Any tail beyond that is silently truncated. Senders may emit longer tags but receivers normalize to 16B for dedup table keys.

#### 7.2.2 Tag-based deduplication

The handler builds `unique_tag = destination_hash || tag_bytes` and consults `Transport.discovery_pr_tags` (`Transport.py:2835-2845`):

```python
unique_tag = destination_hash + tag_bytes

with Transport.discovery_pr_tags_lock:
    if not unique_tag in Transport.discovery_pr_tags:
        Transport.discovery_pr_tags.append(unique_tag)
        Transport.path_request(destination_hash,
                               from_local_client(packet),
                               packet.receiving_interface,
                               requestor_transport_id=requesting_transport_instance,
                               tag=tag_bytes)
    else:
        # ignore duplicate path request
```

`discovery_pr_tags` is bounded at `Transport.max_pr_tags = 32000` entries (`Transport.py:127`); older entries are aged out by the periodic `Transport.jobs` cycle. **Every node — leaf or transport — that wants to respond to path requests MUST maintain this dedup table** or it will respond to every retransmit, and a transport-enabled node will additionally re-forward to all other interfaces, generating a broadcast storm.

The `unique_tag = dest_hash || tag` format means the same tag bytes against different destination_hashes are distinct — so two different requesters racing for the same target with happenstance-identical random tags don't suppress each other. Senders MUST use a fresh random tag per fresh request (the upstream emitter calls `Identity.get_random_hash()`); reusing tags across requests for the same destination_hash makes the second request appear to be a duplicate.

#### 7.2.3 The five-way dispatch in `Transport.path_request`

`RNS/Transport.py:2999-3145`. After dedup, the handler calls into `path_request()` which decides how to respond. Five mutually-exclusive branches in priority order:

1. **`destination_hash` is local** (i.e. it's one of our own registered destinations, line 2873-2875):
   ```python
   local_destination.announce(path_response=True, tag=tag,
                              attached_interface=attached_interface)
   ```
   We answer by emitting a path-response announce (§7.2.4 below) on the interface the request arrived on. **This is the only branch a leaf client must implement** — the others are transport-mode behaviours.

2. **Path is known via the path_table AND `(transport_enabled OR is_from_local_client)`** (line 3030-3092): retrieve the cached announce packet from the path table, set its hops to the cached value, and queue it for retransmit. If the next hop happens to be the requestor itself (path-loop indicator), drop instead. This is the transport-mode path-resolver: a relay that already knows where the destination lives answers on its behalf, saving the requester from another hop of broadcast.

3. **Request is from a local-client interface, no path known** (line 3094-3100): forward the request to every OTHER interface so the broader mesh can answer. Generates a fresh random tag for the forwarded request to avoid loop-back through the same dedup table.

4. **`transport_enabled` AND no path known AND interface allows discovery** (line 3102-3125): record a `discovery_path_requests` entry (capped at `PATH_REQUEST_TIMEOUT = 15s`) and forward the request to every other interface, **preserving the original tag** to prevent loops. Since RNS 1.4.2 the fan-out additionally skips any interface that is not `online` (`if not interface.online: continue`, `RNS/Transport.py:3129`), alongside the pre-existing `search_mode_filter` and per-interface egress-limit checks. This is recursive transport-mode discovery — we don't know the destination but we'll go ask the rest of the mesh.

5. **No path known and not transport-enabled** (line 3139-3140): log "no path known" and drop. Leaf clients hit this branch when they receive a path? for someone else's destination.

Branch 1 is the only MUST for any node that wants to be reachable. Branches 2-4 are transport-node behaviours; a leaf client safely ignores them by never being in `transport_enabled` mode.

#### 7.2.4 Path-response announce wire format

When branch 1 fires, `Destination.announce(path_response=True, tag=tag, ...)` runs. The wire bytes are **identical to a regular announce (§4.1)** except the outer Reticulum packet's context byte is set to `PATH_RESPONSE = 0x0B` instead of `NONE = 0x00` (`RNS/Destination.py:307-308`):

```python
if path_response: announce_context = RNS.Packet.PATH_RESPONSE
else:             announce_context = RNS.Packet.NONE
```

The body — public_key || name_hash || random_hash || [ratchet_pub] || signature || app_data — is built identically; the random_hash carries a fresh emission timestamp, the signature is computed over the same signed_data per §4.2. A receiver running the validation flow in §4.5 can't tell from the announce body that this is a response to a query rather than a periodic re-announce; only the context byte distinguishes them.

A `tag` argument hands a previously-built path-response announce body back unchanged when the same tag is requested twice within `Destination.PR_TAG_WINDOW = 30s` (`RNS/Destination.py:260-278`). This is what prevents a flood of identical path-response announces when several relays simultaneously forward the same path? request to a leaf — the leaf serves the cached body to all of them with the same wire bytes, lining up dedup decisions on every transit relay.

#### 7.2.5 Timing: `PATH_REQUEST_GRACE` and roaming

When branch 2 fires (transit relay answering on behalf of a remote destination), the rebroadcast is delayed by `PATH_REQUEST_GRACE = 0.4s` (`Transport.py:80`) — extra grace to let directly-reachable peers respond first if they're in earshot. On `MODE_ROAMING` interfaces an additional `PATH_REQUEST_RG = 1.5s` is added on top (`Transport.py:81`) so well-connected fixed nodes get a chance to answer before mobile ones.

Branch 1 (local destination answers) fires immediately with no grace, since the leaf is the authoritative source for its own destination — there's no point waiting for someone else to potentially answer faster.

Local-client originators also bypass the grace period (`Transport.py:3068-3073`): a relay answering for a destination that lives on a local-client interface can send back the cached announce instantly because the answer doesn't need to compete with peer-mesh announces.

#### 7.2.6 Minimum responsibility for a leaf

The minimum path-request response logic for a non-transport leaf, in protocol terms:

1. Receive a DATA packet with `dest_hash == 6b9f66014d9853faab220fba47d02761`.
2. Parse `target_dest_hash = data[:16]` and `tag_bytes = data[16:32]` (or `data[32:48]` if `len(data) > 32`).
3. Drop if `len(tag_bytes) == 0` (tagless requests).
4. Drop if `(target_dest_hash, tag_bytes)` already in the dedup table. **A leaf-appropriate cap is 128–256 entries with FIFO eviction**; the upstream `max_pr_tags = 32000` (§7.2.2) is sized for a transit node maintaining dedup across all destinations on the mesh, not a leaf that only sees requests for itself.
5. If `target_dest_hash == our_destination_hash` for any of our registered destinations: emit a path-response announce (§7.2.4) on the receiving interface, with the request's tag passed through.
6. Otherwise: do nothing — leaves can't fulfill path requests for destinations they don't OWN.

Steps 4 and 5 are both required. Skipping the dedup table makes the leaf storm the network with redundant announces; skipping the local-destination check means peers can never message you after the path expires.

**Leaves may skip the §7.2.5 `PR_TAG_WINDOW` body cache** — step 4's dedup table already collapses identical-tag retransmits, and a leaf isn't fanning the same body to multiple downstream relays the way a transit node does, so the 30-second cache offers no additional dedup-convergence benefit. The cache exists upstream because `Destination.announce` runs the same code path for both leaves and transit nodes; on a leaf, the cache is incidental.

For a chronological walk-through of the full request → response → path-table cycle, see [`flows/path-discovery.md`](flows/path-discovery.md).

### 7.3 Ratchet rotation (forward-secrecy hygiene, not dedup)

The 32-byte `ratchet_pub` field in announces is meant to rotate periodically. The **purpose** is forward secrecy: rotating the ECDH key on a regular cadence limits the plaintext window an adversary can decrypt if a single ratchet privkey leaks. It is **not** what makes your announces visible to the mesh.

The actual replay-and-loop defence in upstream is keyed on **`random_hash`**, not on `ratchet_pub` — see §4.5 step 6.3 (path-table replacement check `not random_blob in random_blobs` at `RNS/Transport.py:1832, 1865, 1876`). Verified by `tools/verify_ratchet_dedup.py`: two announces sharing a `ratchet_pub` but differing in `random_hash[:5]` are both accepted by upstream's replay machinery.

> ⚠️ **Spec correction:** Earlier revisions of this section claimed transit nodes dedup announces on `(destination_hash, ratchet_pub)` tuples and that a non-rotating client becomes invisible to the mesh after one announce. That was wrong on the mechanism: upstream's `RATCHET_INTERVAL = 30 min` × `ANNOUNCE_INTERVAL = 5–15 min` means most upstream announces share a ratchet across 2–6 emissions, so if relays really dropped on `ratchet_pub` equality, upstream wouldn't function. The actual win observed in the bootstrap test (per `agent.md` §5) was incidental — the fix that rotated ratchets per announce also rotated `random_hash`, and it was the latter that mattered.

#### 7.3.1 Rotation cadence

Upstream `Destination.rotate_ratchets()` (`RNS/Destination.py:227-235`) runs on every announce but is a no-op unless `RATCHET_INTERVAL = 30*60s` has elapsed since the last rotation:

```python
def rotate_ratchets(self):
    if now > self.latest_ratchet_time + self.ratchet_interval:
        new_ratchet = Identity._generate_ratchet()
        self.ratchets.insert(0, new_ratchet)
        ...
```

So a Sideband emitting an announce every 10 minutes generates a new ratchet at most every 30 minutes (3 announces per ratchet). Path-response announces and periodic announces both call `rotate_ratchets()` and both go through this no-op-if-recent gate.

#### 7.3.2 What MUST be unique per announce

For your destination to remain visible across multiple announces, what MUST change between back-to-back emissions is **`random_hash`**, not `ratchet_pub`. Per §4.1, `random_hash` is constructed as:

```python
random_hash = get_random_hash()[:5] + int(time.time()).to_bytes(5, "big")
```

So as long as you regenerate the first 5 random bytes per announce (which any sensible implementation does), upstream's replay defence accepts each announce as fresh regardless of whether the ratchet rotated. A clean-room client that hard-coded `random_hash` to a constant value would be invisible after the first announce; one that uses fresh random bytes per announce is visible regardless of ratchet rotation cadence.

#### 7.3.3 Per-announce ratchet rotation is fine but not required

Implementations MAY rotate the ratchet on every announce — the only cost is more frequent ratchet-ring growth (capped by §7.4 `RATCHET_COUNT = 512`) and slightly more CPU. They MAY also follow upstream's at-most-every-30-minutes pattern. Either is interop-correct.

What MUST be stable across all rotations: the long-term encryption / signing keys and the `identity_hash` / `destination_hash`. Rotating those means contacts have to re-discover you (different `dest_hash`, no path table entry).

#### 7.3.4 Path-response announces SHOULD reuse the current ratchet

When fulfilling a `path?` request via `Destination.announce(path_response=True, tag=tag)` (§7.2.4), implementations SHOULD reuse the current ratchet rather than rotate. Rotation cadence is governed by §7.3.1 (the 30-minute window), not by inbound `path?` arrivals — a leaf burst-rotating on a flood of identical-target path? requests would burn through ratchet-ring slots without any forward-secrecy benefit, since the announces are all going to the same in-flight requester. Upstream's `rotate_ratchets()` no-op-if-recent gate enforces this implicitly; a clean-room implementation should mirror the behaviour explicitly.

#### 7.3.5 Ratchet-less announces are always accepted

Emitting `context_flag = 0` (no `ratchet_pub` field, body layout per §4.5 step 1, second branch) is interop-correct against every RNS 1.x receiver. `validate_announce` parses both layouts unconditionally; there are no upstream peers that strict-reject ratchet-less announces. The trade-off is **forward secrecy only**: a ratchet-less destination encrypts every opportunistic message to its long-term X25519 key (§3.2 step 2), so a future leak of that long-term privkey decrypts every prior message. Path-table population, signature verification, dest_hash routing, and Link establishment all work unchanged. A new implementation that defers ratchets to v2 will interop fine; the missing forward secrecy should be called out in its README. A future RNS major *may* make ratchets mandatory, but that would be a wire-incompatible change announced ahead of time.

### 7.4 Ratchet ring (inbound decrypt tolerance)

Senders cache the most recent ratchet they've seen for each destination. If you rotate your ratchet faster than relays propagate the announce, in-flight messages may arrive encrypted to your *previous* ratchet. To decrypt these, keep a ring of recent ratchet privkeys and try each in order during decrypt. The fallback to the long-term identity privkey is the ultimate safety net.

Upstream's default ring size is **`Destination.RATCHET_COUNT = 512`** (`RNS/Destination.py:85` in RNS 1.4.2), with a minimum rotation interval of `RATCHET_INTERVAL = 30*60` seconds (line 90) and per-ratchet `RATCHET_EXPIRY = 60*60*24*30` seconds (`RNS/Identity.py:69`). A new ratchet is generated on each `rotate_ratchets()` call and prepended to the in-memory list; `_clean_ratchets` truncates back to `RATCHET_COUNT`. The 512 figure is generous and not a hard interop requirement — it's an in-memory bound on the inbound-decrypt try-list.

A minimal client may keep just the current ratchet privkey, accepting that the brief window between rotation and announce-propagation will lose some messages. Mention the trade-off in your implementation notes.

### 7.5 Periodic re-announce

Transport node path tables expire entries after a few minutes. Clients should re-announce on a 5–15 minute cadence as a baseline so cached paths stay fresh. Without this, even peers who saw your initial announce will be unable to reach you after path TTLs lapse.

### 7.6 `TCPServerInterface.OUT` is True by default in practice

`RNS/Interfaces/TCPInterface.py` line 522 sets `self.OUT = False` in the constructor. This is overridden to `True` by `RNS/Reticulum.py` post-init at line 771-772 for any interface declared in the rnsd config:

```python
if "outgoing" in c and c.as_bool("outgoing") == False: interface.OUT = False
else:                                                  interface.OUT = True
```

Spawned client interfaces (one per connecting TCP client) inherit `OUT` from their parent. So in practice, every TCPServerInterface CAN forward unless the operator explicitly opted out. Do not waste time chasing the constructor's `OUT = False` default; it doesn't hold post-init.

### 7.7 Source

`RNS/Transport.py` `outbound`, `inbound`, `request_path`, `announce`. `RNS/Reticulum.py` `interface_post_init` for the OUT-flag override.

---

## 8. Transport framing

### 8.1 KISS (BLE / serial / RNode link)

```
FEND  = 0xC0    // frame delimiter
FESC  = 0xDB    // escape
TFEND = 0xDC    // escaped FEND  → 0xDB 0xDC
TFESC = 0xDD    // escaped FESC  → 0xDB 0xDD

frame = FEND || cmd_byte || escaped(data) || FEND
```

`cmd_byte` for received/transmitted Reticulum packets is `CMD_DATA = 0x00`. RNode firmware prefixes each received CMD_DATA frame with `CMD_STAT_RSSI = 0x23` (one byte payload, signed value = byte − 157) and `CMD_STAT_SNR = 0x24` (one byte payload, signed Q6.2 → divide by 4 for dB).

Over BLE, KISS frames are split across BLE notifications. A streaming parser MUST accumulate bytes across notifications and emit complete frames only on FEND boundaries.

### 8.2 HDLC (TCP / `rnsd TCPServerInterface`)

```
FLAG = 0x7E
ESC  = 0x7D
ESC_MASK = 0x20

frame = FLAG || escaped(data) || FLAG
escape: 0x7E → 0x7D 0x5E   (FLAG ^ ESC_MASK)
        0x7D → 0x7D 0x5D   (ESC  ^ ESC_MASK)
```

No command byte, no RSSI/SNR sidecar — the HDLC payload IS the raw Reticulum packet. Source: `RNS/Interfaces/TCPInterface.py::HDLC`.

### 8.3 RNode air-frame header and split-packet protocol

The 1-byte header described here lives **between RNodes on the LoRa air-frame**, not on the KISS host channel. The upstream RNode firmware adds it on every TX and strips it on every RX before forwarding the payload to the host as `CMD_DATA`. KISS hosts (RNS, NomadNet, Sideband, etc.) NEVER see this byte. Two RNodes that talk LoRa to each other use it to glue two LoRa frames into one Reticulum packet of up to 508 bytes; an alternative implementation that talks LoRa to an RNode (e.g. a clean-room repeater firmware) MUST construct and parse this header bit-exactly, or its TX will be invisible and its RX will mistake the header byte for the first payload byte.

#### Header byte layout

From `markqvist/RNode_Firmware/Framing.h:105-108`:

```
bit 7..4 : seq         (NIBBLE_SEQ   = 0xF0) — random sequence id, set on each TX
bit 3..1 : reserved    (currently always 0)
bit 0    : FLAG_SPLIT  (NIBBLE_FLAGS = 0x0F, FLAG_SPLIT = 0x01)
SEQ_UNSET = 0xFF                            — sentinel: "no first half buffered"
```

Helpers (`Utilities.h:1218-1224`):

```c
inline bool    isSplitPacket(uint8_t h) { return (h & FLAG_SPLIT); }   // 0x01 mask
inline uint8_t packetSequence(uint8_t h){ return h >> 4; }             // 0..15
```

Constants (`Config.h:59-61`):

```c
#define MTU         508    // max reassembled Reticulum packet payload (2 × 254)
#define SINGLE_MTU  255    // max LoRa frame size (header + up to 254 payload bytes)
#define HEADER_L    1      // header overhead per LoRa frame
```

#### Transmit (`RNode_Firmware.ino:716-742`)

```c
uint8_t header = random(256) & 0xF0;                      // fresh random seq nibble
if (size > SINGLE_MTU - HEADER_L) header |= FLAG_SPLIT;   // split iff payload > 254
LoRa->beginPacket();
LoRa->write(header);
for (i=0; i < size; i++) {
    LoRa->write(tbuf[i]);
    if (written == 255 && isSplitPacket(header)) {        // first frame full
        LoRa->endPacket();
        LoRa->beginPacket();
        LoRa->write(header);                              // SAME header byte on frame 2
        written = 1;
    }
}
LoRa->endPacket();
```

Behavioral facts that matter for interop:

1. **Sequence nibble is randomized on every fresh TX**, not incremented. Two consecutive split packets from the same node will have different (random) seq nibbles. This is the trick a memory-fading reader might recall as "the header rotates between transmissions" — it's per-packet randomization, not a per-retransmit byte rotation. There is no retransmit-driven byte rotation or rechunk; LoRa transmission is fire-and-forget at this layer, and a higher-layer retransmit (e.g. an RNS PROOF timeout firing again) just re-enters this function and gets a fresh random seq nibble.
2. **Both frames of a split share the same header byte byte-for-byte** — same seq nibble, same FLAG_SPLIT bit. The receiver pairs them by exact equality of the seq nibble.
3. **The split point is at exactly 255 bytes total in the LoRa frame** (1 header + 254 payload). The second frame is `header || remainder`, where `remainder` is whatever is left after 254 bytes of payload have been emitted. Maximum reassembled packet payload is `2 × 254 = 508` bytes — Reticulum's `HW_MTU` for the RNode interface is set to match.
4. **Single-frame packets (payload ≤ 254)** still carry the 1-byte header but with `FLAG_SPLIT == 0`. The seq nibble is still random per TX.

#### Receive / reassembly (`RNode_Firmware.ino:359-446`)

State on the receiver: `seq` (default `SEQ_UNSET = 0xFF`) tracks the seq nibble of any buffered first-half. Per inbound LoRa frame:

| Inbound `FLAG_SPLIT` | Buffered `seq` state | Inbound seq | Action |
|---|---|---|---|
| 1 | `SEQ_UNSET` (none) | any | Buffer this frame as the first half. Store its seq. |
| 1 | matches inbound seq | == buffered | Append. **Reassembly complete**. Reset buffer. |
| 1 | doesn't match | != buffered | Discard buffered first-half. Replace with this frame as a new first-half. |
| 0 | `SEQ_UNSET` (none) | n/a | Deliver this single-frame packet directly. |
| 0 | first-half present | n/a | Discard the buffered first-half; deliver this single-frame packet. |

In other words: the receiver holds **at most one** in-progress first-half, keyed by its random seq nibble. Any inbound frame that doesn't match (different seq, or non-split, or simply a long enough silence) replaces or discards it.

#### Reassembly timeout — implementation-defined

Upstream RNode firmware does **not** have an explicit time-based timeout for a buffered first-half — it relies on subsequent traffic (any inbound frame) to clear stale state via the table above. The clean-room repeater at `thatSFguy/reticulum-lora-repeater/src/Radio.cpp:189-194` adds a defensive **500 ms** timeout: if no second half arrives within that window, the buffered first-half is discarded. This is implementation-private: a packet that takes longer than 500 ms to fully transmit (very low SF + large payload) would be lost on a repeater following the clean-room timeout but would survive against an unbounded upstream RNode receiver as long as no other LoRa traffic landed in between.

A new alternative implementation should either match upstream's "no explicit timeout" or pick a value tied to the worst-case airtime of two `SINGLE_MTU` frames at the configured SF/BW, not a flat 500 ms.

#### Sequence-collision airtime ceiling

Because the seq nibble is 4 bits of randomness chosen per TX, two unrelated split packets from the same sender that overlap in time at any receiver will collide with probability 1/16 per pair. At sane LoRa duty cycles this is a non-issue, but it bounds the protocol — a sender that emits split packets back-to-back faster than the air can ferry them risks a reassembled packet that mixes halves of two distinct senders' outputs. The receiver has no way to detect this short of validating the resulting Reticulum packet (which a corrupt mix would fail at the HMAC step). Don't burst.

#### Source map

| File | What it pins down |
|---|---|
| `RNode_Firmware/Framing.h:105-108` | `NIBBLE_SEQ`, `NIBBLE_FLAGS`, `FLAG_SPLIT`, `SEQ_UNSET` constants |
| `RNode_Firmware/Config.h:59-61` | `MTU`, `SINGLE_MTU`, `HEADER_L` |
| `RNode_Firmware/Utilities.h:1218-1224` | `isSplitPacket`, `packetSequence` accessors |
| `RNode_Firmware/RNode_Firmware.ino:716-742` | TX-side header construction and split logic |
| `RNode_Firmware/RNode_Firmware.ino:359-446` | RX-side reassembly state machine |
| `reticulum-lora-repeater/src/Radio.cpp:35-45, 188-316, 351-405` | Clean-room reimplementation; adds 500 ms reassembly timeout |

### 8.4 RNode KISS configuration handshake

§8.1 covers the KISS framing between a host and an RNode. This section covers the **commands** a host issues over that framing to bring up an RNode and configure its radio. Before any Reticulum DATA packet can flow, every command listed here must succeed in approximately the order listed.

The canonical reference is `RNS/Interfaces/RNodeInterface.py` (the Python host driver) plus `RNode_Firmware/Framing.h` (the firmware-side command codes).

#### 8.4.1 Command-byte inventory

Each KISS frame is `FEND || cmd_byte || escaped_payload || FEND` (§8.1). The cmd_byte values used during configuration:

| Hex | Name | Direction | Purpose |
|---|---|---|---|
| `0x00` | `CMD_DATA` | both | Reticulum packet payload (the steady-state command after configuration is done) |
| `0x01` | `CMD_FREQUENCY` | host → RNode | Set radio frequency in Hz; payload is 4-byte big-endian uint32 |
| `0x02` | `CMD_BANDWIDTH` | host → RNode | Set radio bandwidth in Hz; payload is 4-byte big-endian uint32 |
| `0x03` | `CMD_TXPOWER` | host → RNode | Set TX power in dBm; payload is 1 byte |
| `0x04` | `CMD_SF` | host → RNode | Set spreading factor; payload is 1 byte (typically 7..12) |
| `0x05` | `CMD_CR` | host → RNode | Set coding rate denominator; payload is 1 byte (typically 5..8 for `4/5`..`4/8`) |
| `0x06` | `CMD_RADIO_STATE` | host → RNode | `0x00 = OFF`, `0x01 = ON` (turn the modem on after config) |
| `0x07` | `CMD_RADIO_LOCK` | host → RNode | Lock the radio against further config changes |
| `0x08` | `CMD_DETECT` | both | Hardware detect ping/pong (see §8.4.3 below) |
| `0x09` | `CMD_IMPLICIT` | host → RNode | Toggle implicit-header LoRa mode (advanced) |
| `0x0A` | `CMD_LEAVE` | host → RNode | Tell the RNode the host is disconnecting; payload `0xFF` |
| `0x0B` | `CMD_ST_ALOCK` | host → RNode | Short-term airtime limit; payload is 2 bytes big-endian uint16 of (limit × 100) |
| `0x0C` | `CMD_LT_ALOCK` | host → RNode | Long-term airtime limit; same encoding as ST_ALOCK |
| `0x0F` | `CMD_READY` | RNode → host | Boot complete signal |
| `0x21` | `CMD_STAT_RX` | RNode → host | RX-counter status |
| `0x22` | `CMD_STAT_TX` | RNode → host | TX-counter status |
| `0x23` | `CMD_STAT_RSSI` | RNode → host | RSSI sidecar for the next CMD_DATA frame; `dBm = byte − 157` |
| `0x24` | `CMD_STAT_SNR` | RNode → host | SNR sidecar; signed Q6.2 → `dB = byte / 4` |
| `0x26` | `CMD_STAT_PHYPRM` | RNode → host | Reports current frequency/bandwidth/SF/CR back; used for verification |
| `0x40` | `CMD_RANDOM` | both | Get random bytes from the RNode's hardware RNG |
| `0x47` | `CMD_BOARD` | RNode → host | Reports board model code |
| `0x48` | `CMD_PLATFORM` | RNode → host | Reports MCU platform code |
| `0x49` | `CMD_MCU` | RNode → host | Reports MCU variant code |
| `0x50` | `CMD_FW_VERSION` | RNode → host | Reports firmware version (2 bytes: major, minor) |
| `0x55` | `CMD_RESET` | host → RNode | Hard-reset the RNode; payload `0xF8` (`CMD_RESET_BYTE`) |

Full inventory in `RNode_Firmware/Framing.h:24-95`. The configuration handshake uses the bolded subset.

#### 8.4.2 Bring-up sequence

Adapted from `RNodeInterface.initRadio` (`RNS/Interfaces/RNodeInterface.py:470-481`):

```
1. Open serial port (or BLE GATT, or whatever bearer)
2. Optionally: hard_reset()           — CMD_RESET 0xF8 (2.25s wait afterwards)
3. detect()                            — CMD_DETECT + CMD_FW_VERSION + CMD_PLATFORM + CMD_MCU
4. (RNode replies asynchronously with CMD_DETECT 0x46, CMD_FW_VERSION, CMD_PLATFORM,
    CMD_MCU, CMD_BOARD over multiple frames — host correlates by command byte)
5. setFrequency()                      — CMD_FREQUENCY + 4B big-endian Hz
6. setBandwidth()                      — CMD_BANDWIDTH + 4B big-endian Hz
7. setTXPower()                        — CMD_TXPOWER + 1B dBm
8. setSpreadingFactor()                — CMD_SF + 1B
9. setCodingRate()                     — CMD_CR + 1B
10. setSTALock() / setLTALock()        — optional airtime limits
11. setRadioState(RADIO_STATE_ON)      — CMD_RADIO_STATE + 0x01
12. (RNode now in operational state; CMD_DATA frames flow in both directions)
```

The order matters: most firmwares accept config commands only while the radio is OFF (steps 5-10 must precede step 11). Setting parameters after `RADIO_STATE_ON` either silently fails or requires a `RADIO_STATE_OFF` round-trip first depending on firmware version. A clean-room driver should always set the radio OFF (or be in initial-boot state where it's OFF by default) before reconfiguring.

#### 8.4.3 The `CMD_DETECT` exchange

```
host → RNode :  FEND CMD_DETECT(0x08) DETECT_REQ(0x73) FEND
RNode → host :  FEND CMD_DETECT(0x08) DETECT_RESP(0x46) FEND
```

`DETECT_REQ = 0x73` and `DETECT_RESP = 0x46` are at `RNode_Firmware/Framing.h:99-100`. The two-byte exchange tells a host "yes, this thing on the other end of the serial port is an RNode and it's awake". The host follows up immediately with `CMD_FW_VERSION`, `CMD_PLATFORM`, `CMD_MCU` queries — those queries each have a single `0x00` placeholder byte payload (per `RNodeInterface.detect()` line 484) and the RNode replies asynchronously with the same command code carrying the actual answer.

A host driver should accumulate replies for ~1-2 seconds after sending `detect()` before assuming detection failed. The replies arrive in unpredictable order because the firmware fires them off as it produces each value.

`CMD_FW_VERSION`'s payload format is 2 bytes: `[major, minor]`. RNS rejects RNode firmware older than its `REQUIRED_FW_VER_MAJ` / `REQUIRED_FW_VER_MIN` constants and aborts the bring-up. A clean-room driver should at minimum log the version for diagnostics.

#### 8.4.4 4-byte big-endian numerics

`CMD_FREQUENCY` and `CMD_BANDWIDTH` payloads are unsigned 32-bit integers in big-endian byte order:

```python
c1 = self.frequency >> 24
c2 = self.frequency >> 16 & 0xFF
c3 = self.frequency >> 8  & 0xFF
c4 = self.frequency       & 0xFF
data = KISS.escape(bytes([c1, c2, c3, c4]))
```

The byte values are KISS-escaped before transmission per §8.1 (e.g. a frequency of `0xC0...` would have its leading `0xC0` byte escaped to `0xDB 0xDC`).

`CMD_TXPOWER`, `CMD_SF`, `CMD_CR`, `CMD_RADIO_STATE` payloads are single bytes, also subject to KISS escaping.

#### 8.4.5 Receive sidecar metadata

Every CMD_DATA frame from the RNode is preceded by two short metadata frames in the same byte stream (§8.1 already mentions this; the encoding):

```
FEND CMD_STAT_RSSI(0x23) <rssi_byte>  FEND
FEND CMD_STAT_SNR(0x24)  <snr_byte>   FEND
FEND CMD_DATA(0x00)      <data...>    FEND
```

Decode:

- `RSSI in dBm = rssi_byte - 157` (e.g. `rssi_byte = 50` means `-107 dBm`).
- `SNR in dB = (signed)snr_byte / 4` — `snr_byte` is interpreted as signed two's-complement Q6.2 fixed-point. So `0x10 (16) = 4 dB`, `0xF0 (-16) = -4 dB`, etc.

A host driver must cache the most recent RSSI/SNR pair and apply it to the next CMD_DATA frame. If it processes CMD_DATA before the sidecars arrive (e.g. the byte stream re-ordered them across an unreliable link), RSSI/SNR will be from the *previous* packet. In practice the firmware emits them in a tight sequence within microseconds, so reordering is only a concern over BLE notification boundaries (§8.1 closing paragraph).

### 8.5 RNode CSMA / airtime accounting

Real LoRa networks need carrier-sense and airtime budgets to avoid stepping on each other. The RNode firmware implements both server-side; the host is mostly told what's happening via `CMD_STAT_CHTM` (channel-time-metric, `0x25` in `Framing.h:45`) and chooses whether to inform the application.

#### 8.5.1 Airtime caps (`CMD_ST_ALOCK` / `CMD_LT_ALOCK`)

The host can set per-channel airtime limits via:

- **`CMD_ST_ALOCK`** (`0x0B`): short-term airtime lock. Payload is 2 bytes big-endian uint16 of `(limit_percent × 100)` — so `0x0B B8 = 3000 = 30.00%`. Default in `RNS/Reticulum.py` is `Reticulum.ANNOUNCE_CAP = 2.0` (= 2% airtime cap on transmissions, encoded as `0x00C8`).
- **`CMD_LT_ALOCK`** (`0x0C`): long-term version, same encoding. Long-term window length is firmware-private (typically 1 hour).

Once the cap is exceeded the firmware simply refuses to transmit and reports `CMD_ERROR ERROR_QUEUE_FULL (0x04)` if the host queues additional packets. A clean-room driver should treat these errors as backpressure and queue at the application layer rather than retry-spinning at the KISS layer.

#### 8.5.2 Pre-TX carrier sense

Before transmitting, RNode firmware listens on the configured frequency for a short window and aborts the TX if it detects an in-progress LoRa preamble — Listen-Before-Talk. The exact CSMA windowing is firmware-private; a clean-room implementation that talks LoRa via RadioLib (rather than via an RNode) needs to implement its own LBT to avoid stepping on RNodes and other peers. The reference implementation in `markqvist/RNode_Firmware/RNode_Firmware.ino:683-712` (the `add_airtime` accumulator and channel-utilisation tracking) is the canonical algorithm.

For host-side use cases — i.e. a Reticulum client driving an RNode — the firmware handles all CSMA invisibly and the host should not attempt its own. Host-side rate limiting at the announce-cap layer (§4.5 SHOULD-rule for ingress, and `Reticulum.ANNOUNCE_CAP` for outbound) is sufficient.

### 8.6 AutoInterface multicast discovery (LAN auto-detect)

`AutoInterface` is the IPv6-multicast-based protocol Reticulum nodes use to discover each other on a LAN with zero configuration. Drop a node on any IPv6-capable network, configure `[[Default Interface]] type = AutoInterface`, and it finds peers automatically — no static IPs, no rendezvous server.

The reference implementation is `RNS/Interfaces/AutoInterface.py` (~700 lines). This section specifies the wire-visible bits a clean-room implementation needs.

#### 8.6.1 IPv6 multicast group derivation

`AutoInterface.py:202-212`. Each AutoInterface mesh is identified by a `group_id` (default `b"reticulum"`); the actual multicast address is derived from a SHA-256 of the group_id:

```python
group_hash = SHA256(group_id)                     # 32 bytes

# Build the lower 7 hextets from group_hash bytes [2..14]:
gt  = "0"
gt += ":" + f"{(g[3]+(g[2]<<8)):02x}"            # bytes [2:4]
gt += ":" + f"{(g[5]+(g[4]<<8)):02x}"            # bytes [4:6]
gt += ":" + f"{(g[7]+(g[6]<<8)):02x}"            # bytes [6:8]
gt += ":" + f"{(g[9]+(g[8]<<8)):02x}"            # bytes [8:10]
gt += ":" + f"{(g[11]+(g[10]<<8)):02x}"          # bytes [10:12]
gt += ":" + f"{(g[13]+(g[12]<<8)):02x}"          # bytes [12:14]

mcast_discovery_address = "ff" + multicast_address_type + discovery_scope + ":" + gt
```

Where:

| Field | Default | Value bits |
|---|---|---|
| `multicast_address_type` | `"1"` (temporary) — alt `"0"` (permanent) | 4 bits, `RFC 4291` flags |
| `discovery_scope` | `"2"` (link-local) | 4 bits, IPv6 scope: `"2"=link, "4"=admin, "5"=site, "8"=org, "e"=global` |

So with the default `group_id = b"reticulum"`, default `multicast_address_type = "1"`, default `discovery_scope = "2"`, and `SHA256(b"reticulum")[2:14]` filling the lower hextets, every default-config Reticulum node on the same link-local subnet finds the same multicast address.

#### 8.6.2 UDP ports

`AutoInterface.py:47-48`:

| Port | Default | Use |
|---|---|---|
| `discovery_port` | `29716` (UDP) | Periodic discovery announces from each peer; receivers learn other peers' link-local IPv6 addresses by their incoming source addr. |
| `unicast_discovery_port` | `discovery_port + 1` = `29717` | Per-interface unicast probes, used to disambiguate which physical interface a peer is on. |
| `data_port` | `42671` (UDP) | Once peers know each other's addresses, actual Reticulum packets flow as plain UDP datagrams between them on this port. |

A clean-room implementation MUST listen on the discovery port for inbound multicast packets and the data port for inbound unicast packets, and emit periodic announces to the multicast address+port.

#### 8.6.3 Discovery cadence

`AutoInterface.py:61-64`:

| Constant | Value | Meaning |
|---|---|---|
| `ANNOUNCE_INTERVAL` | `1.6s` | Each AutoInterface emits a discovery announce on this cadence. |
| `PEERING_TIMEOUT` | `22.0s` | A peer not heard from within this window is dropped. |
| `PEER_JOB_INTERVAL` | `4.0s` | Cadence of the per-interface peer-management job (eviction, rediscovery). |
| `MCAST_ECHO_TIMEOUT` | `6.5s` | If our own multicast emissions are not echoed back within this window on a given physical interface, the multicast routing on that interface is presumed broken. |

The 1.6s + 22s pairing means a new node is discovered within ~1.6s of join (as soon as one announce cycle completes from any existing peer); a departing node is forgotten within ~22s of last contact. Both bounds are implementation-private, but a clean-room with radically different values may have visible interop quirks (peer flap if you announce too rarely; bandwidth waste if too often).

#### 8.6.4 Discovery announce body format

The discovery announce is a plain UDP datagram on the multicast address. The body is implementation-private — upstream uses a small msgpack blob containing the peer's `group_hash` (so peers from a different group on the same link don't accidentally peer), interface MTU, and an optional IFAC seal (Interface Authentication Code; if present, peers without the matching IFAC key reject the announce). Specific bytes of the discovery announce body aren't part of the wire spec for **Reticulum**; they're part of the wire spec for **AutoInterface peering**, and a clean-room AutoInterface implementation needs to mirror upstream's format. Read `AutoInterface.py::announce_handler` and `AutoInterface.peer_jobs` for the full layout.

#### 8.6.5 Once peers are discovered

After the discovery handshake establishes that two nodes are in the same Reticulum group on the same physical link, all subsequent Reticulum packet traffic flows as **plain UDP datagrams** on the data port (`42671` by default), unicast between the discovered link-local IPv6 addresses. There's no per-packet framing beyond the UDP envelope — each datagram body is one complete Reticulum packet (§2). Out-of-order delivery is handled by Reticulum's normal dedup and (where present) Link sequencing; UDP packet loss is masked by Reticulum's PROOF receipts and Resource sliding-window retransmits.

Effective HW_MTU is `1196` bytes (`AutoInterface.HW_MTU`, line 44) — chosen to fit comfortably within standard Ethernet MTU minus IPv6/UDP overhead.

#### 8.6.6 IFAC integration

If the AutoInterface is configured with an `ifac_identity` (out-of-band-shared key), every Reticulum packet on the data port is IFAC-sealed and unmasked using the standard Transport-level IFAC mechanism (`RNS/Transport.py:1439-1490`). Peers with mismatched IFAC keys can see each other's discovery announces but can't decode each other's data — a pragmatic privacy boundary on a shared LAN.

#### 8.6.7 Source map

| File | What |
|---|---|
| `RNS/Interfaces/AutoInterface.py:43-72` | Default ports, group_id, scope/address-type constants, intervals |
| `RNS/Interfaces/AutoInterface.py:202-212` | Multicast address derivation from `SHA256(group_id)` |
| `RNS/Interfaces/AutoInterface.py:108+` | Per-interface socket setup (multicast join, unicast bind) |
| `RNS/Interfaces/AutoInterface.py::announce_handler` | Discovery announce emission |
| `RNS/Interfaces/AutoInterface.py::peer_jobs` | Peer aging, multicast-echo loop, IFAC sealing |

---

## 9. Implementation gotchas

The findings here cost the most debugging hours per insight ratio. They're not in the upstream manual.

### 9.1 LXMF `source_hash` is the destination hash, not the identity hash

The 16-byte `source_hash` field in an LXMF body is the sender's destination hash (`SHA256(name_hash || identity_hash)[:16]`), NOT the raw 16-byte identity hash. Sending the identity hash here means the recipient can't look you up in their contacts (which are keyed by destination hash) and the conversation gets orphaned.

### 9.2 Web Crypto and JCA AES-CBC auto-pad PKCS#7 — do not pad manually

Both browser `window.crypto.subtle.encrypt({name:"AES-CBC", iv}, key, plaintext)` and JCA's `Cipher.getInstance("AES/CBC/PKCS5Padding")` apply PKCS#7 padding automatically. Manually padding before calling them produces double-padded ciphertext (16 garbage bytes added) that decrypts to plaintext + a trailing PKCS#7 block which the receiver can't strip cleanly.

### 9.3 RNS bundles `umsgpack` — encode display names as `bytes`, not `str`

`RNS/vendor/umsgpack.py` is locked to behaviors regardless of system msgpack:

- `_pack_string` (Python `str`) → `0xa0|len`/`0xd9`/`0xda`/`0xdb` (fixstr/str8/str16/str32)
- `_pack_binary` (Python `bytes`) → `0xc4`/`0xc5`/`0xc6` (bin8/bin16/bin32)
- `_unpack_string` decodes to Python `str` via `bytes.decode("utf-8")`
- `_unpack_binary` returns raw Python `bytes`

The downstream parser at `LXMF/LXMF.py:165` does `dn.decode("utf-8")` on the unpacked first element. This works only when `dn` is `bytes`. If a producer wrote a `str`-encoded name (fixstr), umsgpack returns Python `str`, `.decode()` raises `AttributeError`, the parser swallows it and returns `None` → no display name.

**Implementation rule:** encode the display name field as msgpack `bin` (Python `bytes` equivalent), never `str`. Upstream LXMRouter does this correctly via `display_name.encode("utf-8")` before packing.

### 9.4 Display name preservation across re-announces

Inbound announce ingestion code that uses

```
new_name = extracted ?? known_label ?? ""
merged   = (new_name).ifBlank { existing.name ?? "" }
```

clobbers a real cached name with the placeholder `known_label` (e.g. "LXMF delivery") whenever a minimal re-announce arrives without `app_data`. The next full announce restores it. Symptom: contacts blink to placeholder names briefly during/after activity.

Correct priority order: `extracted ?? existing ?? known_label ?? ""`. The known label fallback is for completely unknown destinations only.

### 9.5 Self-announce echo

If the operator runs both an originating client and a transport node on the same machine (or the same RNode loops back its own emissions), a client will receive its own announce and may add itself to the contact list. Filter announces whose `dest_hash == our_dest_hash` before ingestion.

### 9.6 Clockless sender timestamps

LoRa devices without an RTC will populate the LXMF `timestamp` field with seconds-since-boot (small integers like 30, 90720). Treat any timestamp before 2020-01-01 (`1577836800`) as "no clock" and substitute the local receive time. Otherwise messages from clockless devices appear at January 1 1970 in the inbox.

### 9.7 Periodic re-announce is non-optional

Even after a successful initial announce, paths in the mesh expire within minutes. Without a 5–15 minute re-announce loop, the second message any peer tries to send you will fail because the relay's path table has aged out. (See also §7.5.)

There is **no upstream-mandated default** — `RNS/Reticulum.py:881` uses `6*60*60` (6 h) for interface-level *discovery* announces and `RNS/Transport.py:196` uses `2*60*60` (2 h) for transport-management announces, but those are not the cadence end-user destinations announce at. Sideband emits roughly every 30 minutes; the upstream manual recommends 30–60 minutes for a desktop client. Practical guidance for application destinations:

| Deployment | RECOMMENDED cadence |
|---|---|
| Low-MTU LoRa node, mostly-on radio | 5–10 min — short enough to outpace path-table TTL, sparse enough not to dominate airtime |
| Always-on rnsd-on-IP relay | 15–30 min — faster doesn't help (peer caches stay fresh between announces) |
| Mobile / power-constrained client | 5–10 min while radio active, suppress while suspended |

AVOID < 60 s — short intervals trigger ingress rate limiting (§4.5 step 8) and burn ratchet-ring slots without benefit, since ratchets only rotate every 30 min anyway (§7.3.1). AVOID > 30 min on lossy links — the longer the gap, the more likely your next outbound message lands during a window when no relay holds a path back to you.

### 9.8 The destination hash uses the bare app-name string

An earlier-vintage bug in several implementations was to include the identity's hex hash in the `name_hash` input. `expand_name` in upstream Python takes an `identity` parameter and conditionally appends the identity hex IF the identity is non-None — but the Destination construction path passes `identity = None`. The `name_hash` MUST be `SHA256(plain_app_name_string)[:10]`, nothing more. (See also §1.2.)

### 9.9 Diagnostic: rx-log every inbound packet at the engine entry

A single line of the form

```
rx <size>B H<1|2> <PT> dest=<hex> ctx=0x<hex> hops=<n>
```

logged before any filtering converts hours of "messages aren't arriving" debugging to seconds. Without it, packets dropped by `if (dest != ours) return` vanish silently and look identical to "the bytes never arrived". Symmetric `tx` logging on outbound is similarly cheap insurance.

### 9.10 microReticulum `random_hash` lacks the timestamp half

Real interop bug to plan around: `attermann/microReticulum`'s `Destination::announce` emits 10 fully-random bytes for the announce `random_hash` field rather than the upstream Python form of `5 random bytes || big-endian uint40 unix_seconds` (see §4.1). The Python form is preserved as a comment in the C++ source with a `TODO add in time to random hash` next to it; the timestamp half was never implemented.

Effect on a mixed-vendor mesh: a Python RNS receiver parses `random_hash[5:10]` of a microReticulum announce as a far-future timestamp (median ~year 19403 AD because the random uint40 is uniformly distributed across `0..2^40-1`). The path-table replacement rule at `RNS/Transport.py:1854-1882` rejects subsequent real-timestamped announces from Python sources as "stale" until the path TTL expires.

Symptom: a microReticulum repeater works fine when it's the only path; in a mesh that also has Python relays, paths "stick" to the microReticulum side even when shorter / fresher Python paths come up, until natural TTL expiry. First-contact path-table population is unaffected — the bug only surfaces on path replacement.

Workarounds when building a clean-room implementation that talks to a microReticulum mesh:
- Emit the upstream form yourself (you have a clock — even seconds-since-boot is preferable to random bytes; the path-table comparison only cares about ordering, not absolute time).
- If you receive a uint40 timestamp that's more than, say, 24 hours in the future, treat it as suspect — but be cautious because legitimate Python senders with skewed clocks could trip this.

The repeater repo's `pre_build.py` patches several other microReticulum protocol bugs (ratchet announce parsing, identity hash length 16→32, DATA/PROOF forwarding) but does not patch this one. Filing an upstream issue against `attermann/microReticulum` to land the original Python timestamp form is the durable fix.

---

## 10. Resource fragmentation protocol

A **Resource** transfers a payload that exceeds the per-packet content limit of an established Reticulum Link. It is the only way to carry an LXMF body, NomadNet page, or file larger than ~360 bytes (`LINK_PACKET_MAX_CONTENT`) over a Link. Resource is built **on top of** an active Link — it relies on the Link's session key for encryption (§3.1 link-derived form) and on the Link's bidirectional DATA channel for control traffic.

The complete reference is `RNS/Resource.py` (1367 lines in RNS 1.4.2); `RNS/Packet.py:74-79` defines the context constants. This section describes the wire-level invariants a clean-room implementation must respect; many implementation choices (window sizing heuristics, watchdog timers, EIFR computation) are private and listed only when their absence would cause an interop break.

### 10.1 When Resource runs

Three triggers in upstream:

1. **`LXMessage.send()` for `DIRECT` method with `representation == RESOURCE`.** Set automatically when the encrypted-form LXMF body exceeds `LINK_PACKET_MAX_CONTENT` (`LXMF/LXMessage.py:415-421`).
2. **NomadNet page request fulfillment** — a server returning a page whose body exceeds the link MTU.
3. **Direct file transfers** via `rncp` and similar utilities.

### 10.2 Initiator-side preparation

Given input data and an `RNS.Link` in `ACTIVE` state (`RNS/Resource.py:248-478`):

1. **Optional metadata prefix.** If the caller supplied a `metadata` dict, msgpack-pack it and prepend `length(3 bytes, big-endian uint24) || packed_metadata` to the body. The `has_metadata` (`x`) flag in the advertisement signals this. Receivers strip the prefix during reassembly (line 700-707).
2. **Optional bz2 compression.** If `auto_compress` is true and the data fits within `auto_compress_limit` (default 64 MiB), the body is bz2-compressed and the `compressed` (`c`) flag is set. If compression doesn't shrink the data, the uncompressed form is sent and `c` is cleared.
3. **Random hash prefix.** A 4-byte (`Resource.RANDOM_HASH_SIZE`) random hash is prepended to the (compressed-or-not) body — `Resource.py:401`/`408`, a fresh `RNS.Identity.get_random_hash()[:4]` call. This prefix is **not** the `r` field, and is **not** part of the `hash` / `expected_proof` input. It is a separate throwaway value that travels inside the encrypted blob; the receiver strips and discards it (§10.8 step 3). The advertisement's `r` field carries a *different* value — `self.random_hash`, generated by its own `get_random_hash()[:4]` call at `Resource.py:436` — which is the actual integrity-hash and hashmap salt.
4. **Link encryption.** The full `random_hash || (compressed?) data` blob is encrypted using `link.encrypt(...)` — i.e. the link-derived Token form (§3.1), no ephemeral_pub prefix. The `encrypted` (`e`) flag is set.
5. **Hash and proof material** (`Resource.py:440-443`). All three are computed over the **original uncompressed `plaintext`** — the caller's input, including any metadata prefix from step 1 (`Resource.py:261-267`) — *not* the compressed body, and *not* the random-prefixed wire blob from step 3:
   - `random_hash = RNS.Identity.get_random_hash()[:4]` — the value the advertisement's `r` field carries.
   - `hash = SHA256(plaintext || random_hash)` (32 bytes)
   - `truncated_hash = hash[:16]`
   - `expected_proof = SHA256(plaintext || hash)` (32 bytes) — what the receiver will eventually return in the RESOURCE_PRF packet.

   The 4-byte prefix from step 3 is **not** in any of these inputs. The receiver strips the prefix and bz2-decompresses *before* hashing (§10.8 steps 3-5), so the sender must hash the uncompressed, unprefixed `plaintext` for the two sides to agree. A receiver that includes the prefix, or hashes the compressed form, rejects every legitimate Resource as `CORRUPT`.
6. **Part split.** The encrypted body is sliced into parts of size `SDU = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE`. Each part becomes a packed `RNS.Packet(link, part_data, context=RESOURCE)`; the packed wire bytes are stored in `parts[i]` for later sending.
7. **Hashmap.** Each part is fingerprinted to `MAPHASH_LEN = 4 bytes`. The full hashmap is `b"".join(map_hashes)`. **Hash collisions within the COLLISION_GUARD_SIZE = 2 × WINDOW_MAX + HASHMAP_MAX_LEN window are detected at construction time** — if two parts hash to the same 4-byte map_hash within that window, the random hash is regenerated and the whole hashmap is recomputed. Without this guard, the receiver can't disambiguate which part it just received from a part-request that named a colliding map_hash.

After preparation: `total_parts = ceil(size / SDU)`; `total_size` includes metadata; `total_segments = ceil(total_size / MAX_EFFICIENT_SIZE)` where `MAX_EFFICIENT_SIZE = 1 MiB - 1 = 1_048_575`.

### 10.3 Wire packet contexts used during a Resource transfer

All of these are sent on the established Link and use the Link's session key for encryption (or are unencrypted PROOF-type, depending on context):

| Context | Direction | Type | Body |
|---|---|---|---|
| `RESOURCE_ADV (0x02)` | initiator → receiver | DATA | msgpack dict (§10.4) |
| `RESOURCE (0x01)` | initiator → receiver | DATA | one part of the encrypted body, raw |
| `RESOURCE_REQ (0x03)` | receiver → initiator | DATA | request bytes (§10.5) |
| `RESOURCE_HMU (0x04)` | initiator → receiver | DATA | hashmap continuation (§10.7) |
| `RESOURCE_PRF (0x05)` | receiver → initiator | PROOF | `resource_hash(32) || full_proof(32)` |
| `RESOURCE_ICL (0x06)` | initiator → receiver | DATA | resource_hash(32) — initiator cancel |
| `RESOURCE_RCL (0x07)` | receiver → initiator | DATA | resource_hash(32) — receiver reject/cancel |

### 10.4 RESOURCE_ADV — the advertisement

The first packet in the transfer. Body is `umsgpack.packb(dict)` with these keys (`RNS/Resource.py:1336-1358`):

| Key | Type | Meaning |
|---|---|---|
| `t` | int | **Transfer size** — encrypted byte length on the wire |
| `d` | int | **Data size** — original uncompressed plaintext byte length |
| `n` | int | **Number of parts** in this segment |
| `h` | bytes(32) | **Resource hash** — `SHA256(data || random_hash)` |
| `r` | bytes(4) | **Random hash** prefix |
| `o` | bytes(32) | **Original hash** of the first segment (= `h` if single-segment) |
| `i` | int | **Segment index** (1-based) |
| `l` | int | **Total segments** |
| `q` | bytes(?) or None | **Request id** if this Resource carries the response to a Link REQUEST |
| `f` | int | **Flags byte** (see below) |
| `m` | bytes | **Hashmap fragment** for THIS advertisement segment — up to `HASHMAP_MAX_LEN = ⌊(LINK_MDU - 134)/4⌋` 4-byte map_hashes |

The flags byte `f` packs six booleans (`Resource.py:1310, 1359-1364`):

```
bit 0 : e — encrypted
bit 1 : c — compressed
bit 2 : s — split (multi-segment)
bit 3 : u — is_request (this Resource is the body of a Link REQUEST)
bit 4 : p — is_response (this Resource is the body of a Link RESPONSE)
bit 5 : x — has_metadata
```

`HASHMAP_MAX_LEN` matters: the entire hashmap may not fit in one ADV. If `n > HASHMAP_MAX_LEN`, the receiver reconstructs subsequent map segments via RESOURCE_HMU packets after exhausting the first slice (§10.7).

The advertisement is sent once on `Resource.advertise()`; if no part requests arrive within the watchdog timeout, it is retransmitted up to `MAX_ADV_RETRIES = 4` times before the resource is cancelled (`Resource.py:573-590`).

> **Security: cap `t` and `d` at receive time.** `t` and `d` are the
> sender's claims about how big the resource will be. A misbehaving
> or hostile peer can advertise multi-gigabyte values that a naïve
> receiver will then try to allocate buffers for. Two attack shapes
> matter:
>
> 1. **Direct allocation bomb.** Receiver pre-allocates an output
>    buffer sized from `t` or `d` and OOMs before any chunk arrives.
> 2. **Decompression bomb (when `c = 1`).** A small (~tens of KB)
>    bz2 input legitimately expands to gigabytes. The chunk-count
>    cap from `HASHMAP_MAX_LEN` (§10.4) bounds raw on-wire chunks
>    but does NOT bound the post-decompression buffer.
>
> Implementations SHOULD enforce a per-application cap (a few MiB is
> reasonable for NomadNet pages and propagation `/get` blobs; file
> downloads MAY allow more if the receiver has the budget) and
> reject advertisements with `t` or `d` over the cap before
> responding with the first RESOURCE_REQ. When `c = 1`, the
> decompressor MUST also abort if the running output total exceeds
> the cap (defense in depth — a sender that lies about `d` would
> otherwise bypass the parse-time check). Reference: a receiver
> implementing `delivery_resource_advertised(resource)` returning
> `False` (§5.8.3 / §16.9) is the upstream-blessed way to refuse
> oversized advertisements.
>
> Upstream RNS adopted this cap in 1.1.9 after a CVE-class report:
> `Resource.assemble` uses `bz2.BZ2Decompressor.decompress(data,
> max_length=self.max_decompressed_size)` and rejects the resource
> if `decompressor.eof` is False after the bounded read
> (`RNS/Resource.py:686-691`). The Channel-mode counterpart is
> `Buffer.RawChannelReader` which caps each chunk at
> `RawChannelWriter.MAX_CHUNK_LEN` via the same `max_length` mechanism
> (`RNS/Buffer.py:95-97`). Clean-room implementations should mirror
> this — a `bz2.BZ2Decompressor.decompress(data, max_length=N)` plus
> `eof` check is the minimum. **Do not use the one-shot
> `bz2.decompress()` API for resource bodies** — it has no output
> bound and will allocate as much memory as the input legitimately
> expands to.
>
> Since RNS 1.3.9 upstream also enforces a hard parse-time bound on
> the advertisement itself: `ResourceAdvertisement.unpack` raises on
> `t > Resource.MAX_EFFICIENT_SIZE * 3` (= 3 × (1 MiB − 1) =
> 3,145,725 bytes; `RNS/Resource.py:1366`, `:116` in RNS 1.4.2), so
> the ADV is dropped before any allocation. A legitimate per-segment
> `t` never reaches this bound, because senders split anything larger
> than `MAX_EFFICIENT_SIZE` into separately-advertised segments.

### 10.5 RESOURCE_REQ — receiver requests parts

Sent by the receiver to ask for a window's worth of specific parts (`Resource.py:934-983`). Body layout:

```
hashmap_exhausted_flag(1)  || [last_map_hash(4) if exhausted]
|| resource_hash(32)
|| requested_map_hashes(N × 4 bytes)
```

Where:

- `hashmap_exhausted_flag` is `0x00 (HASHMAP_IS_NOT_EXHAUSTED)` if the receiver still has unrequested map_hashes from the most-recently-known hashmap segment, or `0xFF (HASHMAP_IS_EXHAUSTED)` if it has consumed all of them and needs the next hashmap segment.
- If `exhausted == 0xFF`, the request continues with the **last** map_hash the receiver knows from the current segment (4 bytes). The sender uses this to determine which segment of the hashmap to send back via RESOURCE_HMU.
- `resource_hash` is the 32-byte `h` from the advertisement.
- The trailing `requested_map_hashes` is a concatenation of `N` × 4-byte map_hashes the receiver wants delivered. `N` is at most `WINDOW` (initial 4, dynamically grown — see §10.10).

Receivers who already have the part for a requested map_hash don't issue requests for it; the request is constructed only from `parts[search_start:search_start+window]` where `parts[i] is None` (`Resource.py:944-960`).

### 10.6 RESOURCE part packets

For each map_hash in a RESOURCE_REQ, the sender locates the matching pre-packed part within `parts[receiver_min_consecutive_height : receiver_min_consecutive_height + COLLISION_GUARD_SIZE]` and emits it as a regular Link DATA packet with `context = RESOURCE (0x01)` (`Resource.py:1011-1023`). The body is just the part's encrypted data — no metadata, no sequence number. The receiver matches the inbound part to its hashmap by recomputing its 4-byte map_hash and inserting it into `parts[i]` at the position where `hashmap[i]` matches (`Resource.py:866-885`).

Two interop traps:

1. **Map_hashes are not guaranteed unique across the whole resource** — only within `COLLISION_GUARD_SIZE` of any sliding-window position. A receiver that searches the entire hashmap for a matching part-hash can mis-place a part if two distant parts collide. The reference receiver searches only `hashmap[consecutive_completed_height : consecutive_completed_height + window]`.
2. **Parts are link-encrypted but otherwise opaque** — the receiver has no way to validate a part beyond its 4-byte map_hash until the whole resource assembles and the SHA-256 over the reassembled data matches `h`.

> **Implementation gotcha: chunks are NOT individually encrypted —
> they are raw slices of an already-encrypted whole.** Per §10.2 step
> 4, the entire `random_hash || (compressed?) data` blob is link-
> encrypted ONCE, *then* split into MTU-sized parts at step 6. Each
> wire chunk is just `outerToken[i*sdu : (i+1)*sdu]` — a fragment
> with no Token-form header (no IV, no HMAC) of its own. Receivers
> MUST hand inbound chunk bytes directly to the hashmap match
> (`SHA-256(chunk || random_hash)[:4]`) without attempting per-chunk
> Token decrypt. The single decrypt step happens once over the
> concatenated assembly inside `assemble()` (§10.8), not per packet.
>
> A receiver that calls `link.decrypt(chunk)` on each inbound
> RESOURCE part will fail with HMAC verification errors on every
> chunk — each slice is missing the Token header bytes the
> decrypt expects. This is a common implementer mistake and the
> spec text "parts are link-encrypted" reads ambiguously enough
> that several clean-room ports have made it. Verbatim from
> `Resource.py:607-625`:
>
> ```python
> for i in range(0, hashmap_entries):
>     data = self.data[i*self.sdu : (i+1)*self.sdu]   # slice ciphertext
>     map_hash = self.get_map_hash(data)              # hash the SLICE
>     part = RNS.Packet(link, data, context=RNS.Packet.RESOURCE)
>     part.pack()
>     self.hashmap += part.map_hash
>     self.parts.append(part)
> ```
>
> The body of each RESOURCE packet is `data` here — a raw slice of
> the already-encrypted `self.data`. No re-encryption.

### 10.7 RESOURCE_HMU — hashmap update

When the sender receives a RESOURCE_REQ with `exhausted == 0xFF` and a `last_map_hash`, it locates the position of `last_map_hash` in its full hashmap, advances to the **next** `HASHMAP_MAX_LEN` window, and emits the hashmap continuation (`Resource.py:1033-1074` in RNS 1.4.2):

```
body = resource_hash(32) || umsgpack.packb([segment_index(int), hashmap_segment_bytes])
```

The segment_index is `part_index // HASHMAP_MAX_LEN`. The receiver applies this with `Resource.hashmap_update(segment, hashmap)` to extend its known hashmap and continues issuing RESOURCE_REQ for the new range.

If the part_index doesn't land on a `HASHMAP_MAX_LEN` boundary, the sender treats it as a sequencing error and cancels the resource (`Resource.py:1045-1048`).

> **HMU hardening (RNS ≥ 1.3.9).** The receiver ignores any
> RESOURCE_HMU that arrives while it is not actually waiting for one
> (`waiting_for_hmu` gate in `hashmap_update_packet`,
> `Resource.py:481`), and an HMU whose hashmap segment decodes to
> zero map-hashes cancels the transfer (`Resource.py:497-501`). The
> sender likewise cancels instead of emitting an empty hashmap
> continuation (`Resource.py:1058-1061`). Implementations should not
> rely on out-of-turn or empty HMUs being tolerated.

> **An exhausted RESOURCE_REQ MAY still carry parts — a conformant
> sender fulfils them *and* sends the RESOURCE_HMU.** When the
> `hashmap_exhausted_flag` is `0xFF`, the REQ body may still end with a
> non-empty `requested_map_hashes` trailer (§10.5). The sender MUST emit
> the requested part packets **and** the hashmap continuation; the two
> are independent. Serving the HMU is not a substitute for fulfilling
> the bundled part requests.
>
> In the RNS reference (`Resource.py:982-1071`, `request()` — verified
> against RNS 1.4.2, the current release), the part-fulfilment loop runs
> for every REQ regardless of the flag, and the `if wants_more_hashmap:`
> HMU branch runs afterward, in addition. The reference receiver
> (`request_next`, `Resource.py:931-981`) routinely produces this
> packet shape: as its window scan reaches the end of the known
> hashmap, it has already accumulated the still-outstanding part-hashes
> from the known region into `requested_hashes`, then sets the exhausted
> flag and stops — emitting
> `0xFF || last_map_hash(4) || resource_hash(32) || requested_map_hashes`.
>
> A receiver MAY keep part requests and hashmap pulls in separate REQ
> packets — emitting a **part-less** exhausted REQ
> (body `0xFF || last_map_hash(4) || resource_hash(32)`, no trailing
> map_hashes) purely to pull the continuation. This interoperates with
> every conformant sender. But it is a receiver-side simplification
> only: a sender MUST NOT assume peers do this, and MUST NOT skip part
> fulfilment for an exhausted REQ. A sender that does drops every
> bundled part silently — see `playbook.md` §7 (2026-05-19).

### 10.8 RESOURCE_PRF — final proof

When the receiver has assembled the full resource (`received_count == total_parts`), it runs `assemble()` (`Resource.py:672-726`):

1. Concatenate `parts[0..n]` to a single buffer.
2. `link.decrypt(...)` to plaintext.
3. Strip the 4-byte `random_hash` prefix — **discard, do NOT compare to advertisement.r** (see callout below).
4. If `compressed`: bz2-decompress.
5. Recompute `SHA256(plaintext || random_hash)` — over the prefix-stripped, decompressed body — and compare to `h`.
6. If match: peel off metadata if `x` is set, write `data` to the destination; status = `COMPLETE`.
7. If mismatch: status = `CORRUPT`; cancel.

> **Implementation gotcha: the leading 4 bytes are NOT
> `advertisement.r`.** Step 3 reads "strip the 4-byte random_hash
> prefix" — sender-side `Resource.py:401, 408` writes those bytes via
> `RNS.Identity.get_random_hash()[:4]`, a fresh random call. They
> are deliberately distinct from `self.random_hash` (the value
> the advertisement's `r` field carries — used only for the
> hashmap formula `SHA256(chunk || r)[:4]` and the integrity
> formula `SHA256(data || r)`). A receiver that does
> `assert prefix == advertisement.r` will reject every legitimate
> Resource as corrupt. Just strip and discard. Integrity is proven
> exclusively by step 5's `SHA256(plaintext || random_hash)`
> against `h` — that's the only check that matters; the prefix
> bytes are scaffolding.

On `COMPLETE`, the receiver emits the proof:

```
proof_data = resource_hash(32) || full_proof(32)
where full_proof = SHA256(plaintext || resource_hash)
```

sent as `RNS.Packet(link, proof_data, packet_type=PROOF, context=RESOURCE_PRF)` (`Resource.py:755-766`). The `full_proof` is exactly what the initiator pre-computed as `expected_proof` in §10.2 step 5 — it can validate the proof bytewise without re-running the SHA-256.

The initiator's `validate_proof` (`Resource.py:785-824`) checks `proof_data[32:] == self.expected_proof` and transitions status to `COMPLETE`. If the resource is multi-segment (`s == True`), the next segment's advertisement is sent immediately upon proof of the current segment.

### 10.9 RESOURCE_ICL / RESOURCE_RCL — cancellation

Either side can cancel; the body is just `resource_hash(32)`:

- **`RESOURCE_ICL (0x06)`** — initiator cancel. Sent when the initiator decides to abort (e.g. the user kills the upload, the link MTU shrinks below the resource's pre-packed parts, the watchdog gives up after `MAX_RETRIES = 16`).
- **`RESOURCE_RCL (0x07)`** — receiver reject / cancel. Sent on advertisement reject (`Resource.reject(adv_packet)`, `Resource.py:155-165` in RNS 1.4.2, e.g. resource too large per app callback) and — since RNS 1.3.9 — on any receiver-side abort while the link is still active (`Resource.cancel()` receiver branch, `Resource.py:1104-1110`). Before 1.3.9 only the reject path put RCL on the wire; a mid-transfer receiver abort was silent. Inbound RCL handling has existed on both sides throughout (`Link.py:1114`).

Either form transitions the resource to `FAILED`, releases the parts, and notifies the link's resource-concluded callback.

### 10.10 Sliding window and rate adaptation

The receiver controls request-pacing via a sliding window:

```
WINDOW          = 4    # initial outstanding requests
WINDOW_MIN      = 2
WINDOW_MAX_SLOW = 10   # default cap
WINDOW_MAX_FAST = 75   # cap once link is observed to be fast
WINDOW_MAX_VERY_SLOW = 4
WINDOW_FLEXIBILITY = 4
```

After each successful round (every requested part arrived), `window += 1` up to `window_max`; `window_min += 1` once `window - window_min > WINDOW_FLEXIBILITY - 1` (`Resource.py:902-906`). The window cap is promoted to `WINDOW_MAX_FAST` after `FAST_RATE_THRESHOLD` consecutive rounds at observed throughput > `RATE_FAST = 50 kbps / 8`, and demoted to `WINDOW_MAX_VERY_SLOW` after `VERY_SLOW_RATE_THRESHOLD = 2` rounds below `RATE_VERY_SLOW = 2 kbps / 8` (`Resource.py:917-927`). These are receiver-private — they're not negotiated, so two implementations with different rate-detection cutoffs interop fine but may emerge with different effective throughput on the same channel.

### 10.11 Multi-segment resources

For payloads larger than `MAX_EFFICIENT_SIZE = 1 MiB - 1`, the resource is split into multiple segments at `MAX_EFFICIENT_SIZE` boundaries (`Resource.py:299-314`). Each segment is its own Resource with its own RESOURCE_ADV; the `i` (segment_index) and `l` (total_segments) fields disambiguate. The `o` (original_hash) field carries the first segment's `h` so the receiver can correlate segments belonging to the same logical transfer.

The sender doesn't pre-prepare every segment up front — it builds segment N+1 in `__prepare_next_segment` while segment N is still being delivered, and sends segment N+1's advertisement only after it has received the proof for segment N (`Resource.py:768-783, 822-824`). This caps memory usage; a 100 MiB transfer doesn't materialize 100 segments simultaneously.

The 3-byte big-endian uint24 metadata length encoding (§10.2 step 1) is what limits per-resource metadata to `METADATA_MAX_SIZE = 16 MiB - 1`.

### 10.12 Compression and encryption layering

Encryption layering is **outermost** — the wire bytes look like:

```
wire_blob           = prefix(4) || maybe_compressed       # the body that gets encrypted
prefix              = fresh get_random_hash()[:4]         # NOT `r`; receiver strips & discards
maybe_compressed    = compressed_body iff `c` flag, else uncompressed
parts[i]            = link.encrypt(wire_blob)[i*SDU : (i+1)*SDU]   # encrypt whole, then slice

hash                = SHA256(uncompressed_body || random_hash)    # integrity; random_hash = adv `r`
```

Critically, **the link encryption is applied to the WHOLE concatenated data first, then sliced into parts** — not to each part individually. This means part boundaries don't align with cipher block boundaries; a missing part can't be decrypted in isolation. The receiver must accumulate all parts before calling `link.decrypt()` (`Resource.py:676-679`).

This also means swapping in a new link session key mid-transfer would break decryption — the encryption happened with the link's key as it was when the resource was constructed.

### 10.13 Source map for §10

| File | What it pins down |
|---|---|
| `RNS/Resource.py:43-165` | Class header, constants, state machine values, `reject` |
| `RNS/Resource.py:167-246` | `accept` — receiver-side advertisement acceptance |
| `RNS/Resource.py:248-477` | `Resource.__init__` — preparation, hashmap construction, collision guard |
| `RNS/Resource.py:508-562` | `advertise`, `__advertise_job` |
| `RNS/Resource.py:564-674` | `watchdog_job` / `__watchdog_job` — retry/timeout state machine, advertisement retransmit |
| `RNS/Resource.py:676-754` | `assemble` — receiver reassembly, decrypt, decompress, hash-match |
| `RNS/Resource.py:756-831` | `prove` and `validate_proof` |
| `RNS/Resource.py:833-934` | `receive_part` — receiver-side part insertion + window adjust |
| `RNS/Resource.py:936-986` | `request_next` — receiver-side RESOURCE_REQ construction |
| `RNS/Resource.py:988-1082` | `request` — initiator-side fulfillment + RESOURCE_HMU emission |
| `RNS/Resource.py:1084-1117` | `cancel` — ICL/RCL emission on abort |
| `RNS/Resource.py:1247-1367` | `ResourceAdvertisement` — pack/unpack of the ADV msgpack dict |
| `RNS/Packet.py:72-79` | RESOURCE_* context constants |

---

## 11. REQUEST/RESPONSE protocol (NomadNet pages, propagation `/get`, custom RPC)

A generic over-Link RPC mechanism. NomadNet uses it for page fetches; LXMF propagation uses it for offline-message retrieval; any application can register handlers for arbitrary paths. There is no separate "NomadNet wire format" — NomadNet is just one consumer of this protocol.

This section specifies the wire bytes; the application-layer paths (e.g. NomadNet's `/page/index.mu`) are caller-defined.

### 11.1 Wire form — REQUEST (initiator → server)

`RNS/Link.py::request` line 478-527. After an active Link is established (§6), the initiator builds:

```python
request_path_hash = SHA256(path.encode("utf-8"))[:16]
unpacked_request  = [time.time(), request_path_hash, data]
packed_request    = umsgpack.packb(unpacked_request)
```

Then dispatches based on size:

| `len(packed_request)` | Wire form |
|---|---|
| `≤ link.mdu` | One Link DATA packet, `context = REQUEST (0x09)`, body = `packed_request` |
| `> link.mdu`  | Resource transfer (§10), with `request_id = SHA256(packed_request)[:16]`, `is_response = False` (sets `u = True` in the Resource advertisement flags per §10.4) |

The msgpack array layout:

```
[0]  timestamp            float (seconds since unix epoch, requester's clock)
[1]  request_path_hash    bytes(16) — SHA-256 of the requested path string, truncated
[2]  data                 application-defined value, encoded directly into the
                          outer msgpack list — NOT a pre-msgpacked byte blob
```

> **Implementation gotcha: element [2] is encoded once, not twice.**
> `data` is whatever the application wants to send: `None` (msgpack nil)
> for plain GETs, a `dict` for NomadNet form posts (§11.6), a `list` for
> LXMF propagation `/get` rounds (§11.6), or `bytes` for opaque
> application blobs. **The whole `[time, path_hash, data]` list is
> msgpacked exactly once.** Element [2] is NOT a pre-encoded byte blob
> wrapped as msgpack `bin` — that's a common implementer mistake (see
> below) and it silently corrupts every form submission and every
> propagation poll because server-side handlers do
> `isinstance(data, dict)` / `isinstance(data, list)` and the `bin`
> form is `bytes`, falling through to the no-op branch.
>
> Concrete example for a NomadNet form post `field_message=hello`:
>
> ```python
> data = {"field_message": "hello"}      # native Python dict
> envelope = [time.time(), path_hash, data]
> packed = umsgpack.packb(envelope)      # ONE pack call
> # → on the wire, element [2] decodes back to a {} map, NOT to bytes
> ```
>
> Pre-pack callers (`umsgpack.packb(data)` then passing the bytes as
> element [2]) produce a wire envelope where decode yields `bytes` for
> [2] — looks structurally similar but is semantically a different
> type, and every NomadNet `Node.py:109` / LXMF `LXMRouter.__get_handler`
> drops the request silently with no error response.

For single-packet REQUESTs, `request_id = SHA-256(packet.get_hashable_part())[:16]` — i.e. the 16-byte truncation of the **packet hash**, computed over the on-the-wire bytes (low nibble of flags || `raw[2:]` for HEADER_1 / `raw[18:]` for HEADER_2). NOT a hash of the inner plaintext or of the msgpack-encoded `packed_request` blob. The server side at `Link.handle_request:1286` literally calls `packet.getTruncatedHash()`. Both sides MUST hash the same bytes to match. For Resource REQUESTs the request_id is carried explicitly in the advertisement's `q` field (§10.4) and the initiator MUST set it to the truncated `SHA-256(packed_request)[:16]` of the inner plaintext per `Resource.py::__init__` line 478 (Resource path uses the plaintext-hash form because there is no single packet to hash). The receiver uses this id to correlate the inbound RESPONSE with this REQUEST.

### 11.2 Wire form — RESPONSE (server → initiator)

`RNS/Link.py::handle_request` line 853-904. The server's response generator returns a value, and the dispatcher picks the wire form by size:

```python
packed_response = umsgpack.packb([request_id, response])

if len(packed_response) <= link.mdu:
    RNS.Packet(link, packed_response, DATA, context = RESPONSE).send()
else:
    response_resource = RNS.Resource(packed_response, link,
                                     request_id=request_id, is_response=True,
                                     auto_compress=auto_compress)
```

| Wire form | Trigger |
|---|---|
| Link DATA packet, `context = RESPONSE (0x0A)`, body = `umsgpack([request_id, response])` | response fits in `link.mdu` |
| Resource transfer, `request_id` field set, `is_response = True` (advertisement flag `p`) | response too large |

The `request_id` in element [0] of the response msgpack lets the initiator match the response to the original outbound REQUEST in `Link.pending_requests` even when several requests are in flight on the same Link (`Link.handle_response` line 906-925).

> **Security: initiators MUST verify element [0].** The request_id
> check isn't decorative — without it, a misbehaving or compromised
> transit relay can replay a stale RESPONSE from a prior request and
> the initiator accepts it as the answer to whatever's currently
> pending. An implementation that drives only one in-flight request
> per link at a time is "lucky" today (the wrong-id RESPONSE just
> happens to carry sane bytes for the application to display), but
> as soon as it adds link reuse, partials, or any kind of pipelining
> the bug becomes a silent confused-deputy.
>
> **Compute `expected_id` correctly.** Server-side
> `Link.handle_request:1286` is:
>
> ```python
> request_id = packet.getTruncatedHash()
> ```
>
> i.e. **`SHA-256(packet.get_hashable_part())[:16]`** where
> `get_hashable_part()` (`Packet.py:348-353`) is:
>
> ```
> hashable = (raw[0] & 0x0F) || raw[2:]              # HEADER_1
> hashable = (raw[0] & 0x0F) || raw[18:]             # HEADER_2 (skips transport_id slot)
> ```
>
> NOT a hash of the inner plaintext. Compute the same on the
> initiator from your outbound REQUEST packet's wire bytes; on every
> inbound RESPONSE, drop the packet (and log) if `decoded[0]`
> doesn't match. Many clean-room implementations have read this
> section's prior wording (\"16-byte truncated hash of
> `packed_request`\") as \"hash the inner plaintext bytes\" and
> produced a formula that never matches what the server sent —
> every RESPONSE gets dropped, every page-fetch and `/get` round
> times out silently. The hashing is over the on-the-wire packet
> bytes, not the encrypted-then-decrypted payload.

#### File responses

If the server's response generator returns a `(file_handle, metadata)` tuple, the response goes out as a Resource carrying the file's bytes with optional msgpack metadata in the Resource advertisement's `metadata` slot — `RNS/Link.py:888-895`:

```python
if type(response) == tuple and isinstance(response[0], io.BufferedReader):
    file_handle = response[0]
    metadata    = response[1] if len(response) > 1 else None
    response_resource = RNS.Resource(file_handle, link,
                                     metadata=metadata, request_id=request_id,
                                     is_response=True, auto_compress=auto_compress)
```

This is how NomadNet ships large pages with attached MIME-type / size hints — the file goes through the §10 Resource pipeline; the metadata hits the advertisement's `m` slot reserved for the resource hashmap **but** also gets a separate metadata-prefix slot per §10.2 step 1 (the 3-byte length-prefixed msgpack-packed metadata blob inserted before the random_hash).

### 11.3 Path hash collision avoidance

`request_path_hash` is the 16-byte truncation of `SHA256(path)` — collision space is 2^128, effectively no collisions in practice. The server's `request_handlers` dict is keyed by this hash:

```python
# RNS/Destination.py::register_request_handler
request_path_hash = SHA256(path.encode("utf-8"))[:16]
self.request_handlers[request_path_hash] = (path, response_generator, allow, allowed_list, auto_compress)
```

A server registers a path string; clients hash the path and look it up. The path string itself is not on the wire — only its hash. This means the server can publish opaque path tokens that resist enumeration: a client must already know the path string to fetch the resource at it. NomadNet uses human-readable paths like `/page/index.mu` because the clients (Sideband, the NomadNet client) need them to be discoverable; a private file-server use case can use random tokens for security-by-obscurity.

### 11.4 Authorization (`allow` modes)

Registered via `Destination.register_request_handler(path, response_generator, allow=...)`:

| Mode | Constant | Effect |
|---|---|---|
| `ALLOW_NONE` | `0x00` | Reject every request (handler is a stub for testing). |
| `ALLOW_LIST` | `0x01` | Accept iff the requester has identified themselves on the link (via `link.identify(identity)`) AND their identity_hash is in `allowed_list`. |
| `ALLOW_ALL` | `0x02` | Accept any request that arrives on this Link, regardless of caller identity. |

`Link.identify(identity)` runs `LINKIDENTIFY (context = 0xFB)` packets; this is how the requester proves which long-term identity is making the request without re-running a fresh Link handshake. Most public NomadNet pages use `ALLOW_ALL`; private pages and propagation-node operator commands use `ALLOW_LIST`.

### 11.5 RequestReceipt — initiator-side state machine

`RNS/Link.py:1306-1501`. When `Link.request()` returns a `RequestReceipt`, the initiator can attach:

- `response_callback(receipt)` — fires when the response has fully arrived (single packet OR resource concluded).
- `failed_callback(receipt)` — fires on timeout or link teardown.
- `progress_callback(receipt)` — fires each time more bytes arrive (for Resource responses; reports `receipt.progress` 0.0..1.0).

Default timeout is `link.rtt × link.traffic_timeout_factor + Resource.RESPONSE_MAX_GRACE_TIME × 1.125` — typically a few seconds plus a generous response-side grace. Caller can override via the `timeout=` kwarg.

### 11.6 NomadNet specifics (informational, not normative)

<details>
<summary>Click to expand — NomadNet-layer conventions on top of §11 (form data env vars, link target syntax, micron page headers, <code>/file/</code> downloads, ALLOW_LIST, partials). Skip if you're not implementing a NomadNet client; the §11 wire form is the protocol layer.</summary>

NomadNet pages are served over this protocol with these conventions. Source-of-truth for all of these is upstream `markqvist/NomadNet`: `nomadnet/Node.py` (server) and `nomadnet/ui/textui/Browser.py` (client).

#### 11.6.1 Paths and the `nomadnetwork.node` aspect

- Server: hosts a destination at `nomadnetwork`/`node` aspects (`name_hash = 213e6311bcec54ab4fde`). Pages are registered as `register_request_handler(path="/page/<name>.mu", ...)`.
- Client: default path is `/page/index.mu` (`Browser.py:67` `DEFAULT_PATH`).
- Path format: `/page/<name>.mu` for micron pages, `/file/<name>` for static file downloads (§11.6.5).
- Path hash on the wire is the §11.1 `SHA-256(path)[:16]` truncation — `/page/index.mu` and `/page/help.mu` are distinct request_handler keys.

#### 11.6.2 Form data and env-var convention

When a client tap on a micron link with form fields fires a REQUEST, element [2] of the envelope is a msgpack `dict` (NOT pre-msgpacked bytes — see §11.1). Two key prefixes are conventional and special-cased server-side:

| Prefix | Source | Server treatment |
|---|---|---|
| `field_<name>` | Form-input values typed by the user | Exported as env var `field_<name>=<value>` to the page's executable handler |
| `var_<name>`   | URL-query-style parameters embedded in the link itself | Exported as env var `var_<name>=<value>` |

`Node.py:109-111` (upstream master, fetched 2026-05-04):

```python
if data != None and isinstance(data, dict):
    for e in data:
        if isinstance(e, str) and (e.startswith("field_") or e.startswith("var_")):
            env_map[e] = data[e]
```

The `field_` vs `var_` distinction is purely cosmetic on the wire (both become env vars), but in micron syntax they have separate origins:

- **Form fields** (`field_<name>`) come from `<flags|name`value>` widgets that render as text inputs / checkboxes / radios. The Browser collects current widget state into a dict at submit time.
- **URL parameters** (`var_<name>`) come from `key=value` entries in the third backtick component of a link: `` `[label`/page/foo.mu`username=alice|active=true|message] `` produces `{"var_username": "alice", "var_active": "true", ...}` PLUS `field_message` from a widget named `message` (`Browser.py:198-205`). Entries with `=` are var-params; entries without are field-widget names whose current values get included.

##### Checkbox semantics (Browser.py:226-241)

For checkboxes specifically:

- **Unchecked**: the field key is **omitted from the dict entirely** (NOT sent as empty string).
- **Multi-select** (multiple checkboxes sharing the same field name): values are comma-joined (`{"field_topics": "weather,radio"}`).

Implementations that always send `{"field_<name>": ""}` for unchecked boxes will break server-side handlers that test `if "field_subscribe" in env: ...`.

#### 11.6.3 Link target syntax (parsed by `Browser.py` `expand_shorthands` + `link_request`)

A micron link's `target` string (the second component of `[label`target]` or third of `[label`target`fields]`) is one of:

| Form | Meaning | Browser.py ref |
|---|---|---|
| `/path/to/page.mu` | Same-node nav: load `path` on the currently-selected destination. | implicit |
| `<32hex>` (bare 16-byte truncated identity hash, hex-encoded) | Cross-node nav to `nomadnetwork.node` at that hash, default path `/page/index.mu`. | 255-259 |
| `<32hex>:/page/x.mu` | Cross-node nav with explicit path. | 255-259 |
| `nnn@<32hex>[:/path]` | Same as bare-hash form; `nnn` is a shorthand for `nomadnetwork.node`. | 184-189 |
| `lxmf@<32hex>` / `lxmf.delivery@<32hex>` | Open a conversation in the LXMF (messaging) layer, NOT a page fetch. | 184-189, 266-322 |

`expand_shorthands` (lines 184-189):

```python
def expand_shorthands(self, destination_type):
    if destination_type == "nnn":   return "nomadnetwork.node"
    elif destination_type == "lxmf": return "lxmf.delivery"
    else: return destination_type
```

Implementations should normalize hash hex to lower case before keying any cache / repo lookup, and reject inputs with embedded separators (`dead:beef:…`) — the wire form is plain bytes, accepting forgiving variants creates aliases for the same destination and risks cache-poisoning.

#### 11.6.4 Page-level header conventions

A `.mu` page MAY begin with one or more single-line headers prefixed `#!`. These are stripped by `Browser.py` before micron rendering and are NOT part of the page body:

| Header | Effect | Ref |
|---|---|---|
| `#!c=<seconds>` | Cache-TTL hint. `0` = "do not cache." Default cache is 12 h. | Browser.py:1315-1335 |
| `#!bg=<3hex or 6hex>` | Page-wide background color. | Browser.py:1282-1302 |
| `#!fg=<3hex or 6hex>` | Page-wide foreground color (overrides theme default). | Browser.py:1282-1302 |

The `#!c=N` header is widely used; the color headers are rare. A client that doesn't honor any of them still renders pages correctly.

#### 11.6.5 File downloads (`/file/...`)

Pages whose path starts with `/file/` are static downloads, not micron content. The server's response generator returns:

```python
return [open(file_path, "rb"), {"name": file_name.encode("utf-8")}]
```

— a `(file_handle, metadata_dict)` pair. The transport-layer file response shape per §11.2 §"File responses": the file bytes go through the §10 Resource pipeline, AND the metadata is also embedded as a length-prefixed msgpack blob in the Resource advertisement's metadata-prefix slot (§10.2 step 1). Clients receive `[filename_bytes, file_data_bytes]` after Resource assembly (Browser.py:1437-1441).

A client that hasn't implemented file downloads can detect `/file/` paths and either show a "downloads not supported" message or just discard the response.

#### 11.6.6 Authorization: `ALLOW_ALL` vs `ALLOW_LIST`

Pages are registered with one of three allow modes (`Destination.py:74-76`):

- `ALLOW_ALL` — anyone with a Link can fetch. Used for public NomadNet pages, the propagation node's `/get`, etc.
- `ALLOW_LIST` — caller's identity hash must appear in the page's `.allowed` file. Server checks `remote_identity.hash` against the list at request time (`Node.py:152-154`).
- `ALLOW_NONE` — registered handlers that exist but reject all requests (rare; debug only).

For `ALLOW_LIST` the client MUST call `link.identify(identity)` immediately after the link transitions to ACTIVE and BEFORE issuing the REQUEST. This sends a `LINKIDENTIFY (context = 0xFB)` packet whose 128-byte payload is `public_key(64) || signature(64)`, with the signature computed over `link_id || public_key` — proving the long-term identity hash to the responder. The wire format is specified in §6.7.6. Without it, `remote_identity` is `None` server-side and every `ALLOW_LIST` page returns `DEFAULT_NOTALLOWED`. See `Browser.py:1245-1250` for the upstream call site:

```python
def link_established(self, link):
    if self.app.directory.should_identify_on_connect(self.destination_hash):
        self.link.identify(self.app.identity)
```

> **Privacy note for client implementers.** Calling `link.identify` on
> *every* link reveals the user's long-term identity hash to any node
> they browse — including pages on hostile public hubs. Implementations
> SHOULD make `identify` opt-in per destination (or per session), only
> firing it when the user has affirmatively decided to authenticate.
> Anonymous browsing of `ALLOW_ALL` pages should not pin identity.

#### 11.6.7 Partial pages (server-side includes)

A micron page may embed `` `{<path>[`<refresh_seconds>[`<fields>]]} `` placeholders. The Browser tracks each placeholder, opens / reuses a Link to the partial's destination, fetches `<path>` as a sub-REQUEST, and substitutes the response bytes into the rendered output. If a `<refresh>` is set, the partial is re-fetched periodically.

Implementation reference: `Browser.py:493-606` (`__load_partial`, `start_partial_updater`). Partials are how live "chat tail" / "status" panels work on real NomadNet community pages. A client without partial support sees the literal placeholder text and the page renders as a static snapshot.

#### 11.6.8 Source map (NomadNet ↔ wire)

| Concept | Upstream Python file:line |
|---|---|
| Default path | `nomadnet/ui/textui/Browser.py:67` |
| Form-field collection | `Browser.py:198-241` |
| `field_` / `var_` env-var mapping | `nomadnet/Node.py:109-111` |
| Shorthand expansion (`nnn`/`lxmf`) | `Browser.py:184-189` |
| Cross-node link routing | `Browser.py:248-322` |
| Identify-on-connect | `Browser.py:1245-1250` |
| Cache-TTL header `#!c=N` | `Browser.py:1315-1335` |
| Color headers `#!bg=` / `#!fg=` | `Browser.py:1282-1302` |
| `/file/...` download dispatch | `Browser.py:781-785, 1420-1462` + `Node.py:128-141` |
| Partial placeholders | `Browser.py:493-606` |
| Allow modes / `ALLOW_LIST` enforcement | `Node.py:152-154` |

None of these are wire-spec — they're caller conventions layered on top of §11. A Reticulum client that can't render micron markup or doesn't implement the form/cache/partial conventions can still fetch pages and display the raw bytes; the protocol layer doesn't care about content.

</details>

### 11.7 Source map

| File | What |
|---|---|
| `RNS/Link.py:478-527` | `Link.request()` — initiator-side packing and dispatch by size |
| `RNS/Link.py:853-904` | `Link.handle_request()` — server-side path lookup + auth + response dispatch |
| `RNS/Link.py:906-925` | `Link.handle_response()` — initiator-side response correlation |
| `RNS/Link.py:1306-1501` | `RequestReceipt` — callback machinery |
| `RNS/Destination.py::register_request_handler` | Server-side handler registration |
| `RNS/Destination.py:74-76` | `ALLOW_NONE/ALLOW_LIST/ALLOW_ALL` constants |
| `RNS/Packet.py:81-82` | `REQUEST = 0x09`, `RESPONSE = 0x0A` context constants |

---

## 12. Transport-relay behaviour

Everything in §1-§11 applies to both leaf clients and transport-mode nodes. This section covers what additionally runs on a node configured with `enable_transport = Yes` in the `[reticulum]` config — i.e. a node whose role is to forward traffic for others. Reticulum's relay is host-routed (no broadcast flooding except for path-discovery), keyed by the `path_table` populated from announces.

A leaf client can ignore §12 entirely. Implementations that target the rnsd-replacement or repeater use case need every sub-section.

### 12.1 The `transport_enabled` toggle

`Reticulum.transport_enabled()` returns the value of the `enable_transport` config option (default `False`). Setting it to `True`:

- Allows the node to populate `path_table`, `announce_table`, `link_table`, `reverse_table`, and `tunnels` for non-local destinations (a leaf only populates path entries it personally needs).
- Enables the §12.2 DATA forwarding branches in `Transport.inbound`.
- Enables the §12.3 ANNOUNCE rebroadcast branch.
- Enables `Transport.identity` — the transport node's own identity, used for `transport_id` insertion in HEADER_2 packets (§2.3) and as the `requesting_transport_instance` field in path requests (§7.1).

A clean-room implementation testing forwarding without operating as a real transport node SHOULD respect the same flag: ignoring the toggle and unconditionally forwarding turns every implementation into a network-flooding hazard.

### 12.2 DATA forwarding rules

For an inbound DATA packet (`packet_type == DATA`, `destination_type` not LINK) where:

- `packet.transport_id == Transport.identity.hash` (the originator picked us as the next hop), AND
- `packet.destination_hash` is in `Transport.path_table`,

the relay rewrites the wire bytes according to `path_table[dest][HOPS]` and re-transmits on `path_table[dest][RVCD_IF]`. From `RNS/Transport.py:1500-1580`, three cases by `remaining_hops`:

#### 12.2.1 `remaining_hops > 1` — forward as HEADER_2

Increment hops (already done by `Transport.inbound` line 1395), replace the transport_id with the next-hop transport_id from the path table, keep the rest of the packet:

```
new_raw = packet.raw[0:1]                        # flags byte unchanged
new_raw += struct.pack("!B", packet.hops)        # incremented hops byte
new_raw += next_hop                              # 16B transport_id (new next hop)
new_raw += packet.raw[18:]                       # original dest_hash + ctx + body
```

The flags byte high nibble is unchanged — the packet stays HEADER_2 with the TRANSPORT bit set. Final wire form is `flags(1) || hops+1(1) || new_transport_id(16) || dest_hash(16) || ctx(1) || body`.

#### 12.2.2 `remaining_hops == 1` — strip transport headers, forward as HEADER_1 broadcast

The destination is one hop away on the next-hop interface; no further transport_id is needed. Convert to HEADER_1 with BROADCAST transport type:

```
new_flags = (HEADER_1 << 6) | (BROADCAST << 4) | (packet.flags & 0x0F)
new_raw = struct.pack("!B", new_flags)
new_raw += struct.pack("!B", packet.hops)
new_raw += packet.raw[18:]                       # original dest_hash + ctx + body (transport_id stripped)
```

This is the inverse of the §2.3 originator HEADER_1→HEADER_2 conversion: the relay strips the transport_id when the packet has reached its last hop.

#### 12.2.3 `remaining_hops == 0` — local destination, just bump hops

The destination is registered on the relay itself (it's both our path-table next-hop AND a local destination). Just increment hops and pass through unchanged for local processing — the standard `Destination.receive` path takes over from there.

#### 12.2.4 LINKREQUEST forwarding extras

When the forwarded packet is a `LINKREQUEST`, the relay also writes a `link_table` entry keyed by the link_id (computed via §6.3's `link_id_from_lr_packet`). Entry contents (`Transport.py:1556-1565`):

```
[ now,                            # 0  IDX_LT_TIMESTAMP
  next_hop,                       # 1  IDX_LT_NH_ID — next-hop transport_id
  outbound_interface,             # 2  IDX_LT_NH_IF
  remaining_hops,                 # 3  IDX_LT_REM_HOPS
  packet.receiving_interface,     # 4  IDX_LT_RCVD_IF
  packet.hops,                    # 5  IDX_LT_TAKEN_HOPS
  packet.destination_hash,        # 6  IDX_LT_DSTHASH
  False,                          # 7  IDX_LT_VALIDATED
  proof_timeout ]                 # 8  IDX_LT_PROOF_TMO
```

This entry is what lets the relay forward the eventual LRPROOF back to the initiator on the reverse path (§12.5) and forward subsequent Link DATA in both directions.

The relay also performs the §6.6 MTU clamp at this point: if the LINKREQUEST carries signalling and the next-hop interface's HW_MTU is smaller than the requested value, the signalling bytes in `new_raw` are rewritten in place with the clamped MTU before transmission.

#### 12.2.5 Non-LINKREQUEST DATA — reverse_table entry

For any other forwarded DATA (the much-more-common opportunistic LXMF case), the relay writes a `reverse_table` entry keyed by `packet.getTruncatedHash()` (`Transport.py:1570-1574`):

```
[ packet.receiving_interface,    # 0  IDX_RT_RCVD_IF — interface to send PROOF back through
  outbound_interface,            # 1  IDX_RT_OUTB_IF — interface forward was sent on
  time.time() ]                  # 2  IDX_RT_TIMESTAMP
```

The reverse_table is what lets the eventual PROOF receipt (§6.5) trace its way back to the originator without consulting the path_table again — see §12.5.

### 12.3 ANNOUNCE rebroadcasting

When an inbound ANNOUNCE validates (per §4.5) AND the destination is non-local AND `transport_enabled OR is_from_local_client`, the relay queues a rebroadcast. From `Transport.py:1930-1989`:

```python
if (Reticulum.transport_enabled() or is_from_local_client) and packet.context != PATH_RESPONSE:
    if not rate_blocked:
        Transport.announce_table[packet.destination_hash] = [
            now, retransmit_timeout, retries,
            received_from, announce_hops, packet,
            local_rebroadcasts, block_rebroadcasts, attached_interface,
        ]
```

The `announce_table` entry queues a delayed retransmit; the actual emission happens in the periodic `Transport.jobs` cycle which scans the table for entries whose `retransmit_timeout` has elapsed and fires them on each suitable interface.

#### 12.3.1 Announce cap (`ANNOUNCE_CAP`)

`Reticulum.ANNOUNCE_CAP = 2.0` (default 2% of airtime, configurable via `[reticulum] announce_cap`). Each interface tracks its outbound announce airtime and when the rolling-window utilization exceeds the cap, further announces are queued in `interface.announce_queue` rather than transmitted immediately. `process_announce_queue` (`RNS/Interfaces/Interface.py:321-357`) drains the queue at a rate the cap permits, picking the lowest-hop-count entry first.

The cap is per-interface, not global — a relay with multiple interfaces budgets each one independently, which lets a fast TCP backbone interface announce freely while the same node throttles announces on a slow LoRa interface. Without per-interface caps, a single high-rate interface would starve every other.

#### 12.3.2 `random_blob` replay defence

§4.5 step 6.3 already documents this from the receiver's perspective; for the rebroadcast logic, the relay only queues an announce if the new `random_blob` (the 10-byte `random_hash` field, treated as an opaque blob for routing purposes) is **not** already in the cached `random_blobs` list for this destination. The list is capped at `Transport.MAX_RANDOM_BLOBS` (default 32) entries, sliding-window. This prevents an announce from looping through a multi-relay topology because each relay only forwards each unique blob once.

#### 12.3.3 Path-response announces don't rebroadcast

`packet.context == PATH_RESPONSE` short-circuits the rebroadcast branch (line 1945). Path-response announces travel back along the reverse path from the responder to the requester (see §7.2 and `flows/path-discovery.md`), and the relay's job is to forward them on a single specific interface (`attached_interface`), not re-broadcast to the whole mesh. Mishandling this would multiply path-response traffic by the relay fanout.

### 12.4 Path table management

`Transport.path_table[destination_hash]` entry shape (`Transport.py:3668-3674`):

```
[ timestamp,                # 0  IDX_PT_TIMESTAMP — when last refreshed
  next_hop,                 # 1  IDX_PT_NEXT_HOP — 16B transport_id of next hop
  hops,                     # 2  IDX_PT_HOPS — distance to destination
  expires,                  # 3  IDX_PT_EXPIRES — unix-seconds eviction time
  random_blobs,             # 4  IDX_PT_RANDBLOBS — sliding window of recent blobs
  receiving_interface,      # 5  IDX_PT_RVCD_IF — interface to forward on
  packet ]                  # 6  IDX_PT_PACKET — cached announce packet for path-? response
```

#### 12.4.1 TTLs

Three different expiry constants based on the `attached_interface.mode`:

| Mode | TTL constant | Default seconds | Used for |
|---|---|---|---|
| `MODE_ACCESS_POINT` | `Transport.AP_PATH_TIME` | 1 hour | Hub-and-spoke topologies (TCP servers, BLE gateways) |
| `MODE_ROAMING` | `Transport.ROAMING_PATH_TIME` | 4 hours | Mobile devices that disappear and reappear |
| (default) | `Transport.PATHFINDER_E` | 30 days | Stable backbone interfaces |

The wide spread of defaults reflects expected churn rates: AP-mode interfaces have many short-lived clients; roaming devices come and go; backbone TCP relays are essentially permanent.

#### 12.4.2 Eviction

`Transport.jobs` runs a `stale_paths` accumulator that walks `path_table` and pops entries whose `expires` timestamp has passed (`Transport.py:780-801`). Eviction is silent — no notification to the application; the next outbound message to the destination just re-discovers it via `request_path` per §7.1.

A relay also evicts path entries whose underlying interface has been removed (`receiving_interface not in Transport.interfaces`). This handles the case where a TCP client disconnects.

#### 12.4.3 Persistence

If `[reticulum] persist_paths = Yes`, the path_table is serialized to `{storagepath}/paths` (a pickled dict in upstream RNS) so it survives restarts. The repeater repo's `pre_build.py` adds a "skip redundant path writes" patch to avoid hammering the on-board flash on nRF52 — for clean-room implementations, the persistence cadence is implementation-private.

### 12.5 Reverse-table link transport

Once a Link's LINKREQUEST has been forwarded by a relay (§12.2.4 wrote the `link_table` entry), every subsequent Link packet — DATA, KEEPALIVE, PROOF, LINKCLOSE — must be forwarded by the same relay in the appropriate direction. `Transport.inbound` uses `link_table` and `reverse_table` for this:

#### 12.5.1 LRPROOF forwarding

When an LRPROOF arrives whose `dest_hash` (= link_id) is in the relay's `link_table` AND the proof arrives on the next-hop interface (`packet.receiving_interface == link_entry[IDX_LT_NH_IF]`), the relay validates the signature against the destination's known long-term public key (recalled via `Identity.recall(link_entry[DSTHASH])`) and forwards on the receive interface (`Transport.py:2110-2145`):

```python
new_raw = packet.raw[0:1] + struct.pack("!B", packet.hops) + packet.raw[2:]
Transport.transmit(link_entry[IDX_LT_RCVD_IF], new_raw)
link_table[packet.destination_hash][IDX_LT_VALIDATED] = True
```

After validation, the link_table entry is marked `validated`, and from now on the relay forwards Link DATA in both directions transparently.

#### 12.5.2 Link DATA forwarding

For a `DATA` packet with `destination_type == LINK` whose `dest_hash` is in `link_table`, the relay forwards on the appropriate direction's interface. The link_table entry remembers both sides via `IDX_LT_NH_IF` (toward initiator end) and `IDX_LT_RCVD_IF` (toward responder end); the relay picks based on which interface the inbound packet arrived on.

Unlike the path_table forwarding in §12.2 — which strips `transport_id` (`HEADER_2` → `HEADER_1`) at the last hop — link_table forwarding does NOT touch the header. The relay bumps `hops` and emits `packet.raw[0:1] + struct.pack("!B", packet.hops) + packet.raw[2:]` (`Transport.py:1618-1620`). Whatever header bytes the initiator emitted reach the destination verbatim. This is why the originator's wire conventions for post-handshake link DATA are constrained — see §6.4.3: senders MUST emit `HEADER_1` with no `transport_id` for every link-addressed packet, because a `HEADER_2` link packet would arrive at the destination with `transport_id` intact and be dropped by the destination's `packet_filter` as "for another transport instance".

#### 12.5.3 PROOF receipt forwarding via `reverse_table`

`Transport.py:2199-2208`. When a PROOF arrives whose `dest_hash` is in `reverse_table` (i.e. an opportunistic-DATA proof being routed back to its originator), the relay pops the entry, checks the proof arrived on the correct outbound interface (`receiving_interface == reverse_entry[IDX_RT_OUTB_IF]`), and forwards on the originally-receiving interface:

```python
new_raw = packet.raw[0:1] + struct.pack("!B", packet.hops) + packet.raw[2:]
Transport.transmit(reverse_entry[IDX_RT_RCVD_IF], new_raw)
```

Reverse_table entries are popped on use (one-shot routing) and aged out by `Transport.jobs` after `Transport.REVERSE_TIMEOUT` (default `30s`). This bounds the relay's memory regardless of whether the proof ever arrives.

### 12.6 Tunnels and shared-instance protocol

Two related state mechanisms a transport node maintains:

#### 12.6.1 `discovery_path_requests`

When a transport-enabled relay receives a path? for a destination it doesn't know AND doesn't have a local client to forward to, it records a `discovery_path_requests[dest_hash]` entry (`Transport.py:3113-3125`):

```python
pr_entry = {
    "destination_hash": destination_hash,
    "timeout": time.time() + PATH_REQUEST_TIMEOUT,    # 15s
    "requesting_interface": attached_interface,
}
Transport.discovery_path_requests[destination_hash] = pr_entry
```

Then forwards the path? to every other **online** interface (offline interfaces are skipped since RNS 1.4.2 — `RNS/Transport.py:3129`) preserving the original tag. This is recursive transport-mode discovery — the relay is acting as a search proxy. When the response announce eventually arrives back, the relay forwards it on `requesting_interface` (the one the original path? came from), and the entry is aged out.

#### 12.6.2 `tunnels`

A tunnel is an interface-level path mechanism for handling temporarily-disconnected interfaces (e.g. a mobile peer that comes and goes). The `tunnels[interface_tunnel_id]` state lets the relay reconstruct paths through the interface when it reconnects, without requiring all paths to be re-discovered from scratch. The shape (`Transport.py:792-832`):

```
[ now,                                       # 0  IDX_TT_TIMESTAMP
  expires,                                   # 1  IDX_TT_EXPIRES — TUNNEL_TIMEOUT
  paths_dict,                                # 2  IDX_TT_PATHS — dest_hash → path-entry
  ... ]
```

Each path inside the tunnel's `paths_dict` mirrors a `path_table` entry. When the tunnel's interface returns, the relay re-installs every path from the tunnel into the active `path_table`, jump-starting connectivity. Without this, every reconnection would require a full announce flood across the mesh.

`TUNNEL_TIMEOUT` defaults to substantially longer than path TTLs because tunnels persist across interface flap.

#### 12.6.3 Shared-instance protocol

When multiple processes on one host share a single Reticulum stack (via `share_instance = Yes` in the rnsd config), one process owns `Transport` and the others connect to it as **local clients** via a small TCP loopback interface. The shared instance treats local-client traffic specially:

- `from_local_client` and `for_local_client` are computed on every inbound packet (`Transport.py:1551-1556`).
- Path-table entries with `IDX_PT_HOPS == 0` mean "destination is a local client" — the §2.3 originator-side HEADER_1 conversion applies for hops==1 too, so the shared instance gets a transport_id-tagged packet (`Transport.py:1172-1183`).
- Local-client originated path? requests are forwarded to every external interface, fanning out the search across the shared mesh (§7.2 dispatch branch 3).

The wire protocol for shared-instance loopback is just the same Reticulum packets over a TCP loopback interface — no special framing or commands. What's "shared" is the path_table and announce dispatch, not the wire format.

### 12.7 Source map for §12

| File | What |
|---|---|
| `RNS/Transport.py:1602-1697` | DATA forwarding (HEADER_1↔HEADER_2 conversion for relay) |
| `RNS/Transport.py:1556-1565` | `link_table` entry shape |
| `RNS/Transport.py:1686-1688` | `reverse_table` entry shape |
| `RNS/Transport.py:1930-2073` | ANNOUNCE rebroadcast queue and per-interface dispatch |
| `RNS/Transport.py:2206-2265` | LRPROOF forwarding via `link_table` |
| `RNS/Transport.py:2338-2347` | PROOF receipt forwarding via `reverse_table` |
| `RNS/Transport.py:3668-3674` | `path_table` entry shape (IDX_PT_*) |
| `RNS/Transport.py:780-867` | stale-path / stale-tunnel eviction |
| `RNS/Transport.py:3113-3125` | `discovery_path_requests` recursive search |
| `RNS/Interfaces/Interface.py:321-357` | per-interface `announce_queue` and `ANNOUNCE_CAP` enforcement |

---

## 13. Threading and concurrency model

The wire spec is silent on threading, but a clean-room client built single-threaded mostly works for opportunistic LXMF and starts breaking on Resource transfers and Link keepalives. This is consistently the #1 cause of "my client compiles and almost works but is flaky." Everything below is **implementation-private** — there's no wire requirement to use threads, only to satisfy the timing guarantees that upstream's threading provides. But the upstream Python implementation is highly concurrent; an alternative implementation that wants to interop has to provide the same guarantees, however it achieves them.

### 13.1 Long-running threads

Upstream RNS spawns the following persistent daemon threads at `Transport.start()`:

| Thread | Source | Cadence | Purpose |
|---|---|---|---|
| **`Transport.jobloop`** | `RNS/Transport.py:302, 516-519` | every `job_interval = 0.250s` | Runs `Transport.jobs()` — the catch-all maintenance pass: link state checks, announce-queue drain, stale-path eviction, hashlist cleanup, reverse-table cleanup, tunnels housekeeping. |
| **`Transport.count_traffic_loop`** | `RNS/Transport.py:303, 483-514` | every 1s | Snapshots per-interface RX/TX byte counters into rolling-window deques for bandwidth/airtime accounting. |
| **`Link.__watchdog_job`** | `RNS/Link.py:751-828` | per-link, RTT-driven | One per active Link. Drives keepalive emission (initiator side), STALE→CLOSED transitions, and link-establishment timeouts. Sleeps `min(WATCHDOG_MAX_SLEEP=5s, RTT-derived)` between iterations. |
| **`Resource.__watchdog_job`** | `RNS/Resource.py:564-670` | per-resource | One per in-progress Resource. Detects retransmit timeouts, advertisement retries, and PRF-wait timeouts. |
| **`AnnounceHandler` callbacks** | `RNS/Transport.py:2094-2123` | per inbound announce | Each accepted announce fires its registered handler **on a fresh daemon thread** — the dispatcher does not serialize. Two announces from the same destination back-to-back run two handler threads concurrently. |
| **Per-interface RX threads** | `RNS/Interfaces/*Interface.py` | always | Each interface (TCP, KISS, RNode, AutoInterface) has its own blocking-read RX thread that calls `Transport.inbound(raw, self)` on each complete frame. |
| **`process_announce_queue`** | `RNS/Interfaces/Interface.py:355` | one-shot timer per drain | Per-interface `announce_queue` drain uses `threading.Timer` to schedule the next emission at the airtime-cap-derived wait time. Not a long-running thread but a chain of one-shots. |
| **`Resource.__advertise_job`** | `RNS/Resource.py:520-542` | per-resource | One-shot daemon thread that performs the resource hashmap construction (which can take seconds on a large body) so the calling thread doesn't block. |

A clean-room implementation with cooperative scheduling (e.g. asyncio, embedded RTOS task model) needs to provide equivalent behavior for each row. The key invariants — not the exact thread inventory — are what matter for interop:

- The watchdog must run independently of the calling code, or links go stale silently when the application is busy.
- Announce-handler callbacks must NOT block subsequent inbound packet dispatch. If your handler runs synchronously on the receive thread, a slow handler stalls every other inbound traffic.
- The job loop must run regardless of inbound traffic; otherwise `path_table` doesn't evict stale entries, `discovery_path_requests` doesn't time out, and the announce_table doesn't drain its queued retransmits.

### 13.2 Lock inventory

Upstream uses about 30 named locks. The shared-state ones a clean-room implementation must guard equivalently (or substitute single-threaded equivalent):

| Lock | Guards |
|---|---|
| `Transport.path_table_lock` | `Transport.path_table` reads and writes |
| `Transport.announce_table_lock` | `Transport.announce_table` reads and writes |
| `Transport.link_table_lock` | `Transport.link_table` (transit-relay link forwarding state) |
| `Transport.reverse_table_lock` | `Transport.reverse_table` (PROOF reverse-routing state) |
| `Transport.active_links_lock` | `Transport.active_links` list |
| `Transport.pending_links_lock` | `Transport.pending_links` list |
| `Transport.tunnels_lock` | `Transport.tunnels` |
| `Transport.destinations_map_lock` | `Transport.destinations_map` (local destinations registered for receive) |
| `Transport.announce_handler_lock` | `Transport.announce_handlers` list |
| `Transport.path_requests_lock` | `Transport.path_requests` rate-limiting cache |
| `Transport.discovery_pr_tags_lock` | `Transport.discovery_pr_tags` dedup |
| `Transport.jobs_lock` | held for the entire `jobs()` body — long-held, blocking |
| `Identity.known_destinations_lock` | `Identity.known_destinations` dict reads/writes |
| `Identity.ratchet_persist_lock` | ratchet persistence file I/O |
| `Link.watchdog_lock` | per-link gate; the watchdog `wait`s on this when the link is in the middle of a state change |
| `Link.receive_lock` | per-link inbound packet processing |
| `Resource.assembly_lock` | per-resource gate around assemble() |
| `Destination.ratchet_file_lock` | per-destination ratchet file I/O |

`Transport.jobs_lock` is the most aggressive — it's held for the **entire** `jobs()` execution (which can include I/O for path persistence, announce queue draining, etc.). This is what bounds how often `jobs()` can run; you can't pile up parallel jobs() invocations even if `job_interval` elapses while one is running.

### 13.3 Callback-thread guarantees (and lack thereof)

What upstream **guarantees** to application-level callbacks:

- **`Destination.set_packet_callback`** — fires once per inbound DATA, on the receive thread. **Synchronous.** A slow callback stalls subsequent inbound packet dispatch on the same interface.
- **`Link.set_link_established_callback`** — fires once when a link transitions PENDING → ACTIVE. On the receive thread.
- **`Link.set_link_closed_callback`** — fires once when a link transitions to CLOSED, regardless of cause (timeout, peer close, local teardown). On the watchdog thread or the receive thread depending on which path triggered the close.
- **`PacketReceipt.set_delivery_callback`** — fires once when a PROOF arrives matching this receipt. On the receive thread.
- **`AnnounceHandler.received_announce`** — fires once per accepted announce, **on a fresh daemon thread**. This is the only callback that's NOT on the receive thread (`Transport.py:2094-2123`).
- **`Resource.callback`** — fires once on resource conclude, on the assembly thread.

Implications for a clean-room implementation:

1. **Don't block on the receive thread.** A `set_packet_callback` that does I/O or PoW work blocks every other inbound packet on the same interface until it returns. The standard pattern is: copy the data out, hand it to a worker queue, return immediately.
2. **Announce handlers race.** Two callbacks for the same destination can run concurrently; if your handler mutates shared state (a contacts list, a UI), use a lock or single-thread the writes.
3. **Link-closed can fire from two paths.** Watchdog timeout or peer LINKCLOSE both call `link_closed_callback`. Make the callback idempotent.

### 13.4 Implementation-private constants

These are not on the wire but affect timing-sensitive interop. A client that uses radically different values may diverge from upstream's behavior in subtle ways:

| Constant | Default | Notes |
|---|---|---|
| `Transport.job_interval` | `0.250s` | Quarter-second cadence of `jobs()`. |
| `Transport.links_check_interval` | `1.0s` | Throttles inside `jobs()`; links are scanned at most every 1s. |
| `Transport.tables_cull_interval` | `5.0s` | Throttles path/reverse/link table eviction inside `jobs()`. |
| `Transport.hashlist_maxsize` | `1000000` | Packet-hash dedup ring; once full, half is purged on next `jobs()`. |
| `Link.WATCHDOG_MAX_SLEEP` | `5s` | Cap on link watchdog sleep regardless of RTT. |
| `Resource.WATCHDOG_MAX_SLEEP` | `1s` | Resource watchdog cadence cap. |
| `Resource.PROCESSING_GRACE` | `1.0s` | Grace before a resource is considered timed out. |
| `Resource.SENDER_GRACE_TIME` | `10.0s` | End-of-transfer grace if some parts haven't been requested. |

A client running on a constrained device (less RAM, slower CPU) can scale all of these up — at the cost of slower path-table responsiveness and slightly later timeout decisions. Don't scale them down unless you've actually measured your platform; below ~100 ms `job_interval` upstream Python burns measurable CPU just on the bookkeeping passes.

### 13.5 Source map

| File | What |
|---|---|
| `RNS/Transport.py:302-303` | top-level thread spawn at startup |
| `RNS/Transport.py:135-151` | the lock inventory (Transport-side) |
| `RNS/Transport.py:178, 180, 191` | `job_interval`, `links_check_interval`, `tables_last_culled` |
| `RNS/Transport.py:516-519` | `jobloop` — the periodic driver |
| `RNS/Transport.py:522+` | `jobs()` body (held under `jobs_lock`) |
| `RNS/Transport.py:2094-2123` | announce-handler dispatch (fresh thread per callback) |
| `RNS/Link.py:712-781` | per-link `__watchdog_job` |
| `RNS/Resource.py:564-670` | per-resource `__watchdog_job` |
| `RNS/Resource.py:520-542` | one-shot `__advertise_job` |
| `RNS/Interfaces/*Interface.py` | per-interface RX thread |

---

## 14. Failure modes — symptom → root cause

§9 lists gotchas keyed by *cause* ("here's a thing that's true"). This section is the inverse index, keyed by *symptom* — what you're observing, and where to look. Each entry names the symptom, points at the section that explains why, and (where useful) names a `tools/verify_*.py` script that locks in the fix.

### Identity / announce

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Generated identity files don't load on upstream `rnsd` | §1.3 — on-disk byte order is `X25519_priv \|\| Ed25519_priv` (NOT the opposite as some old docs claim) | `tools/verify_destination_hash.py` round-trips `to_file`/`from_file` |
| Sideband shows you as "Anonymous" or random hex instead of your display name | §9.3 — display name was msgpack-encoded as `str` instead of `bytes`. Upstream's `dn.decode("utf-8")` raises silently | `tools/verify_msgpack_quirk.py` |
| Announces validate locally but upstream peers reject as "Destination mismatch" | §1.2 — `name_hash` recipe wrong; the `identity=None` branch of `expand_name` does NOT include the identity hex in the hash input | `tools/verify_destination_hash.py` |
| Upstream announces with ratchets get rejected by my validator | §4.5 step 1 — body parser didn't branch on `context_flag` bit; ratchet-bearing announces shift `signature` 32 bytes deeper | §4.5 step 1 |
| First contact with a peer works, but path table never refreshes from a Python source after a microReticulum announce arrives | §4.1 / §9.10 — microReticulum emits 10 fully-random bytes for `random_hash` instead of 5-random + 5-uint40-timestamp. Python receivers parse `random_hash[5:10]` as far-future and lock the path against fresher Python announces | §9.10 |
| Periodic re-announce works locally but peers can't reach me after a few minutes | §7.5 / §9.7 — re-announce loop isn't running. Transit relays evict path entries within minutes regardless of TTL | §9.7 |
| Announces propagate fine but my client populates its contact list with itself | §9.5 / §4.5 step 8 — self-announce echo. Filter `dest_hash == our_dest_hash` before ingesting any inbound announce | §4.5 step 8 |

### Token crypto / opportunistic LXMF

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Decrypted plaintext is correct but has 16 garbage bytes appended | §9.2 — manual PKCS#7 padding on top of platform's automatic padding (Web Crypto / JCA `AES/CBC/PKCS5Padding`) | §9.2 |
| HMAC validates but AES decrypt produces gibberish | §3.2 — HKDF salt is wrong. Salt MUST be the recipient's 16-byte `identity_hash`, not the destination hash, not the ratchet pub | `tools/verify_token_crypto.py` |
| Decrypt works for the first message after announce but fails for subsequent ones | §3.3 / §7.4 — recipient rotated their ratchet, you're still using the cached `ratchet_pub`. Re-fetch the latest announce or use the long-term encryption key as fallback | §3.3 |
| Tampered packets are accepted as valid | §3.3 — verifying HMAC AFTER AES decrypt (or not at all). Encrypt-then-MAC: verify HMAC FIRST | `tools/verify_token_crypto.py` |
| LXMF decrypts cleanly but signature validation fails | §5.6 — try both raw `packed_payload` AND a stripped-and-re-encoded form (with the optional 5th `stamp` element removed) | §5.6 |
| `source_hash` lookup returns nothing even though I just received an announce from that peer | §9.1 / §5.4 — `source_hash` is the SENDER's destination hash (`SHA256(name_hash \|\| identity_hash)[:16]`), NOT the raw 16-byte identity hash | §9.1 |

### Link establishment / proof receipts

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| LINKREQUEST goes out but no LRPROOF arrives | §6.1 — body length wrong. 64 (no signalling) or 67 (with §6.6 signalling); anything else is rejected | `tools/verify_link_handshake.py` |
| LRPROOF arrives but signature validation fails | §6.2 — body order wrong. Actual upstream is `signature \|\| responder_X25519_pub \|\| signalling`; the `link_id` is in the packet header, not the body | `tools/verify_link_handshake.py` |
| Link handshake fails specifically when MTU signalling is present on one side but not the other | §6.6.5 — signalling bytes (when present) are part of the LRPROOF `signed_data`. A mismatch means signed_data differs and signature fails | §6.6.5 |
| Link establishes but tears down within 5 minutes of inactivity | §6.7 — KEEPALIVE not implemented. Initiator sends `0xFF` ping every `keepalive` seconds; responder replies with `0xFE` pong | §6.7.1 |
| Sender sees DATA bursts repeatedly retransmitted, link dies | §6.5 — receiver isn't emitting the mandatory PROOF receipt for each CTX_NONE Link DATA packet | `tools/verify_proof_packet.py` |
| Some peers work, others reject every PROOF I send | §6.5.2 — wrong proof body length. Upstream default emits 64-byte implicit proofs (`signature` only) but your peer expects 96-byte explicit (`packet_hash \|\| signature`). Validator dispatches on length | `tools/verify_proof_packet.py` |
| Initiator and responder complete LRPROOF but every Resource ADV / link DATA the initiator sends is silently dropped at the responder | §6.4.2 — initiator never emitted LRRTT after LRPROOF. Responder stays in `HANDSHAKE`, `link_established` callback never fires, LXMF's `set_resource_strategy(ACCEPT_APP)` never installs, and `Link.receive` hits the silent `ACCEPT_NONE` branch on every RESOURCE_ADV | §6.4.2 |
| Single-hop link works, but the same flow over a multi-hop link silently drops every link DATA / Resource part at the destination | §6.4.3 — link-addressed packets emitted as `HEADER_2` with `transport_id` set to the next-hop relay. link_table forwarding doesn't strip `transport_id`, so the destination's `packet_filter` rejects it as "for another transport instance" (LOG_EXTREME). Use `HEADER_1` and `transport_id=None` regardless of hop count | §6.4.3 |

### Resource transfers (large bodies)

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Resource advertisement arrives, but my receiver never asks for parts | §10.5 — RESOURCE_REQ shape: `exhausted_flag(1) [\|\| last_map_hash(4)] \|\| resource_hash(32) \|\| requested_map_hashes(N×4)` | §10.5 |
| Resource transfers but assemble fails with hash mismatch | §10.12 — encryption is applied to the WHOLE concatenated body BEFORE part splitting. Accumulate all parts, then run `link.decrypt()` once | §10.12 |
| Resource hash collisions during construction | §10.2 step 9 — collision-guard must regenerate `random_hash` and recompute the hashmap when any 4-byte map_hash collides within `COLLISION_GUARD_SIZE` window | §10.2 step 9 |
| `ADV` for >1MiB body never resolves | §10.11 — multi-segment cutover at `MAX_EFFICIENT_SIZE = 1 MiB - 1`. Each segment is a separate Resource; sender only sends segment N+1's ADV after PRF for segment N | §10.11 |

### Path discovery

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Path? requests sent but no announce response | §7.2.1 — tagless requests are dropped. Body must be `target_dest_hash(16) [\|\| transport_id(16)] \|\| tag(≥1)` | `tools/verify_path_request.py` |
| Path? requests accepted by responder but I get no announce back | §7.2.6 — leaf clients only respond when `target_hash == our_destination_hash`. Don't respond for destinations you don't OWN | §7.2.6 |
| Spurious double-announces in response to one path request | §7.2.2 — `discovery_pr_tags` dedup table missing on responder. Without it, every retransmitted path? produces another announce | §7.2.2 |
| Sending opportunistic LXMF triggers a path? on every send, never converges | §7.1 — path? is gated by `not has_path() AND method == OPPORTUNISTIC`. If your `has_path()` always returns False, you're storming the network | §7.1 |

### Transport / framing

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| LoRa packets > 254 bytes drop entirely on RNode | §8.3 — RNode air-frame split protocol not implemented. Random seq nibble + FLAG_SPLIT bit; both halves share the same header byte | `tools/verify_rnode_split.py` |
| RNode receives correctly but TX is silent | §8.4.2 — KISS configuration handshake incomplete. CMD_RADIO_STATE = 0x01 must be the LAST step | §8.4.2 |
| Received RSSI/SNR values are garbage | §8.4.5 — wrong sidecar decode. `RSSI = byte - 157`, `SNR = signed Q6.2 / 4`. Sidecar frames precede each `CMD_DATA` frame | §8.4.5 |
| Multi-hop packets arrive but local-destination packets don't | §2.3 — originator HEADER_1→HEADER_2 conversion not applied for hops > 1. Originators must do this conversion themselves when path table reports `hops > 1` | `tools/verify_packet_header.py` |
| Sending to multi-hop peers fails silently after path table populated | §7.6 — `TCPServerInterface.OUT` is True by default in practice (constructor's `False` is overridden at runtime). Don't waste time chasing a stuck OUT flag | §7.6 |

### LXMF specifics

| Symptom | Likely cause | Fix / verifier |
|---|---|---|
| Messages from clockless devices appear at January 1, 1970 | §9.6 — substitute. Treat any timestamp before `1577836800` (2020-01-01) as "no clock"; substitute local receive time | §9.6 |
| Modern Sideband marks my messages as spam / drops them | §5.7 — recipient requires a stamp (announced via `stamp_cost` in app_data) and your client doesn't compute one. PoW is 3000-round HKDF over `message_id`, target_cost leading zero bits | §5.7 |
| Display name disappears after a re-announce | §9.4 — wrong name-priority order. Use `extracted ?? existing ?? known_label ?? ""`, NOT `extracted ?? known_label ?? existing ?? ""` | §9.4 |
| Propagation node accepts messages but my client never retrieves them | §5.8.3 — `/get` request needs the link to be `identify()`-d first; otherwise it returns `ERROR_NO_IDENTITY` | `flows/receive-propagated-lxmf.md` |
| Custom propagation node implementation rejects all client `/offer` requests | §5.8.5 — element [5] of the propagation announce app_data is a 3-element list `[stamp_cost, stamp_cost_flexibility, peering_cost]`, NOT a single integer | §5.8.5 |

### Concurrency

| Symptom | Likely cause | Fix |
|---|---|---|
| Links go stale even though my application is actively using them | §13.1 — your watchdog runs on the same thread as your application. Move it to a daemon thread | §13.1 |
| Slow announce handler stalls subsequent inbound packets | §13.3 — packet callback runs synchronously on the receive thread. Queue and return; don't do I/O or PoW on the receive thread | §13.3 |
| `link_closed_callback` fires twice for one link | §13.3 — callback fired from both watchdog timeout AND inbound LINKCLOSE paths. Make idempotent | §13.3 |
| Two announces from the same destination produce duplicate UI rows | §13.3 — handler callbacks race on fresh threads. Lock or single-thread the writes to your contacts list | §13.3 |

### When all else fails

§9.9 — add a single one-line `rx <size>B H<1\|2> <PT> dest=<hex> ctx=0x<hex> hops=<n>` log at the top of your `Transport.inbound` equivalent. The number of debugging hours this saves is hard to overstate. Symmetric `tx` logging on outbound is similarly cheap.

---

## 15. Time and clock requirements

Reticulum has time-sensitive behaviour scattered across many sections. This is the consolidated reference for what kind of clock you need where, what tolerance the protocol gives you, and what fails on a no-RTC device (Faketec, RAK4631 stock, Heltec_T114, generic nRF52 LoRa boards).

### 15.1 Three clock kinds

| Kind | What it tells you | Typical embedded availability |
|---|---|---|
| **Absolute wall time** | Current Unix-seconds (e.g. `1714780800`) | Only with NTP sync, GPS, or hand-set clock |
| **Boot-relative monotonic seconds** | Seconds since the device booted | Always, via `millis()` / `time.monotonic()` |
| **High-resolution monotonic** | Sub-second timing for RTT and watchdog | Always, but precision varies |

Most upstream Python code assumes wall time is available because it runs on hosts with NTP. Embedded clean-room implementations need to be careful about which kind each call site needs.

### 15.2 Required: monotonic seconds (every implementation)

These break a single-clock implementation if missing. All can be satisfied by **boot-relative seconds** — they only need order, not absolute value.

| Use | Section | What fails without it |
|---|---|---|
| Link RTT measurement | §6.7.1 | `keepalive` interval can't adapt; defaults to `KEEPALIVE_MAX = 360s` worst case |
| Link watchdog (last_inbound, last_outbound, last_keepalive timestamps) | §6.7 | Link can't detect staleness; lingers forever or tears down spuriously |
| Resource transfer watchdog (last_activity, advertisement retry timing) | §10 | Resource transfers stall without retry; SENDER_GRACE_TIME never triggers |
| `Transport.path_requests` rate-limit (`PATH_REQUEST_MI = 20s` minimum interval) | §7.1 | Path? storms — repeats faster than rate limit allows |
| `Transport.tables_last_culled` periodic eviction trigger | §13.4 | Path/reverse/link tables grow without bound |
| `Transport.discovery_pr_tags` aging (`PATH_REQUEST_GATE_TIMEOUT = 120s`) | §7.2.2 | Path-request dedup table never evicts old entries |
| `Interface.ic_burst_freq` rolling deque for ingress rate limiting | §4.5 step 8 | Per-interface ingress limiter can't compute Hz |

### 15.3 Recommended: monotonic-with-no-skew across announces (timestamp encoding)

The §4.1 `random_hash` carries a 5-byte big-endian uint40 timestamp:

```python
random_hash = get_random_hash()[:5] + int(time.time()).to_bytes(5, "big")
```

Transit relays read `random_hash[5:10]` as a unix-seconds value and use it for path-table replay-ordering decisions (§4.5 step 6.3). Two requirements:

1. **Monotonic across announces from the same destination.** A new announce should have a higher timestamp than older ones from the same destination, or relays will reject it as "older than what we have cached" in the equal-or-greater-hop branch.
2. **Comparable to other peers' timestamps.** If all your announces always look like "year 1970" (boot-relative seconds presented as unix), you'll consistently lose path-replay comparisons against peers with real wall time. That's actually fine — your announces just won't replace cached entries from real-time peers — but the inverse case is the §9.10 microReticulum bug: random `random_hash[5:10]` looks "far future" and freezes the path table.

**No-RTC strategy:** emit boot-relative seconds. You'll always look stale to wall-time peers (their announces win in path-replace decisions, which is correct because their data is fresher), and you'll get monotonic-from-boot ordering between your own announces (correct).

**Wrong strategy:** emit fully-random bytes (the §9.10 microReticulum bug). Locks you in as "latest" forever.

### 15.4 Recommended: wall time (LXMF-level)

These use absolute Unix-seconds. A device without wall time can substitute, with caveats:

| Use | Section | Substitution if no wall time |
|---|---|---|
| LXMF body `timestamp` (`payload[0]`) | §5.3 | Use boot-relative seconds. Recipients per §9.6 should treat any timestamp before `1577836800` (2020-01-01) as "no clock" and substitute their local receive time. |
| Outgoing message `LXMessage.timestamp` for sender-side ordering | §5.3 | Same as above. |
| Stamp ticket expiry (`fields[FIELD_TICKET][0]`) | §5.7.3 | **You can't substitute here.** Tickets you issue with boot-relative seconds will appear to have already-expired-or-already-distant-future expiries to recipients. If your device has no wall time, don't issue tickets — fall back to PoW stamps (§5.7.2). |
| Propagation node `timebase` field in `/offer` requests | §5.8.5 | Same as random_hash strategy: boot-relative is fine; you'll appear "stale" but your peers' state stays consistent. |

### 15.5 Optional: high-resolution monotonic for diagnostics

These are nice-to-have; missing them just degrades observability:

- Per-packet RX timestamp for RTT decomposition.
- Airtime accounting (sub-second precision improves `ANNOUNCE_CAP` enforcement; integer seconds is fine).
- Resource transfer `establishment_rate` calculation.

Use whatever monotonic source your platform provides; even 1 ms resolution from `millis()` is plenty.

### 15.6 What fails on a no-RTC, no-NTP-sync device

A device that boots with no clock at all (`time.time()` returns a small integer, RTC chip absent or empty) and never syncs:

- ✅ **Sending and receiving opportunistic LXMF** works fine. The §9.6 receiver-side fix-up (substitute local receive time when timestamp < 2020) handles your "year 1970" timestamps cleanly.
- ✅ **Receiving propagated LXMF** works. The propagation node tags messages with its own timestamp; you don't need yours.
- ✅ **Establishing Links** works. RTT is measured locally and only used for relative cadences.
- ⚠️ **Periodic re-announces** work, but your `random_hash[5:10]` will always look stale to wall-time peers. Your announces propagate fine; they just don't win path-table replacement races against fresher peers (which is correct — they ARE fresher).
- ⚠️ **Path-table updates from your own announces** work the first time (no cached entry to compare against), but subsequent re-announces may not replace stale cache entries on transit relays. Practical effect: your destination is reachable but transit relays keep trying older paths longer than ideal.
- ❌ **Issuing LXMF tickets** doesn't work — the expiry timestamp in `FIELD_TICKET` is meaningless without wall time. Don't issue tickets; rely on PoW stamps.
- ❌ **Sending propagated LXMF with ticket-based stamp shortcuts** doesn't work for the same reason.

A single one-time clock sync (BLE config, web flasher, manual button-press at known time, GPS, `rnstatus` peer query) flips most of the ⚠️ items to ✅. The repeater repo's BLE config protocol can carry a clock value in the connection handshake; that's the simplest fix.

### 15.7 Source map

| Section | What relies on time |
|---|---|
| §4.1 | `random_hash[5:10]` emission timestamp |
| §4.5 step 6.3 | Path-table replacement using `random_blob` timestamps |
| §5.3 | LXMF body timestamp |
| §5.7.3 | LXMF ticket expiry |
| §5.8.5 | Propagation node timebase field |
| §6.7.1 | Link KEEPALIVE / RTT cadence |
| §7.1 | `Transport.path_requests` rate limit |
| §7.2 | `discovery_pr_tags` aging |
| §7.5 | Periodic re-announce cadence |
| §9.6 | Clockless sender LXMF timestamp fix-up |
| §10 | Resource watchdog timeouts |
| §13.4 | All `Transport.jobs` periodic intervals |

---

## 16. Bounded-state inventory (memory limits at a glance)

Embedded clean-room implementations need to know up front which data structures grow with traffic and which are bounded by protocol-level caps. This section is a single-table reference for every bounded structure across §1-§15.

### 16.1 Per-node state caps

| Structure | Cap | Where | Notes |
|---|---|---|---|
| `Transport.path_table` | (unbounded — count grows with mesh size) | §12.4 | Grows with the number of distinct destinations the node has heard about. Bounded effectively by TTL eviction (§12.4.2): AP_PATH_TIME (1h), ROAMING_PATH_TIME (4h), PATHFINDER_E (30d). On a tiny LoRa mesh this is dozens of entries; on a global Reticulum mesh routed through a TCP backbone it can be thousands. |
| `path_table[dest][IDX_PT_RANDBLOBS]` (per-destination random_blob history) | `Transport.MAX_RANDOM_BLOBS = 64` (RNS 1.4.2) | §4.5 step 6.3, §12.3.2 | Sliding window. Caps memory growth from one destination's announce stream. |
| `Transport.announce_table` | (unbounded — populated only for in-flight announces awaiting rebroadcast) | §12.3 | Drains via `Transport.jobs` retransmit timer, capped at `PATHFINDER_R = 4` retries each. Effective cap: number of announces seen × time. |
| `Transport.discovery_pr_tags` | `Transport.max_pr_tags = 32000` | §7.2.2 | Path-request dedup table. Older entries aged out by `Transport.jobs`. |
| `Transport.path_requests` | (unbounded — one entry per recently-issued path? request) | §7.1 | Aged out at `Transport.PATH_REQUEST_GATE_TIMEOUT = 120s`. |
| `Transport.discovery_path_requests` | (unbounded) | §7.2.3, §12.6.1 | Aged out at `Transport.PATH_REQUEST_TIMEOUT = 15s`. |
| `Transport.link_table` (transit-relay link state) | (unbounded) | §12.2.4, §12.5 | One per Link the relay is forwarding for; cleared on link teardown or stale aging. |
| `Transport.reverse_table` | (unbounded) | §12.5.3 | One entry per in-flight DATA→PROOF round-trip; popped on use, aged at `Transport.REVERSE_TIMEOUT = 30s`. |
| `Transport.tunnels` | (unbounded) | §12.6.2 | One per tunnel-able interface; aged at `Transport.TUNNEL_TIMEOUT`. |
| `Transport.packet_hashlist` (dedup ring) | `Transport.hashlist_maxsize = 1,000,000` | §13.4 | Half is purged on next `Transport.jobs` after the cap is hit. |
| `Transport.active_links` | (unbounded — one per active Link the node owns or relays) | §6 | |
| `Transport.pending_links` | (unbounded — one per Link in PENDING/HANDSHAKE state) | §6.7 | Aged out at `Link.ESTABLISHMENT_TIMEOUT_PER_HOP × hops + KEEPALIVE`. |

### 16.2 Per-interface state caps

| Structure | Cap | Where |
|---|---|---|
| `Interface.held_announces` | `Interface.MAX_HELD_ANNOUNCES = 256` | §4.5 step 8 |
| `Interface.announce_queue` | `Reticulum.MAX_QUEUED_ANNOUNCES` (default ~64; configurable) | §12.3.1 |
| `Interface.ia_freq_deque` (incoming announce rate) | `Interface.IA_FREQ_SAMPLES` rolling sliding window | §13.1 |
| `Interface.oa_freq_deque` (outgoing announce rate) | `Interface.OA_FREQ_SAMPLES` rolling sliding window | §13.1 |

### 16.3 Per-destination state caps

| Structure | Cap | Where |
|---|---|---|
| `Destination.ratchets` | `Destination.RATCHET_COUNT = 512` | §7.4 |
| `Destination.path_responses` | (per-tag, aged at `Destination.PR_TAG_WINDOW = 30s`) | §7.2.4 |
| `Destination.links` (responder-side active links) | (unbounded — one per established Link to this destination) | §6 |

### 16.4 Per-Link state caps

| Structure | Cap | Where |
|---|---|---|
| `Link.outgoing_resources` | (unbounded — one per in-flight outgoing Resource on this link) | §10 |
| `Link.incoming_resources` | (unbounded — one per in-flight incoming Resource on this link) | §10 |
| `Link.pending_requests` | (unbounded — one per outstanding REQUEST on this link) | §11.5 |

### 16.5 Per-Resource state caps

| Structure | Cap | Where |
|---|---|---|
| `Resource.window` | runtime: between `WINDOW_MIN = 2` and `window_max` | §10.10 |
| `Resource.window_max` | one of `WINDOW_MAX_VERY_SLOW = 4`, `WINDOW_MAX_SLOW = 10`, `WINDOW_MAX_FAST = 75` | §10.10 |
| `Resource.parts` | `Resource.total_parts = ceil(size / SDU)` | §10.2 step 7 |
| `Resource.hashmap` | 4 × `total_parts` bytes | §10.2 step 8 |
| `Resource.req_hashlist` | (unbounded per resource — one entry per RESOURCE_REQ packet seen) | §10.6 |

### 16.6 Identity/cryptography caches

| Structure | Cap | Where |
|---|---|---|
| `Identity.known_destinations` | (unbounded) | §4.5 step 6 — main growth vector. Persisted across restart; aged out via `Identity.clean_known_destinations` based on `Identity.RATCHET_EXPIRY = 30 days` for unused entries. |
| `Identity.known_ratchets` | (unbounded — one per `known_destinations` entry that has ever announced a ratchet) | §4.5 step 6, §7.4 |
| `Transport.blackholed_identities` | (operator-controlled; empty by default) | §4.5 step 5 |

### 16.7 LXMF-level caps

| Structure | Cap | Where |
|---|---|---|
| `LXMRouter.locally_delivered_transient_ids` | (operator-bounded) | §4.5 step 6 / §5.7 dedup |
| `LXMRouter.outbound_stamp_costs` | (per peer — grows with peer count) | §5.7.4 |
| `LXMRouter.available_tickets` | (per peer / direction) | §5.7.3 |
| `LXMRouter.propagation_entries` | (operator-bounded — propagation node only) | §5.8 |
| `LXMRouter.peers` | (operator-bounded — propagation node only) | §5.8 |

### 16.8 Channel state caps

| Structure | Cap | Where |
|---|---|---|
| `Channel.window` | `Channel.WINDOW = 2` initial, growth like §10.10 | §6.8.4 |
| `Channel.message_factories` | (per-Link, application-defined) | §6.8.3 |
| `Channel.outbound_queue` / inbound | (unbounded — one entry per in-flight message) | §6.8.4 |

### 16.9 What this means for embedded targets

A typical nRF52 / RAK4631 / Heltec_T114 client carrying ~64KB of usable RAM should:

- Not run as a transport node (skips most of §16.1's largest structures: link_table, reverse_table, tunnels, large path_table). Leaf clients only populate `path_table` for destinations they personally need, dramatically smaller.
- Cap `Identity.known_destinations` at a sane size (e.g. 50-200 entries) and drop older ones when full. Upstream's unbounded growth is fine on a desktop; embedded clients need explicit eviction. Loss of an entry just means re-discovering via §7.1 path? on next outbound to that destination.
- Bound `Resource.hashmap` size — a 1 MiB resource has 1024 parts at SDU=1024, so a 4 KiB hashmap. Reject incoming Resources whose advertised `n` would exceed your memory budget; the receiver's `delivery_resource_advertised` callback can return False to reject (§5.8.3 / NomadNet pattern).
- Stick to `WINDOW_MAX_SLOW = 10` rather than `WINDOW_MAX_FAST = 75` for any Resource transfer to bound part-buffer memory.
- Avoid registering Channel message types with large `pack()` outputs.

For comparison: a desktop `rnsd` typically settles around 50-200 MB of memory in steady state on a moderately-busy mesh, dominated by `path_table` and `known_destinations` growth.

---

## 17. Implementation taxonomy: who needs which sections

Reticulum applications fall into three categories. **Most of this spec only matters if you're in category 3.** Categories 1 and 2 inherit upstream Python RNS's protocol implementation and pick up most of the wire-level correctness for free.

This section exists to save category-1/2 readers from over-engineering, and to flag for category-3 readers exactly which spec sections are theirs to implement vs. theirs to verify against.

### 17.1 The three categories

| Category | Description | Examples |
|---|---|---|
| **1: Upstream-RNS-based** | Python application that does `import RNS` and uses upstream's `Reticulum` / `Transport` / `Identity` / `Destination` / `Packet` / `Link` directly. Inherits all wire-level behavior from upstream. | Sideband (Mark Qvist's flagship), NomadNet, [`liamcottle/reticulum-meshchat`](https://github.com/liamcottle/reticulum-meshchat), `rncp`, `rnsh`, `rnstatus`, anything in `pip show rns` example code |
| **2: Wrappers / language bindings** | Non-Python application whose Reticulum protocol layer is a wrapper around upstream Python RNS — typically via FFI, subprocess, or a network bridge to a co-resident `rnsd`. Inherits wire correctness from the wrapped layer. | Future native iOS / Android / desktop apps that embed CPython, `rnsh` clients in shell scripts, anything that uses `rnsd`'s socket interface |
| **3: Clean-room implementations** | Application that re-implements the Reticulum protocol layer in another language without calling into upstream. Bears full responsibility for wire-level correctness. | `attermann/microReticulum` (C++), `thatSFguy/reticulum-lora-repeater` (C++ via microReticulum), reticulum-mobile-app (Kotlin), reticulum-lora-webclient (JavaScript), any from-scratch implementation in Rust / Go / Swift / etc. |

### 17.2 Section relevance by category

Three classes of section in this spec:

| Class | What it tells you | Cat 1 | Cat 2 | Cat 3 |
|---|---|---|---|---|
| **Wire format** (§1-§8, §10, §11) | What bytes appear on the wire and in what order | Reference only — you emit and parse correctly because upstream does | Reference only — your wrapper does the work | **You implement these.** Bug here → can't talk to anyone |
| **Implementation gotchas** (§9) | Things upstream does that surprise you when reading the manual | **Yes** — because the gotchas often manifest as application-layer behaviour you need to explain to users | **Yes** — same reason | **Yes** — and you need to reproduce the gotchas faithfully or peers reject your traffic |
| **Behavioural guidance** (§7, §12, §13, §14, §15, §16) | Threading, timing, transport-relay, memory caps, failure debug | Mostly informational — upstream handles it | Mostly informational | **Critical** — you implement everything here from scratch |
| **Test vectors / verifiers** (§18, `tools/`) | Round-trip-able byte sequences | Reference for understanding | Reference for understanding | **Required** — these are your regression suite |

### 17.3 Worked example: §2.3 originator HEADER_1→HEADER_2 conversion

A reader hitting §2.3 might wonder "do I need this?" Three different answers:

- **Cat 1 (e.g. Sideband):** No — `RNS.Transport.outbound` at lines 1149-1158 does the conversion automatically when you call `Packet.send()` to a destination with `path_table[dest][HOPS] > 1`. Your app just calls `LXMessage.send()` or `Packet.send()` and §2.3 happens invisibly. You can read §2.3 to understand WHY some captures show HEADER_2 with a transport_id, but you have no code to write.
- **Cat 2 (wrappers):** Same as Cat 1 — the wrapped Python RNS does the conversion. Your wrapper is just relaying API calls.
- **Cat 3 (clean-room):** **Yes, you implement §2.3 yourself.** Failure to do so means your packets aren't forwarded by transit relays — they're processed and dropped silently per `Transport.py:1602` (only HEADER_2 packets with `transport_id == relay.identity.hash` enter the forwarding branch). The symptom is "messages I send through a relay never arrive, but direct-link messages do." Sideband works in shared-instance and direct-TCP modes both because **upstream** does the conversion; a clean-room app working only via shared-instance is masking the missing §2.3.

### 17.4 Pragmatic implication

If you're a category-1 or category-2 developer reading this spec for **operational understanding** — debugging an interop issue, writing a deployment guide, explaining behaviour to users — read §1-§9 and §13-§16; skip the implementation depth.

If you're a category-3 developer building from scratch, you need everything. Verify each section as you go using `tools/verify_*.py`, and treat §14 (failure modes) as your fault-finding entry point when integration testing reveals a discrepancy.

If you're not sure which category you're in: `grep -r "import RNS" your_codebase` is a quick check. Any hit means cat 1 (or cat 2 if it's behind an FFI wall). No hits means cat 3.

### 17.5 Application protocols layered over Reticulum

Reticulum is a transport substrate; user-facing features are *application protocols* built on top. This spec documents **LXMF** (§5) in depth because its wire format is published nowhere else. Other application protocols carry their own authoritative specs and are **out of scope here** — but a clean-room author building a client for one still needs the RNS-layer sections below.

**Reticulum Relay Chat (RRC)** — a live, IRC-style chat protocol. Authoritative spec: <https://rrc.kc1awv.net/> (its CBOR envelope, message types, and state machines live there, not here). RRC is a category-3-style consumer of RNS: it defines its own wire format but relies entirely on Reticulum for transport. An RRC client built clean-room needs:

| RRC depends on | Sections in this spec |
|---|---|
| Hub destination (`rrc.hub` aspect) + client identity | §1.1, §1.2, §9.8 |
| Identity hash as the canonical sender id (RRC envelope key 4, "opaque, do not re-encode") | §1.1; §9.1 — the identity-hash-vs-destination-hash pitfall RRC's rule guards against |
| All traffic over a single Reticulum Link | §6.1–§6.4, §6.7 |
| Single-packet CBOR frames sized to the link MTU | §2.1–§2.2, §2.4, §6.6 (MTU is *negotiated* — see note below) |
| Ordered/reliable delivery, *if* RRC layers over Channel | §6.5, §6.8 |

RRC does **not** use opportunistic packets, Resource transfer (§10), REQUEST/RESPONSE (§11), or LXMF (§5) — an RRC-only client can skip those entirely.

> Two things RRC's spec leaves implicit that this spec makes explicit: link MTU is **negotiated** (§6.6), not a fixed 500 bytes, so frames sized to the default can overflow a smaller link; and a bare Link does not itself guarantee ordered/reliable delivery — that comes from Channel (§6.8) or packet receipts (§6.5).

---

## 18. Test vectors

See [`test-vectors/`](test-vectors/). Currently populated:

- **`identities.json`** — Alice and Bob private-key inputs plus their derived `public_key`, `identity_hash`, and `lxmf.delivery` `destination_hash`. Verified by `tools/verify_destination_hash.py`; regenerated by `tools/regen_identities.py`. Covers SPEC.md §1.1 and §1.2.

> ⚠️ **UNVERIFIED:** The remaining vector categories — signed announce packets, encrypted opportunistic LXMF DATA, and Link handshake (LINKREQUEST + LRPROOF + derived session keys) — are not yet populated. See [`agent.md`](agent.md) §5 and [`todo.md`](todo.md) for the remaining bootstrap work.

An implementation that round-trips every test vector — both directions — should be wire-compatible with upstream Reticulum and LXMF for the covered operations.

---

## 19. Source map

Upstream Python sources, in rough order of frequency-of-reference:

| File | What lives here |
|---|---|
| `RNS/Identity.py` | Key generation, `to_file`/`from_file`, `validate_announce`, `recall` |
| `RNS/Destination.py` | `expand_name`, `name_hash`, destination hash construction |
| `RNS/Packet.py` | Header pack/unpack, packet types, contexts, `prove` |
| `RNS/Transport.py` | `outbound`, `inbound`, `request_path`, path table, HEADER_1↔2 |
| `RNS/Link.py` | Link establishment, LRPROOF, session-key derivation |
| `RNS/Cryptography/Token.py` | The Fernet-style Token format |
| `RNS/vendor/umsgpack.py` | The bundled msgpack with locked bin/str semantics |
| `RNS/Interfaces/TCPInterface.py` | TCPClient/TCPServer, including HDLC framing |
| `LXMF/LXMessage.py` | LXMF body pack/unpack, opportunistic vs link methods |
| `LXMF/LXMF.py` | `display_name_from_app_data`, `stamp_cost_from_app_data`, etc. |
| `LXMF/LXMRouter.py` | Delivery destination registration, announce-app-data assembly |

When upstream code changes such that this document drifts, please open a PR.
