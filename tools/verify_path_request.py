"""
Verifier for SPEC.md S7.1, S7.2 (path requests).

Verifies:
  - The well-known path-request destination hash:
        SHA256(SHA256("rnstransport.path.request")[:10])[:16]
        == 6b9f66014d9853faab220fba47d02761
  - The full SPEC table for `name_hash` values.
  - The path-request payload format constructed by upstream
    `RNS.Transport.request_path` (LXMF/LXMRouter.py:1777-1780 calls path):
       transport-disabled (leaf): destination_hash(16) || tag(16)         -> 32B
       transport-enabled         : destination_hash(16) || transport_id(16)
                                   || tag(16)                             -> 48B
  - That LXMF triggers a path? request from `LXMRouter.handle_outbound`
    (line 1777 in LXMF 1.1.0) ONLY when `not has_path(destination_hash) and
    method == OPPORTUNISTIC`. The "always-precedes" claim in older spec drafts
    is too strong: the request is conditional on the path-table miss.
  - The S7.1 retry-loop timing constants on the LXMRouter class
    (LXMF/LXMRouter.py:30-34): PATH_REQUEST_WAIT = 7, DELIVERY_RETRY_WAIT = 10,
    MAX_DELIVERY_ATTEMPTS = 5, MAX_PATHLESS_TRIES = 1.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import hashlib
import inspect
import sys

import RNS
import LXMF
from LXMF.LXMRouter import LXMRouter


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def verify_well_known_hashes():
    cases = [
        ("lxmf.delivery",                   "6ec60bc318e2c0f0d908"),
        ("lxmf.propagation",                "e03a09b77ac21b22258e"),
        ("nomadnetwork.node",               "213e6311bcec54ab4fde"),
        ("nomadnetwork.gossip",             "0ad8bff9ff75737c058e"),
        ("rnstransport.broadcasts",         "9efb9c771eeb5ae90ea6"),
        ("rnstransport.remote.management",  "4848a053c16415bed6c8"),
        ("rnstransport.path.request",       "7926bbe7dd7f9aba88b0"),
    ]
    for name, expected_namehash_hex in cases:
        actual = hashlib.sha256(name.encode("utf-8")).digest()[:10]
        if actual.hex() != expected_namehash_hex:
            fail(f"S1.2 name_hash for {name!r}: "
                 f"got {actual.hex()} want {expected_namehash_hex}")
    print("PASS S1.2 well-known name_hash table")

    # Full path-request dest_hash: SHA256(name_hash || identity_hash)[:16]
    # with identity=None -> identity_hash = b"" (Destination.hash w/ identity=None
    # at RNS/Destination.py:121 has addr_hash_material = name_hash only).
    expected_pr_dest_hash = "6b9f66014d9853faab220fba47d02761"
    namehash = hashlib.sha256(b"rnstransport.path.request").digest()[:10]
    pr_dest_hash = hashlib.sha256(namehash).digest()[:16]
    if pr_dest_hash.hex() != expected_pr_dest_hash:
        fail(f"S7.1 path-request dest_hash: got {pr_dest_hash.hex()} "
             f"want {expected_pr_dest_hash}")
    print("PASS S7.1 path-request dest_hash 6b9f66014d9853faab220fba47d02761")


def verify_request_path_payload_format():
    # Read source — verify the body construction matches the SPEC's claim.
    src = inspect.getsource(RNS.Transport.request_path)
    # transport-disabled: destination_hash + request_tag
    # transport-enabled : destination_hash + Transport.identity.hash + request_tag
    if "destination_hash+request_tag" not in src.replace(" ", ""):
        fail(f"S7.1 transport-disabled payload form not found in request_path source:\n{src}")
    if "destination_hash+Transport.identity.hash+request_tag" not in src.replace(" ", ""):
        fail(f"S7.1 transport-enabled payload form not found in request_path source:\n{src}")
    print("PASS S7.1 request_path payload format "
          "(leaf: dest+tag; transport: dest+xport_id+tag)")


def verify_lxmf_only_when_pathless():
    # Confirm the LXMF outbound path-request is gated on
    # `not has_path(destination_hash) and method == OPPORTUNISTIC`.
    src = inspect.getsource(LXMRouter.handle_outbound)
    if "not RNS.Transport.has_path(destination_hash) and lxmessage.method == LXMessage.OPPORTUNISTIC" not in src:
        fail("S7.1 LXMF path-request gating expression not found in "
             "LXMRouter.handle_outbound — upstream may have changed the rule. "
             f"Source excerpt:\n{src[:2000]}")
    if "Pre-emptively requesting unknown path" not in src:
        fail("S7.1 LXMF 'Pre-emptively requesting unknown path' log line not found "
             "in handle_outbound")
    print(f"PASS S7.1 LXMF {LXMF.__version__}: path? issued only when "
          "has_path()=False AND method=OPPORTUNISTIC "
          "(LXMF/LXMRouter.py handle_outbound)")


def verify_retry_constants():
    # S7.1 timing constants — class-level on LXMRouter (LXMF/LXMRouter.py:30-34).
    expected = {
        "PATH_REQUEST_WAIT": 7,
        "DELIVERY_RETRY_WAIT": 10,
        "MAX_DELIVERY_ATTEMPTS": 5,
        "MAX_PATHLESS_TRIES": 1,
    }
    for name, want in expected.items():
        got = getattr(LXMRouter, name, None)
        if got != want:
            fail(f"S7.1 LXMRouter.{name}: got {got!r} want {want!r} "
                 f"(LXMF {LXMF.__version__}) — upstream changed the retry "
                 "timing; update SPEC.md S7.1 and flows/lxmf-outbound-retry.md")
    print("PASS S7.1 retry constants (PATH_REQUEST_WAIT=7, DELIVERY_RETRY_WAIT=10, "
          "MAX_DELIVERY_ATTEMPTS=5, MAX_PATHLESS_TRIES=1)")


def main():
    print(f"verify_path_request.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")
    verify_well_known_hashes()
    verify_request_path_payload_format()
    verify_lxmf_only_when_pathless()
    verify_retry_constants()
    print("ALL PASS")


if __name__ == "__main__":
    main()
