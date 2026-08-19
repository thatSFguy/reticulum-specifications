"""
Verifier for SPEC.md §5.8 (propagation-node request paths and error responses).

Loads upstream `LXMF.LXMPeer` and `LXMF.LXMRouter` and confirms that the
request-path strings and the `ERROR_*` response bytes match the values §5.8.1
and §5.8.2 put on the wire. Both are protocol surface: a peer or client sees
the path string in the REQUEST and the error byte in the RESPONSE, so a
renumber upstream is a wire-format change even though nothing in the packet
layout moves.

This verifier exists because nothing covered these constants until 2026-08-19.
§5.8.2 shipped `ERROR_THROTTLED = 0xf2` and `ERROR_NOT_FOUND = 0xf5` from the
section's introduction; upstream has used 0xf6 and 0xfd since at least LXMF
0.9.7, and allocates 0xf5 to `ERROR_INVALID_STAMP`. `verify_lxmf_fields.py`
covers `LXMF.LXMF` (`FIELD_*`, `PN_META_*`, …) but never touched `LXMPeer` or
the `LXMRouter` control paths, so the bad values survived every prior sync.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import sys

from LXMF.LXMPeer import LXMPeer
from LXMF.LXMRouter import LXMRouter


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


# §5.8.2 error-response table. Note the values are NOT contiguous: upstream
# allocates no constant at 0xf2, and jumps 0xf6 -> 0xfd. Implementations must
# use these literals rather than deriving them from an enumeration order.
EXPECTED_ERRORS = {
    "ERROR_NO_IDENTITY":   0xF0,
    "ERROR_NO_ACCESS":     0xF1,
    "ERROR_INVALID_KEY":   0xF3,
    "ERROR_INVALID_DATA":  0xF4,
    "ERROR_INVALID_STAMP": 0xF5,
    "ERROR_THROTTLED":     0xF6,
    "ERROR_NOT_FOUND":     0xFD,
    "ERROR_TIMEOUT":       0xFE,
}

# The byte §5.8.2 documents as unallocated. Asserted explicitly because the
# spec makes a positive claim about the gap, not just about the eight values.
UNALLOCATED_ERROR_BYTES = {0xF2}

# §5.8.1 request paths, split across the two destinations that carry them.
# `/offer` and `/get` are registered on the `lxmf.propagation` destination
# (ALLOW_ALL); the control paths live on the separate `lxmf.propagation.control`
# destination (ALLOW_LIST, restricted to the node operator's own identity).
EXPECTED_PROPAGATION_PATHS = {
    (LXMPeer, "OFFER_REQUEST_PATH"): "/offer",
    (LXMPeer, "MESSAGE_GET_PATH"):   "/get",
}

EXPECTED_CONTROL_PATHS = {
    (LXMRouter, "STATS_GET_PATH"):      "/pn/get/stats",
    (LXMRouter, "SYNC_REQUEST_PATH"):   "/pn/peer/sync",
    (LXMRouter, "UNPEER_REQUEST_PATH"): "/pn/peer/unpeer",
}


def verify_errors() -> None:
    print("== LXMPeer.ERROR_* (propagation-node error responses) ==")
    for name, want in EXPECTED_ERRORS.items():
        got = getattr(LXMPeer, name, None)
        if got is None:
            fail(f"upstream LXMF.LXMPeer is missing constant `{name}` — spec §5.8.2 tables it")
        if got != want:
            fail(
                f"upstream `LXMPeer.{name}` = 0x{got:02x}, spec §5.8.2 says 0x{want:02x}. "
                "Either upstream renumbered (update the §5.8.2 table AND this verifier, and "
                "add a README errata — peers already on the wire will disagree) or the spec "
                "is wrong."
            )
        print(f"  {name:<21s} = 0x{got:02x}  (matches spec)")


def verify_error_gap() -> None:
    print("== unallocated error bytes ==")
    in_use = {
        getattr(LXMPeer, a) for a in dir(LXMPeer)
        if a.startswith("ERROR_") and isinstance(getattr(LXMPeer, a), int)
    }
    for byte in sorted(UNALLOCATED_ERROR_BYTES):
        if byte in in_use:
            offenders = sorted(
                a for a in dir(LXMPeer)
                if a.startswith("ERROR_") and getattr(LXMPeer, a) == byte
            )
            fail(
                f"spec §5.8.2 documents 0x{byte:02x} as unallocated, but upstream now uses it "
                f"for {', '.join(offenders)}. Update the §5.8.2 table and drop the gap note."
            )
        print(f"  0x{byte:02x} unallocated  (matches spec)")


def verify_paths(label: str, expected: dict[tuple[type, str], str]) -> None:
    print(f"== {label} ==")
    for (cls, name), want in expected.items():
        got = getattr(cls, name, None)
        if got is None:
            fail(f"upstream {cls.__name__} is missing `{name}` — spec §5.8.1 tables it")
        if got != want:
            fail(
                f"upstream `{cls.__name__}.{name}` = {got!r}, spec §5.8.1 says {want!r}. "
                "The path string is on the wire in the REQUEST; update §5.8.1 and this verifier."
            )
        print(f"  {cls.__name__}.{name:<19s} = {got!r}  (matches spec)")


def verify_no_unknown_constants() -> None:
    """Fail if upstream adds an ERROR_* response or a request-path constant that
    §5.8 doesn't enumerate. This is the check that would have caught the missing
    ERROR_INVALID_STAMP allocation."""
    print("== unknown-constant audit ==")

    for attr in dir(LXMPeer):
        if not attr.startswith("ERROR_"):
            continue
        val = getattr(LXMPeer, attr)
        if not isinstance(val, int):
            continue
        if attr not in EXPECTED_ERRORS:
            fail(
                f"upstream `LXMPeer.{attr}` = 0x{val:02x} is not enumerated in spec §5.8.2. "
                "Add it to the error table and to this verifier."
            )

    # Request paths are the str-valued *_PATH attributes. The int-valued ones
    # (e.g. LXMRouter.PR_NO_PATH, a path-request status byte) are a different
    # namespace and are deliberately out of scope here.
    known_paths = set(EXPECTED_PROPAGATION_PATHS) | set(EXPECTED_CONTROL_PATHS)
    for cls in (LXMPeer, LXMRouter):
        for attr in dir(cls):
            if not attr.endswith("_PATH"):
                continue
            val = getattr(cls, attr)
            if not isinstance(val, str):
                continue
            if (cls, attr) not in known_paths:
                fail(
                    f"upstream `{cls.__name__}.{attr}` = {val!r} is not enumerated in spec "
                    "§5.8.1. Document the handler and add it to this verifier."
                )

    print("  (no unknown ERROR_* or *_PATH constants)")


def main() -> None:
    verify_errors()
    verify_error_gap()
    verify_paths("lxmf.propagation request paths (ALLOW_ALL)", EXPECTED_PROPAGATION_PATHS)
    verify_paths("lxmf.propagation.control request paths (ALLOW_LIST)", EXPECTED_CONTROL_PATHS)
    verify_no_unknown_constants()
    print()
    print("PASS")


if __name__ == "__main__":
    main()
