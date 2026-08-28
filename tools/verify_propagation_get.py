"""
Verifier for SPEC.md S5.8.3 (client retrieval via `/get`).

Drives upstream LXMF.LXMRouter's propagation-node handlers directly —
no link, no network — and locks in the three claims S5.8.3 makes about
the retrieval direction:

  1. The `/get` response is a FLAT LIST of LXMF bodies. It is NOT the
     `msgpack.packb([time.time(), [bodies]])` envelope used for the
     upload direction (S5.8.2).

  2. Each served body has had the S5.7 propagation stamp stripped:
     the node stores `lxmf_data || stamp` but serves
     `lxmf_data[:-LXStamper.STAMP_SIZE]`. A retrieved body is the
     pre-stamp propagated form, dest_hash(16) || ciphertext.

  3. `RNS.Identity.full_hash(body_as_received)` reproduces the
     transient_id the node filed the message under, because that id was
     computed before the stamp was appended. This is what makes the
     `have_ids` acknowledge-and-purge round close.

Also checks the negative direction for (1): decoding the response as
the upload envelope must NOT yield a usable [timestamp, [bodies]] pair,
which is the failure an implementer following the old spec text hit.

Exit code 0 on PASS, non-zero on FAIL.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile

import RNS
import LXMF
from LXMF import LXStamper
from LXMF.LXMessage import LXMessage
from LXMF.LXMRouter import LXMRouter, APP_NAME


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def make_body(dest_hash, marker):
    """A stand-in for a propagated LXMF body: dest_hash(16) followed by
    opaque ciphertext. Only its length (>= LXMF_OVERHEAD) and its first
    16 bytes matter to the propagation-node handlers — the node never
    decrypts."""
    filler = marker * ((LXMessage.LXMF_OVERHEAD // len(marker)) + 2)
    return dest_hash + filler


def main():
    print(f"verify_propagation_get.py against RNS {RNS.__version__} / LXMF {LXMF.__version__}")

    cfg_dir  = tempfile.mkdtemp(prefix="rns-verify-pnget-")
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    RNS.Reticulum(configdir=cfg_dir, loglevel=0)

    store_dir = tempfile.mkdtemp(prefix="lxmf-verify-pnget-")
    try:
        router = LXMRouter(storagepath=store_dir)

        # Stand the router up as a propagation node without starting its
        # announce/sync jobs: the two handlers under test read only
        # propagation_node, messagepath and propagation_entries.
        router.propagation_node = True
        router.messagepath      = os.path.join(store_dir, "messagestore")
        os.makedirs(router.messagepath, exist_ok=True)

        # The recipient, and the delivery destination the node keys on.
        client_identity = RNS.Identity()
        client_dest     = RNS.Destination(client_identity, RNS.Destination.OUT,
                                          RNS.Destination.SINGLE, APP_NAME, "delivery")

        bodies = [make_body(client_dest.hash, b"\xa1"),
                  make_body(client_dest.hash, b"\xb2")]

        # Ingest as a propagation node would: transient_id is derived
        # from the body, then the stamp is appended for storage.
        transient_ids = []
        for body in bodies:
            stamp = os.urandom(LXStamper.STAMP_SIZE)
            tid   = RNS.Identity.full_hash(body)
            transient_ids.append(tid)
            if router.lxmf_propagation(body, stamp_value=1, stamp_data=stamp) != True:
                fail("S5.8.3 lxmf_propagation did not accept the test body")

        for tid in transient_ids:
            if tid not in router.propagation_entries:
                fail("S5.8.3 transient_id != full_hash(body) — the node filed the "
                     "message under a different key than the pre-stamp body hash")
        print(f"PASS S5.8.3 node keys its store on full_hash(body) computed "
              f"before the stamp is appended ({len(transient_ids)} messages stored)")

        # Sanity: what is on disk is the stamped form.
        stored_path = router.propagation_entries[transient_ids[0]][1]
        with open(stored_path, "rb") as f:
            stored = f.read()
        if len(stored) != len(bodies[0]) + LXStamper.STAMP_SIZE:
            fail(f"S5.8.3 stored entry is {len(stored)} bytes, want "
                 f"{len(bodies[0]) + LXStamper.STAMP_SIZE} (body + STAMP_SIZE)")
        print(f"PASS S5.8.3 stored form is body || stamp "
              f"(+{LXStamper.STAMP_SIZE} bytes on disk)")

        # --- the retrieval round ---
        response = router.message_get_request(
            "/get", [transient_ids, None], request_id=os.urandom(16),
            remote_identity=client_identity, requested_at=0)

        if not isinstance(response, list):
            fail(f"S5.8.3 /get response is {type(response).__name__}, want list")
        if len(response) != len(bodies):
            fail(f"S5.8.3 /get returned {len(response)} entries, want {len(bodies)}")
        if not all(isinstance(e, bytes) for e in response):
            fail("S5.8.3 /get response elements are not all bytes — the response "
                 "is not a flat list of message bodies")
        print(f"PASS S5.8.3 /get response is a flat list of {len(response)} bodies")

        # Negative: the upload envelope would put a float at [0] and a
        # list at [1]. A flat body list does neither.
        if isinstance(response[0], float) or isinstance(response[0], int):
            fail("S5.8.3 response[0] is a number — the response looks like the "
                 "[timestamp, [bodies]] upload envelope after all")
        if len(response) > 1 and isinstance(response[1], list):
            fail("S5.8.3 response[1] is a list — the response looks like the "
                 "[timestamp, [bodies]] upload envelope after all")
        print("PASS S5.8.3 response is NOT the [timestamp, [bodies]] upload envelope")

        served = dict(zip((RNS.Identity.full_hash(b) for b in response), response))

        for body, tid in zip(bodies, transient_ids):
            if body not in response:
                fail("S5.8.3 a served body does not match the pre-stamp body "
                     "that was ingested — the stamp was not stripped, or was "
                     "stripped at the wrong offset")
            if tid not in served:
                fail("S5.8.3 full_hash(body_as_received) does not reproduce the "
                     "transient_id the node filed the message under — the "
                     "acknowledge-and-purge round cannot close")
        print(f"PASS S5.8.3 served bodies are stamp-stripped "
              f"(-{LXStamper.STAMP_SIZE} bytes, back to the pre-stamp form)")
        print("PASS S5.8.3 full_hash(body_as_received) == the node's transient_id")

        # And the purge round the client builds from those hashes works.
        purge = router.message_get_request(
            "/get", [None, list(served.keys())], request_id=os.urandom(16),
            remote_identity=client_identity, requested_at=0)
        if purge != []:
            fail(f"S5.8.3 purge round returned {purge!r}, want an empty list")
        for tid in transient_ids:
            if tid in router.propagation_entries:
                fail("S5.8.3 purge round did not remove the acknowledged entry")
        print("PASS S5.8.3 have_ids built from those hashes purges the node's store")

    finally:
        try: RNS.Reticulum.exit_handler()
        except Exception: pass
        shutil.rmtree(store_dir, ignore_errors=True)
        shutil.rmtree(cfg_dir, ignore_errors=True)

    print("ALL PASS")


if __name__ == "__main__":
    main()
