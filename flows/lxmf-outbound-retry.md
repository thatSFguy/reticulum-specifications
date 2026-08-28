# Flow: LXMF outbound retry loop and per-message state machine

What `LXMRouter.process_outbound` actually does on each tick — the layer that wraps [`send-opportunistic-lxmf.md`](send-opportunistic-lxmf.md), [`send-link-lxmf.md`](send-link-lxmf.md), and [`send-propagated-lxmf.md`](send-propagated-lxmf.md) and decides when each happy-path operation runs, retries, gives up, or falls through.

The three send-* flows describe what happens for *one* attempt of each method. This doc describes how attempts are scheduled, how the per-message state advances, and when a message moves from retry-eligible to terminally `FAILED`. It is the missing piece for any client that wants delivery semantics matching upstream Sideband.

Pinned against **RNS 1.5.0 / LXMF 1.1.1**. Line numbers below are from those versions.

---

## Cadence: how often process_outbound runs

`LXMRouter.jobloop` (`LXMF/LXMRouter.py:912-921` → `def jobloop(self)`) is a daemon thread that wakes every `PROCESSING_INTERVAL` seconds and calls `LXMRouter.jobs`, which dispatches to `process_outbound` whenever its tick counter is divisible by `JOB_OUTBOUND_INTERVAL`:

| Constant | Value | File:line |
|---|---|---|
| `PROCESSING_INTERVAL` | `4` (seconds) | `LXMF/LXMRouter.py:31` |
| `JOB_OUTBOUND_INTERVAL` | `1` | `LXMF/LXMRouter.py:871` → `JOB_OUTBOUND_INTERVAL  = 1` |

So the **effective outbound tick is every 4 seconds.** Any per-message timer (path-request defer, retry backoff, link-establish timeout) is sampled at this granularity — a 10-second backoff isn't actually 10 seconds, it's "first tick at or after `now + 10s`."

`handle_outbound` also kicks `process_outbound` directly on a fresh thread when a new message is queued (`LXMF/LXMRouter.py:1793` → `threading.Thread(target=self.process_outbound, daemon=True).start()`), so the first attempt doesn't wait for the next jobloop tick.

---

## Constants that drive retry behavior

All on `LXMRouter`, all module-cited (`LXMF/LXMRouter.py:30-38` → `MAX_DELIVERY_ATTEMPTS = 5`):

| Constant | Value | Meaning |
|---|---|---|
| `MAX_DELIVERY_ATTEMPTS` | `5` | Per-message attempt cap. Crossing this triggers `fail_message`. |
| `DELIVERY_RETRY_WAIT` | `10` (seconds) | Wait between attempts when path is known but the prior attempt didn't yield delivery proof. |
| `PATH_REQUEST_WAIT` | `7` (seconds) | Wait after issuing a `path?` request before the next attempt. |
| `MAX_PATHLESS_TRIES` | `1` | OPPORTUNISTIC only — number of attempts before forcing a path request. |
| `MESSAGE_EXPIRY` | `30*24*60*60` (30 days) | Used by propagation-node store cleanup, not the per-message retry path. |
| `LINK_MAX_INACTIVITY` | `10*60` | Direct-link idle teardown threshold (`clean_links`). |
| `P_LINK_MAX_INACTIVITY` | `3*60` | Propagation-link idle teardown threshold. |

A full single-message retry budget for DIRECT or PROPAGATED is therefore **5 attempts × 10 seconds ≈ 50 seconds of wall-clock** before `fail_message` runs, plus whatever each attempt itself spends inside the link-establishment / proof-wait window.

---

## Per-message state machine

States from `LXMF/LXMessage.py:13-22`:

| State | Value | When |
|---|---|---|
| `GENERATING` | `0x00` | Stamp generation in progress (deferred-stamp messages only) |
| `OUTBOUND` | `0x01` | Queued in `pending_outbound`; not currently transmitting |
| `SENDING` | `0x02` | A send is in flight on the wire (packet sent / Resource transferring) |
| `SENT` | `0x04` | Wire send completed, but no end-to-end PROOF yet — also the **terminal** state for PROPAGATED (delivery to the recipient is the propagation node's job) |
| `DELIVERED` | `0x08` | End-to-end PROOF received from the final recipient — only reachable for OPPORTUNISTIC and DIRECT |
| `REJECTED` | `0xFD` | Receiver explicitly rejected (e.g. stamp validation failed on a propagation node) |
| `CANCELLED` | `0xFE` | Sender called `LXMessage.cancel` while still queued |
| `FAILED` | `0xFF` | `MAX_DELIVERY_ATTEMPTS` exhausted, or unrecoverable error |

The valid-method enum is `LXMessage.OPPORTUNISTIC = 0x01`, `DIRECT = 0x02`, `PROPAGATED = 0x03`, `PAPER = 0x05` (`LXMF/LXMessage.py:29-32`).

---

## Per-tick decision tree

`process_outbound` (`LXMF/LXMRouter.py:2682`) holds `outbound_processing_lock` across the whole tick (`:2683-2684` → `with self.outbound_processing_lock`) and walks `pending_outbound` once. For each message, the top-of-loop branches on terminal state first:

| Branch | File:line | Effect |
|---|---|---|
| `state == DELIVERED` | 2517-2542 | Remove from queue. If method was DIRECT, perform backchannel-identify on the link so the recipient can reply over the same link. |
| `method == PROPAGATED and state == SENT` | 2544-2546 | Remove from queue (PROPAGATED's terminal success state is SENT, not DELIVERED — see state table). |
| `state == CANCELLED` | 2548-2552 | Remove and fire `failed_callback`. |
| `state == REJECTED` | 2554-2558 | Remove and fire `failed_callback`. |
| Else (`OUTBOUND` or `SENDING`) | 2560+ | Per-method retry/send branch — see below. |

The non-terminal branch in turn switches on `lxmessage.method`:

### OPPORTUNISTIC branch (`LXMF/LXMRouter.py:2735-2764` → `if lxmessage.method == LXMessage.OPPORTUNISTIC`)

```python
if lxmessage.method == LXMessage.OPPORTUNISTIC:
    if lxmessage.delivery_attempts <= LXMRouter.MAX_DELIVERY_ATTEMPTS:
        if lxmessage.delivery_attempts >= LXMRouter.MAX_PATHLESS_TRIES \
                and not RNS.Transport.has_path(lxmessage.get_destination().hash):
            # Force a path request, defer PATH_REQUEST_WAIT seconds
            ...
            lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
        elif lxmessage.delivery_attempts == LXMRouter.MAX_PATHLESS_TRIES + 1 \
                and RNS.Transport.has_path(...):
            # Path is known but prior attempt failed — drop_path + re-discover
            RNS.Reticulum.get_instance().drop_path(...)
            ...
            lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
        else:
            if not hasattr(lxmessage, "next_delivery_attempt") \
                    or time.time() > lxmessage.next_delivery_attempt:
                lxmessage.delivery_attempts += 1
                lxmessage.next_delivery_attempt = time.time() + LXMRouter.DELIVERY_RETRY_WAIT
                lxmessage.send()
    else:
        self.fail_message(lxmessage)
```

Key behaviors:
- **First attempt is "pathless-tolerant":** if `delivery_attempts < MAX_PATHLESS_TRIES (=1)` and there's no path, the message still tries a send (relying on `handle_outbound`'s pre-emptive `path?` at `LXMF/LXMRouter.py:1777-1781`).
- **After the pathless tries are exhausted,** an explicit `path?` is fired and the message defers `PATH_REQUEST_WAIT (=7s)`.
- **The `MAX_PATHLESS_TRIES + 1` case** is the "I have a stale path that didn't deliver" recovery: `Reticulum.drop_path` evicts the bad path table entry, then a fresh `path?` is requested.
- **The `else` branch is the actual retransmit:** increment attempts, schedule `+ DELIVERY_RETRY_WAIT (=10s)`, fire `lxmessage.send()`.
- **`fail_message` runs only after `delivery_attempts > MAX_DELIVERY_ATTEMPTS`** — i.e. attempts 1..5 are tried, attempt 6 trips `fail_message`.

### DIRECT branch (`LXMF/LXMRouter.py:2765-2845` → `elif lxmessage.method == LXMessage.DIRECT`)

Two sub-paths, decided by whether a usable link already exists in `direct_links` or `backchannel_links`:

**Existing link, `status == ACTIVE` (line 2616-2627):**
- If `state != SENDING`, set the link as the delivery destination and call `lxmessage.send()`.
- If `state == SENDING`, just log progress — the prior send is still pending its proof.

**Existing link, `status == CLOSED` (line 2628-2647):**
- If the link was previously activated (`activated_at != None`), the link died unexpectedly — issue a fresh `path?` and schedule `PATH_REQUEST_WAIT`.
- Else (link was never activated — LRPROOF never arrived on the prior attempt), retry the path request once via `path_request_retried`, then schedule `PATH_REQUEST_WAIT`.
- Either way, **drop the dead link from `direct_links` / `backchannel_links`** and schedule the next attempt at `+ DELIVERY_RETRY_WAIT`.

**No link exists (line 2651-2670):**
```python
if not hasattr(lxmessage, "next_delivery_attempt") \
        or time.time() > lxmessage.next_delivery_attempt:
    lxmessage.delivery_attempts += 1
    lxmessage.next_delivery_attempt = time.time() + LXMRouter.DELIVERY_RETRY_WAIT

    if lxmessage.delivery_attempts < LXMRouter.MAX_DELIVERY_ATTEMPTS:
        if RNS.Transport.has_path(lxmessage.get_destination().hash):
            delivery_link = RNS.Link(lxmessage.get_destination())
            delivery_link.set_link_established_callback(self.process_outbound)
            self.direct_links[delivery_destination_hash] = delivery_link
        else:
            RNS.Transport.request_path(lxmessage.get_destination().hash)
            lxmessage.next_delivery_attempt = time.time() + LXMRouter.PATH_REQUEST_WAIT
```

The `set_link_established_callback(self.process_outbound)` re-entry is what lets the next tick after a successful LRPROOF immediately enter the "existing ACTIVE link" branch and fire `send()` — see [`send-link-lxmf.md`](send-link-lxmf.md) §2 for why this works.

`fail_message` runs at line 2671-2673 once `delivery_attempts > MAX_DELIVERY_ATTEMPTS`.

### PROPAGATED branch (`LXMF/LXMRouter.py:2846-2899` → `elif lxmessage.method == LXMessage.PROPAGATED`)

Structurally mirrors DIRECT but against `outbound_propagation_link` / `outbound_propagation_node` instead of per-recipient direct links. Two early failures:

- `outbound_propagation_node == None` → immediate `fail_message` (`:2849-2851` → `if self.outbound_propagation_node == None`). LXMF will not attempt PROPAGATED without an explicitly configured node — there is **no automatic fallback** from DIRECT/OPPORTUNISTIC to PROPAGATED. Sideband configures one via `LXMRouter.set_outbound_propagation_node` at startup; a clean-room client must do the same before the user picks PROPAGATED.
- All `MAX_DELIVERY_ATTEMPTS` exhausted → `fail_message` (`:2884-2899`).

Otherwise the link-state branching is identical to DIRECT: ACTIVE → send / CLOSED → drop and retry / no-link → establish-or-path-request.

---

## The terminal transition: `fail_message`

`LXMF/LXMRouter.py:2564-2578` → `def fail_message(self, lxmessage)`:

```python
def fail_message(self, lxmessage):
    RNS.log(str(lxmessage)+" failed to send", RNS.LOG_DEBUG)

    lxmessage.progress = 0.0
    if lxmessage in self.pending_outbound: self.pending_outbound.remove(lxmessage)
    if lxmessage.state != LXMessage.REJECTED: lxmessage.state = LXMessage.FAILED
    if lxmessage.failed_callback != None and callable(lxmessage.failed_callback):
        lxmessage.failed_callback(lxmessage)
```

A few non-obvious properties:

- `REJECTED` is preserved when present (the receiver explicitly rejected — don't overwrite the reason).
- The message **is removed from `pending_outbound` synchronously**; the `failed_callback` fires on the same thread as `process_outbound`. Callbacks must not block.
- There is **no automatic re-queue or method change** on FAIL. A failed DIRECT message does not get re-tried as PROPAGATED. Apps that want that fallback have to implement it themselves on top of the `failed_callback`.

---

## What does NOT happen

These are common assumptions that don't match upstream behavior. Listed here so reimplementers don't trust their intuition:

- **No automatic DIRECT→PROPAGATED fallback** — see PROPAGATED branch above. The user (or app) chose `desired_method` at message construction time; LXMF never overrides it on failure.
- **No exponential backoff** — `DELIVERY_RETRY_WAIT = 10s` is constant across attempts 1..5.
- **No persistence of `pending_outbound` to disk by default** — pending outbound messages live in process memory. A LXMRouter restart drops them. (Sideband persists messages at the *app* level, not via LXMRouter.)
- **`MESSAGE_EXPIRY` is not a per-message send timeout.** It governs the propagation-node *store* (how long the node retains a message for offline pickup); it does not bound how long a single sender will keep retrying. The retry loop bounds itself via `MAX_DELIVERY_ATTEMPTS`, which at ~10s per attempt is ~50 seconds, not 30 days.
- **`SENT` is not `DELIVERED`.** PROPAGATED reaches `SENT` after the propagation node accepts the message; the recipient may pick it up minutes, hours, or days later. There is no end-to-end delivery proof for PROPAGATED messages until the recipient comes online and emits it (see [`send-propagated-lxmf.md`](send-propagated-lxmf.md) §6).
- **Path-request preamble is OPPORTUNISTIC-only at submit time.** `handle_outbound` only fires the pre-emptive `path?` when `lxmessage.method == OPPORTUNISTIC` (`LXMF/LXMRouter.py:1777`). DIRECT and PROPAGATED rely on `process_outbound`'s no-link branch to discover the path on the first tick.

---

## Source map

| Concern | File | Function / line |
|---|---|---|
| Class constants | `LXMF/LXMRouter.py` | 30-45 |
| Job interval table | `LXMF/LXMRouter.py` | 871-879 |
| `jobs` dispatcher | `LXMF/LXMRouter.py` | 880-910 |
| `jobloop` daemon | `LXMF/LXMRouter.py` | 912-921 |
| Pre-emptive path request on submit | `LXMF/LXMRouter.py` | 1777-1781 |
| `handle_outbound` thread kick | `LXMF/LXMRouter.py` | 1793 |
| `process_outbound` entry + lock | `LXMF/LXMRouter.py` | 2682-2684 |
| Terminal-state branches (DELIVERED / SENT-PROPAGATED / CANCELLED / REJECTED) | `LXMF/LXMRouter.py` | 2700-2734 |
| OPPORTUNISTIC retry branch | `LXMF/LXMRouter.py` | 2735-2764 |
| DIRECT retry branch | `LXMF/LXMRouter.py` | 2765-2845 |
| PROPAGATED retry branch | `LXMF/LXMRouter.py` | 2846-2899 |
| `fail_message` | `LXMF/LXMRouter.py` | 2564-2578 |
| Message states | `LXMF/LXMessage.py` | 13-22 |
| Delivery methods | `LXMF/LXMessage.py` | 29-33 |
