# Flows

End-to-end chronological narratives for common Reticulum operations. Where [`SPEC.md`](../SPEC.md) is organized by *layer* (identity, header, token crypto, announce, LXMF, link, transport, framing), the documents here are organized by *operation* and walk through what each layer contributes in order — app-call → wire bytes.

The two views are complementary: SPEC.md tells you what each piece looks like; the flows tell you when each piece runs and what calls what. A flow document should not introduce new normative claims — every byte-level detail should be a cross-reference to the relevant SPEC.md section. If you find yourself describing wire bytes here that aren't in SPEC.md, that's a sign the spec has a gap to fill.

## Status

| Flow | Status |
|---|---|
| [`send-opportunistic-lxmf.md`](send-opportunistic-lxmf.md) | ✅ |
| [`receive-opportunistic-lxmf.md`](receive-opportunistic-lxmf.md) | ✅ |
| [`send-link-lxmf.md`](send-link-lxmf.md) (DIRECT method, over a Reticulum Link) | ✅ |
| [`receive-announce.md`](receive-announce.md) | ✅ |
| `receive-link-lxmf.md` (inverse of send-link-lxmf, including responder side of the handshake) | ⏳ |
| `send-propagated-lxmf.md` (PROPAGATED method, via a propagation node) | ⏳ |
| `send-announce.md` (build, sign, transmit, ratchet rotation, periodic re-announce) | ⏳ |
| `forward-announce.md` (transport-node rebroadcast logic, announce_cap, queue) | ⏳ |
| `path-discovery.md` (path? request, path-response wire detail, path-table population) | ⏳ |
| `send-resource.md` (Resource fragmentation over a Link) | ⏳ |

## Conventions

- Each flow targets one specific upstream operation. `send-opportunistic-lxmf.md` documents what `LXMRouter.handle_outbound(lxm)` does for an opportunistic message; it does not also cover Link or propagation paths — those get their own docs so the chronology stays linear.
- Numbered steps are chronological. Each step that produces wire bytes cross-references the SPEC.md section that defines those bytes.
- Source citations use the standard `pip install rns lxmf` install layout (`RNS/`, `LXMF/`) with file + line. Line numbers are pinned to the RNS / LXMF version named at the top of each flow; out-of-date line numbers should be fixed in a PR.
- "Verified" claims must be backed by a `tools/` script per [`../agent.md`](../agent.md) §1. Flow docs inherit the verification status of the SPEC.md sections they reference — if a flow step relies on an unverified SPEC.md callout, the flow should mark that step as inheriting the unverified status rather than silently treat it as fact.
