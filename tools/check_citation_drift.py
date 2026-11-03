"""
Bump-time gate: after a pin change, does every citation still point at the
same upstream code it pointed at before?

check_citations.py cannot answer this, by construction:

  - a LINE-only citation is bounds-checked, so a stale line number that still
    exists in the new version resolves happily — pointing at whatever code now
    occupies it;
  - an ANCHORED RANGE is satisfied by its anchor appearing anywhere inside the
    range, so a range whose start has drifted still passes.

Both failed silently on the RNS 1.5.0 -> 1.5.2 bump: 36 citations kept 1.5.0
line numbers and 15 anchored ranges kept stale starts, with a green check on
every one. `Transport.py:133` was `PATH_REQUEST_GRACE = 0.4` in 1.5.0 and is a
blank line in 1.5.2.

How it decides
--------------
Each cited upstream file is diffed between the two installs, which maps every
unchanged old line to exactly one new line. A cited line number must move
through that map: old line L becomes M(L), and nothing else is correct.

This replaced comparing the *text* at the two line numbers. Text comparison
is fooled by repeated lines — `else:`, `return False`,
`self.fail_message(lxmessage)` — and on the RNS 1.5.7 / LXMF 1.2.1 bump that
let a text-matching repair write `LXMRouter.py:2989-2893` (an inverted range)
and `LXMessage.py:421-421` (a seven-line range collapsed to one), both passing
this gate. A diff map cannot confuse two identical lines, because it maps
positions, not contents.

A cited line that upstream CHANGED has no image under the map. That is
reported for a person: the code the spec cites is not the code it cited.

Pairing citations across the two versions of a document is done the same way:
the documents are diffed with every citation number masked, so lines that
only had numbers rewritten pair up, and a line a person edited is reported
rather than mis-paired. (Pairing used to be positional over the whole
document, which gave up on any document with a hand edit anywhere.)

  python tools/check_citation_drift.py \\
      --baseline <dir of pre-bump docs> \\
      --old-src  <site-packages of the old pin> \\
      --new-src  <site-packages of the new pin> [--fix]

--fix rewrites each citation to its image under the map. An endpoint on a
changed line takes the shift of the nearest unchanged line inside the same
range, and is still reported, so a person confirms it.

Exit 0 when every citation survived the bump, 1 otherwise.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_citations as cc

REPO_ROOT = cc.REPO_ROOT

RE_CITE = re.compile(r"`(?P<path>[A-Za-z_][\w/]*\.py)?:(?P<lines>\d[\d,\s-]*)`")
RE_FENCE_CITE = re.compile(
    r"^(?P<pre>\s*#\s*)(?P<path>[A-Za-z_][\w/]*\.py):(?P<lines>\d[\d,\s-]*)\s*$")


RE_VERSION = re.compile(r"\b(RNS|LXMF|NomadNet)\s+`?\d+\.\d+\.\d+`?")


def doc_citations(text):
    """Per document line: list of (path, linespec, start, end), with
    continuation paths resolved from the most recent explicit path."""
    out, last = [], None
    for raw in text.split("\n"):
        row = []
        fm = RE_FENCE_CITE.match(raw)
        if fm:
            last = fm.group("path")
            row.append((last, fm.group("lines").strip(),
                        fm.start("lines"), fm.end("lines")))
        else:
            for m in RE_CITE.finditer(raw):
                path = m.group("path") or last
                if m.group("path"):
                    last = m.group("path")
                if path:
                    row.append((path, m.group("lines").strip(),
                                m.start("lines"), m.end("lines")))
        out.append(row)
    return out


def masked(line):
    """The document line with citation numbers hidden, for pairing."""
    line = RE_FENCE_CITE.sub(lambda m: f"{m.group('pre')}{m.group('path')}:#", line)
    line = RE_CITE.sub(lambda m: f"`{m.group('path') or ''}:#`", line)
    # check_citations.py --fix rewrites pin claims ("in RNS 1.5.7") on a bump
    # too; that is not a hand edit.
    return RE_VERSION.sub(lambda m: f"{m.group(1)} #", line)


class Tree:
    """Resolves a citation path inside one install root (site-packages)."""

    def __init__(self, root):
        self.root = root
        self._files = {}
        self._by_base = None

    def _bases(self):
        if self._by_base is None:
            self._by_base = {}
            for pkg in ("RNS", "LXMF", "nomadnet"):
                base = os.path.join(self.root, pkg)
                for dp, _dn, fns in os.walk(base):
                    for fn in fns:
                        if fn.endswith(".py"):
                            self._by_base.setdefault(fn, []).append(
                                os.path.join(dp, fn))
        return self._by_base

    def resolve(self, path):
        if "/" in path:
            p = os.path.join(self.root, *path.split("/"))
            return p if os.path.isfile(p) else None
        hits = self._bases().get(path, [])
        return hits[0] if len(hits) == 1 else None

    def lines(self, abspath):
        if abspath not in self._files:
            with open(abspath, encoding="utf-8", errors="replace") as f:
                self._files[abspath] = f.read().splitlines()
        return self._files[abspath]


class LineMap:
    """old line number -> new line number, for lines unchanged by the bump."""

    def __init__(self, old_lines, new_lines):
        self.n_old, self.n_new = len(old_lines), len(new_lines)
        self.map = {}
        sm = difflib.SequenceMatcher(None, [l.rstrip() for l in old_lines],
                                     [l.rstrip() for l in new_lines],
                                     autojunk=False)
        for tag, i1, i2, j1, _j2 in sm.get_opcodes():
            if tag == "equal":
                for k in range(i2 - i1):
                    self.map[i1 + k + 1] = j1 + k + 1

    def image(self, a, lo, hi):
        """(new line, exact?) for old line a cited in the range lo..hi.
        A changed line borrows the shift of the nearest unchanged line inside
        the range; None if the whole range changed."""
        if a in self.map:
            return self.map[a], True
        for d in range(1, hi - lo + 1):
            for c in (a + d, a - d):
                if lo <= c <= hi and c in self.map:
                    return self.map[c] - c + a, False
        return None, False


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", required=True,
                    help="directory holding the pre-bump copies of the docs")
    ap.add_argument("--old-src", required=True,
                    help="site-packages of the OLD pin")
    ap.add_argument("--new-src", required=True,
                    help="site-packages of the NEW pin")
    ap.add_argument("--fix", action="store_true",
                    help="rewrite each citation to its image under the "
                         "old->new source diff")
    args = ap.parse_args()

    old_tree, new_tree = Tree(args.old_src), Tree(args.new_src)
    maps = {}

    def line_map(path):
        if path not in maps:
            a, b = old_tree.resolve(path), new_tree.resolve(path)
            maps[path] = (LineMap(old_tree.lines(a), new_tree.lines(b))
                          if a and b else None)
        return maps[path]

    docs = ["SPEC.md"] + sorted(
        "flows/" + f for f in os.listdir(os.path.join(REPO_ROOT, "flows"))
        if f.endswith(".md"))

    moved, changed, unpaired, inverted = [], [], [], []
    checked = skipped = fixed_total = 0
    for doc in docs:
        base_path = os.path.join(args.baseline, doc)
        if not os.path.isfile(base_path):
            continue                     # new document; nothing to compare to
        with open(base_path, encoding="utf-8") as f:
            old_text = f.read()
        with open(os.path.join(REPO_ROOT, doc), encoding="utf-8") as f:
            new_text = f.read()
        old_lines, new_lines = old_text.split("\n"), new_text.split("\n")
        old_cites, new_cites = doc_citations(old_text), doc_citations(new_text)

        sm = difflib.SequenceMatcher(None, [masked(l) for l in old_lines],
                                     [masked(l) for l in new_lines],
                                     autojunk=False)
        pairs = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                pairs.extend((i1 + k, j1 + k) for k in range(i2 - i1))
            else:
                for j in range(j1, j2):
                    if new_cites[j]:
                        unpaired.append((doc, j + 1))

        rewrites = []
        for i, j in pairs:
            for (p_old, s_old, _, _), (p_new, s_new, st, en) in zip(
                    old_cites[i], new_cites[j]):
                n_old = cc.parse_line_spec(s_old)
                n_new = cc.parse_line_spec(s_new)
                lm = line_map(p_new) if p_old == p_new else None
                if lm is None or len(n_old) != len(n_new):
                    skipped += 1
                    continue
                lo, hi = min(n_old), max(n_old)
                want, exact_all = [], True
                for a in n_old:
                    b, exact = lm.image(a, lo, hi)
                    want.append(b)
                    exact_all &= exact
                if None in want:
                    changed.append((doc, j + 1, p_new, s_old, s_new, "whole range changed upstream"))
                    continue
                checked += len(n_old)
                if any(x > y for x, y in zip(want, want[1:])) and "-" in s_new:
                    inverted.append((doc, j + 1, p_new, s_new))
                if want != n_new:
                    new_spec = re.sub(r"\d+", lambda _m, it=iter(want): str(next(it)), s_new)
                    moved.append((doc, j + 1, p_new, s_new, new_spec))
                    if args.fix:
                        rewrites.append((j, st, en, new_spec))
                if not exact_all:
                    changed.append((doc, j + 1, p_new, s_old, s_new,
                                    "a cited line was changed upstream"))
        if args.fix and rewrites:
            for j, st, en, new_spec in sorted(rewrites, reverse=True):
                new_lines[j] = new_lines[j][:st] + new_spec + new_lines[j][en:]
            with open(os.path.join(REPO_ROOT, doc), "w", encoding="utf-8") as f:
                f.write("\n".join(new_lines))
            fixed_total += len(rewrites)

    if args.fix:
        print(f"--fix re-pointed {fixed_total} citation(s) through the "
              f"old->new source diff")
        moved = []                       # repaired; re-run to confirm
    for doc, n, path, spec in inverted:
        print(f"  INVERTED {doc}:{n}: `{path}:{spec}`")
    for doc, n, path, cur, want in moved:
        print(f"  MOVED   {doc}:{n}: `{path}:{cur}` should be `{want}`")
    for doc, n, path, s_old, s_new, why in changed:
        print(f"  CHANGED {doc}:{n}: `{path}:{s_new}` (was `{s_old}`) — {why}; "
              f"a person must confirm the citation still fits")
    for doc, n in unpaired:
        print(f"  EDITED  {doc}:{n}: line edited by hand, citations not "
              f"compared; check it against the new pin")

    print(f"\n{checked} cited line(s) compared across the pin change; "
          f"{skipped} unresolvable; {len(moved)} moved, {len(changed)} on "
          f"changed upstream code, {len(unpaired)} on hand-edited lines")
    if moved or changed or unpaired or inverted:
        print("FAIL: a citation does not point at the code it cited before "
              "the bump. MOVED is fixable with --fix; the rest need a person.")
        return 1
    print("PASS: every citation still points at the code it cited before.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
