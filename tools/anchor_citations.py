"""
Migrates legacy line-only citations in SPEC.md and flows/ to the anchored form.

check_citations.py states the rule this repo works to: **a line number is
generated output, never input.** An anchored citation carries the upstream
text it points at, so the checker can find where that text actually lives and
repair the line number mechanically:

    before   `RNS/Transport.py:162`
    after    `RNS/Transport.py:162` -> `MAX_RANDOM_BLOBS = 64`

The difference is not cosmetic. A line-only citation is bounds-checkable and
nothing more, so when upstream moves it keeps resolving — to whatever code now
occupies that line. That is how the RNS 1.5.2 bump left `MAX_RANDOM_BLOBS`
citing `MAX_RECEIPTS = 1024` with CI green. An anchored citation instead
splits the two cases that a bare line number collapses into one:

  - upstream MOVED the code  -> --fix re-anchors it, no human needed
  - upstream CHANGED the code -> hard error, --fix refuses; a human must look

This script only proposes anchors it can prove are unambiguous: the snippet
must occur in exactly one line of the pinned file, the way find_snippet()
matches. Citations whose line is blank, structural (`else:`, a decorator, a
closing bracket), or whose text repeats in the file are left alone and
reported — those need a human, and many of them want a `path::symbol`
citation instead, which carries no line number at all.

Fenced-block `# path:line` comments are skipped: they are code, and an arrow
would not survive there.

  python tools/anchor_citations.py            # dry run, prints a summary
  python tools/anchor_citations.py --apply    # rewrite in place

Run `python tools/check_citations.py` afterwards. Every anchor this script
writes is verified by that checker, so a mis-bound anchor fails there.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_citations as cc

MIN_ANCHOR = 16      # shorter than this is rarely distinctive
MAX_ANCHOR = 70      # keep prose readable; find_snippet matches on substring

# A line that carries no distinguishing content of its own.
RE_TRIVIAL = re.compile(
    r"^\s*(else:|try:|finally:|pass|return|continue|break|@\w+|[)\]}]+,?)?\s*$")

# An except-clause is never what a spec claim is about. Anchoring one is
# mechanically valid but cements an uninformative target, so leave these
# line-only for a human — they usually want their range start moved, or a
# `path::symbol` citation instead.
RE_UNINFORMATIVE = re.compile(r"^\s*except\b")


def anchor_for(index, abspath, lineno):
    """Shortest unambiguous snippet for `lineno`, or (None, reason)."""
    lines = index.lines(abspath)
    if lineno > len(lines):
        return None, "out of range"
    raw = lines[lineno - 1]
    if RE_TRIVIAL.match(raw):
        return None, "blank or structural line"
    if RE_UNINFORMATIVE.match(raw):
        return None, "uninformative line (except-clause)"
    if "`" in raw:
        return None, "line contains a backtick"

    full = cc.norm(raw)
    if not full:
        return None, "blank or structural line"

    # Grow the prefix on word boundaries until it matches this line alone.
    candidates = []
    for m in re.finditer(r"\S+", full):
        end = m.end()
        if end >= MIN_ANCHOR:
            candidates.append(full[:end])
    if not candidates or candidates[-1] != full:
        candidates.append(full)

    for cand in candidates:
        if len(cand) > MAX_ANCHOR:
            break
        if cc.Checker.looks_like_citation(cand):
            continue
        hits = cc.find_snippet(index, abspath, cand)
        if hits == [lineno]:
            return cand, None
    # Nothing short enough was unique; say which problem it was.
    hits = cc.find_snippet(index, abspath, full[:MAX_ANCHOR])
    if len(hits) > 1:
        return None, "text repeats in the file"
    return None, "no unambiguous snippet under the length cap"


class Collector(cc.Checker):
    """Reuses the real document walk to find LINE / CONTINUATION citations."""

    def __init__(self, index):
        super().__init__(index)
        self.seen = {}

    def check_anchored(self, *a, **k):
        return

    def check_symbol(self, *a, **k):
        return

    def check_lines(self, doc, n, path, spec, kind="line"):
        abspath = self.index.resolve(path)
        if abspath:
            self.seen[(path, spec)] = abspath
        return abspath


RE_FENCE = re.compile(r"^\s*```")
ARROWED = re.compile(r"\s*(?:→|->)\s*`")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    index = cc.SourceIndex()
    col = Collector(index)
    targets = ["SPEC.md"] + sorted(
        "flows/" + f for f in os.listdir(os.path.join(cc.REPO_ROOT, "flows"))
        if f.endswith(".md"))
    for t in targets:
        col.check_document(t)

    # Decide an anchor once per (path, spec); the first cited line is the one
    # check_anchored measures drift from, and it shifts the rest of the range.
    decided, skipped = {}, {}
    for (path, spec), abspath in col.seen.items():
        nums = cc.parse_line_spec(spec)
        if not nums:
            continue
        snippet, reason = anchor_for(index, abspath, nums[0])
        if snippet:
            decided[(path, spec)] = snippet
        else:
            skipped[(path, spec)] = reason

    rewritten = 0
    already = 0
    for doc in targets:
        p = os.path.join(cc.REPO_ROOT, doc)
        with open(p, encoding="utf-8") as f:
            lines = f.read().splitlines(keepends=True)
        in_fence = False
        last_path = None
        for i, raw in enumerate(lines):
            if RE_FENCE.match(raw):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            out, pos = [], 0
            for m in re.finditer(
                    r"`(?P<path>[A-Za-z_][\w/]*\.py)?:(?P<lines>\d[\d,\s-]*)`", raw):
                path = m.group("path") or last_path
                if m.group("path"):
                    last_path = m.group("path")
                if path is None:
                    continue
                if ARROWED.match(raw[m.end():]):
                    already += 1
                    continue
                key = (path, m.group("lines"))
                if key not in decided:
                    continue
                out.append((m.start(), m.end(), decided[key]))
            if not out:
                continue
            new, cur = "", 0
            for s, e, snip in out:
                new += raw[cur:e] + f" → `{snip}`"
                cur = e
                rewritten += 1
            new += raw[cur:]
            lines[i] = new
        if args.apply:
            with open(p, "w", encoding="utf-8") as f:
                f.writelines(lines)

    print(f"{len(col.seen)} distinct line-only / continuation citations")
    print(f"  {len(decided)} anchorable, {len(skipped)} left for a human")
    reasons = {}
    for r in skipped.values():
        reasons[r] = reasons.get(r, 0) + 1
    for r, c in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"      {c:4d}  {r}")
    print(f"\n{rewritten} citation site(s) "
          f"{'rewritten' if args.apply else 'would be rewritten'}; "
          f"{already} already anchored")
    if not args.apply:
        print("\n(dry run — pass --apply to write)")


if __name__ == "__main__":
    main()
