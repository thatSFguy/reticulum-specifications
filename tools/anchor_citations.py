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

When a file-scope anchor is not unique, the tool falls back to a **symbol-scoped**
anchor, which is strictly more durable than anything carrying a line number:

    before   `RNS/Transport.py:2494`
    after    `RNS/Transport.py::lxmf_propagation` -> `transient_id =`

check_citations.py resolves that by finding the symbol, then searching only its
body, so the snippet only has to be unique *within the function*. There is no
line number left to drift — a move, a reformat, and a change of length upstream
all leave it valid. Prefer this form; it is only second here because it reads
longer, and a line number is genuinely useful for navigation when it is safe.

Fenced-block `# path:line` comments are skipped: they are code, and an arrow
would not survive there.

  python tools/anchor_citations.py            # dry run, prints a summary
  python tools/anchor_citations.py --apply    # rewrite in place

Run `python tools/check_citations.py` afterwards. Every anchor this script
writes is verified by that checker, so a mis-bound anchor fails there.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_citations as cc

MIN_ANCHOR = 16      # shorter than this is rarely distinctive at file scope
MIN_SYM_ANCHOR = 8   # inside one function body, a short snippet is still exact
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


def symbol_anchor(index, abspath, lineno):
    """(symbol, snippet) for `lineno`, scoped to its innermost function.

    Uniqueness only has to hold inside the function body, which is why this
    succeeds on lines that are hopelessly repetitive at file scope — a bare
    `if self.type == Destination.GROUP:` appears in both encrypt and decrypt,
    but exactly once in each.
    """
    lines = index.lines(abspath)
    if lineno > len(lines):
        return None, None
    raw = lines[lineno - 1]
    if RE_TRIVIAL.match(raw) or RE_UNINFORMATIVE.match(raw) or "`" in raw:
        return None, None
    try:
        tree = ast.parse("\n".join(lines))
    except SyntaxError:
        return None, None

    fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= lineno <= end:
                if fn is None or node.lineno > fn.lineno:
                    fn = node
    if fn is None:
        return None, None
    span = (fn.lineno, getattr(fn, "end_lineno", fn.lineno))

    # Only a name check_citations can resolve back to this exact span.
    table = index.symbols(abspath)
    if not (fn.name in table and table[fn.name] == span):
        return None, None

    full = cc.norm(raw)
    candidates = [full[:m.end()] for m in re.finditer(r"\S+", full)
                  if m.end() >= MIN_SYM_ANCHOR]
    if not candidates or candidates[-1] != full:
        candidates.append(full)
    for cand in candidates:
        if len(cand) > MAX_ANCHOR:
            break
        if cc.Checker.looks_like_citation(cand):
            continue
        if cc.find_snippet(index, abspath, cand, span) == [lineno]:
            return fn.name, cand
    return None, None


def advance_range_start(index, abspath, spec):
    """A range citation starting on a blank or structural line points its
    anchor at whitespace. Advance the start to the first meaningful line
    still inside the range — the range covers the same code either way, and
    it becomes anchorable. Single-line citations are left alone: moving one
    changes what is cited, which is a judgement call, not a normalisation.
    """
    nums = cc.parse_line_spec(spec)
    if len(nums) < 2:
        return None
    lo, hi = nums[0], nums[-1]
    lines = index.lines(abspath)
    if lo > len(lines):
        return None
    if not RE_TRIVIAL.match(lines[lo - 1]):
        return None
    for k in range(lo + 1, min(hi, len(lines)) + 1):
        if not RE_TRIVIAL.match(lines[k - 1]):
            return k
    return None


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
    decided, decided_sym, skipped = {}, {}, {}
    for (path, spec), abspath in col.seen.items():
        nums = cc.parse_line_spec(spec)
        if not nums:
            continue
        snippet, reason = anchor_for(index, abspath, nums[0])
        if snippet:
            decided[(path, spec)] = (spec, snippet)
            continue
        if reason == "blank or structural line":
            newlo = advance_range_start(index, abspath, spec)
            if newlo is not None:
                nums2 = cc.parse_line_spec(spec)
                newspec = (spec.replace(str(nums[0]), str(newlo), 1)
                           if newlo < nums2[-1] else str(newlo))
                snippet, _ = anchor_for(index, abspath, newlo)
                if snippet:
                    decided[(path, spec)] = (newspec, snippet)
                    continue
                sym, sym_snip = symbol_anchor(index, abspath, newlo)
                if sym:
                    decided_sym[(path, spec)] = (sym, sym_snip)
                    continue
        # Fall back to a symbol-scoped anchor, which drops the line number
        # entirely. Uniqueness only has to hold inside the function body.
        sym, sym_snip = symbol_anchor(index, abspath, nums[0])
        if sym:
            decided_sym[(path, spec)] = (sym, sym_snip)
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
                if key in decided:
                    newspec, snip = decided[key]
                    head = (f"`{path}:{newspec}`" if m.group("path")
                            else f"`:{newspec}`")
                    out.append((m.start(), m.end(), head + f" → `{snip}`"))
                elif key in decided_sym:
                    sym, snip = decided_sym[key]
                    out.append((m.start(), m.end(),
                                f"`{path}::{sym}` → `{snip}`"))
            if not out:
                continue
            new, cur = "", 0
            for st, e, text in out:
                new += raw[cur:st] + text
                cur = e
                rewritten += 1
            new += raw[cur:]
            lines[i] = new
        if args.apply:
            with open(p, "w", encoding="utf-8") as f:
                f.writelines(lines)

    print(f"{len(col.seen)} distinct line-only / continuation citations")
    print(f"  {len(decided)} anchorable at file scope, "
          f"{len(decided_sym)} as symbol-scoped anchors (no line number), "
          f"{len(skipped)} left for a human")
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
