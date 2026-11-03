"""
Bump-time gate: after a pin change, does every citation still point at the
same upstream text it pointed at before?

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

This compares the SAME citation across two installs:

    old docs @ old pin  ->  source text at the cited line
    new docs @ new pin  ->  source text at the cited line

and requires the two to be identical. A citation that was correct before and is
correct after must satisfy this; one that was silently left behind cannot.

Citations are paired positionally within each document, which is exact because
`check_citations.py --fix` only ever rewrites numbers in place — it never adds
or removes a citation. A document whose citation *count* changed is reported
rather than guessed at: that means a human edited it, and the pairing is no
longer meaningful.

  python tools/check_citation_drift.py \
      --baseline <dir of pre-bump docs> \
      --old-src  <site-packages of the old pin> \
      --new-src  <site-packages of the new pin>

Exit 0 when every citation survived the bump, 1 otherwise.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_citations as cc

REPO_ROOT = cc.REPO_ROOT

RE_CITE = re.compile(r"`(?P<path>[A-Za-z_][\w/]*\.py)?:(?P<lines>\d[\d,\s-]*)`")
RE_FENCE_CITE = re.compile(
    r"^\s*#\s*(?P<path>[A-Za-z_][\w/]*\.py):(?P<lines>\d[\d,\s-]*)\s*$")


def citations(text, positions=False):
    """Ordered (path, linespec) for one document, continuations resolved.

    With positions=True each entry also carries (line_index, start, end) of
    the linespec inside the document, so --fix can rewrite it in place."""
    out, last = [], None
    for i, raw in enumerate(text.splitlines()):
        fm = RE_FENCE_CITE.match(raw)
        if fm:
            last = fm.group("path")
            out.append((last, fm.group("lines").strip(),
                        (i, fm.start("lines"), fm.end("lines"))))
            continue
        for m in RE_CITE.finditer(raw):
            path = m.group("path") or last
            if m.group("path"):
                last = m.group("path")
            if path:
                out.append((path, m.group("lines").strip(),
                            (i, m.start("lines"), m.end("lines"))))
    return out if positions else [(p, s) for p, s, _ in out]


# A line this short ("else:", "return False", blank) occurs all over a file,
# so finding it near the old position proves nothing. Such endpoints borrow
# the shift of a distinctive endpoint in the same citation instead.
TRIVIAL_LEN = 12
SEARCH_WINDOW = 400


def repair(old_tree, new_tree, path, n_old, n_new):
    """New line numbers that put every cited line back on the text it cited
    at the old pin, or None if that cannot be done unambiguously."""
    ap = new_tree.resolve(path)
    if ap is None:
        return None
    new_lines = [cc.norm(l) for l in new_tree.lines(ap)]
    out, deltas = [None] * len(n_old), {}
    for i, (a, b) in enumerate(zip(n_old, n_new)):
        t_old = old_tree.text_at(path, a)
        if t_old is None:
            return None
        if len(t_old) < TRIVIAL_LEN:
            continue
        hits = [j for j in range(max(1, b - SEARCH_WINDOW),
                                 min(len(new_lines), b + SEARCH_WINDOW) + 1)
                if new_lines[j - 1] == t_old]
        if not hits:
            return None
        hits.sort(key=lambda j: abs(j - b))
        if len(hits) > 1 and abs(hits[0] - b) == abs(hits[1] - b):
            return None                  # equidistant: ambiguous
        out[i] = hits[0]
        deltas[i] = hits[0] - b
    for i, (a, b) in enumerate(zip(n_old, n_new)):
        if out[i] is not None:
            continue
        t_old = old_tree.text_at(path, a)
        if deltas:
            near = min(deltas, key=lambda k: abs(k - i))
            cand = b + deltas[near]
            if 1 <= cand <= len(new_lines) and new_lines[cand - 1] == t_old:
                out[i] = cand
                continue
        hits = [j for j in range(max(1, b - 3), min(len(new_lines), b + 3) + 1)
                if new_lines[j - 1] == t_old]
        hits.sort(key=lambda j: abs(j - b))
        if not hits or (len(hits) > 1 and
                        abs(hits[0] - b) == abs(hits[1] - b)):
            return None
        out[i] = hits[0]
    return out


def respec(spec, numbers):
    """Rewrite the numbers in a linespec in order: '151-153' -> '152-154'."""
    it = iter(numbers)
    return re.sub(r"\d+", lambda _m: str(next(it)), spec)


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

    def text_at(self, path, lineno):
        ap = self.resolve(path)
        if ap is None:
            return None
        ls = self.lines(ap)
        if lineno > len(ls):
            return None
        return cc.norm(ls[lineno - 1])


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
                    help="rewrite each drifted citation to the line numbers "
                         "that carry the text it cited at the old pin, where "
                         "that is unambiguous; report the rest")
    args = ap.parse_args()

    old_tree, new_tree = Tree(args.old_src), Tree(args.new_src)

    docs = ["SPEC.md"] + sorted(
        "flows/" + f for f in os.listdir(os.path.join(REPO_ROOT, "flows"))
        if f.endswith(".md"))

    errors, skipped, checked, unpaired = [], 0, 0, []
    fixed_total = 0
    for doc in docs:
        base_path = os.path.join(args.baseline, doc)
        if not os.path.isfile(base_path):
            continue                     # new document; nothing to compare to
        with open(base_path, encoding="utf-8") as f:
            before = citations(f.read())
        with open(os.path.join(REPO_ROOT, doc), encoding="utf-8") as f:
            doc_text = f.read()
        after_pos = citations(doc_text, positions=True)
        after = [(p, sp) for p, sp, _ in after_pos]
        rewrites = []

        # Positional pairing is only exact when nothing but --fix touched the
        # document. Any change to the sequence of cited PATHS means a human
        # edited it, and every comparison after that point would be measuring
        # the edit rather than the bump.
        if len(before) != len(after):
            unpaired.append((doc, f"{len(before)} citations",
                             f"{len(after)} citations"))
            continue
        if [p for p, _ in before] != [p for p, _ in after]:
            unpaired.append((doc, "path sequence A", "path sequence B"))
            continue

        for k, ((p_old, s_old), (p_new, s_new)) in enumerate(zip(before, after)):
            if p_old != p_new:
                unpaired.append((doc, p_old, p_new))
                break
            n_old = cc.parse_line_spec(s_old)
            n_new = cc.parse_line_spec(s_new)
            if len(n_old) != len(n_new):
                errors.append((doc, p_old, s_old, s_new,
                               "line-count changed", ""))
                continue
            if args.fix and any(
                    old_tree.text_at(p_old, a) is not None
                    and old_tree.text_at(p_old, a) != new_tree.text_at(p_new, b)
                    for a, b in zip(n_old, n_new)):
                fixed = repair(old_tree, new_tree, p_new, n_old, n_new)
                if fixed is not None:
                    rewrites.append((after_pos[k][2], respec(s_new, fixed)))
                    n_new = fixed
            for a, b in zip(n_old, n_new):
                t_old = old_tree.text_at(p_old, a)
                t_new = new_tree.text_at(p_new, b)
                if t_old is None or t_new is None:
                    skipped += 1
                    continue
                checked += 1
                if t_old != t_new:
                    errors.append((doc, p_old, f"{a}", f"{b}",
                                   t_old[:70], t_new[:70]))

        if rewrites:
            doc_lines = doc_text.split("\n")
            # Right to left within a line, so earlier offsets stay valid.
            for (li, st, en), new_spec in sorted(rewrites, reverse=True):
                doc_lines[li] = doc_lines[li][:st] + new_spec + doc_lines[li][en:]
            with open(os.path.join(REPO_ROOT, doc), "w", encoding="utf-8") as f:
                f.write("\n".join(doc_lines))
            fixed_total += len(rewrites)

    if args.fix:
        print(f"--fix re-pointed {fixed_total} citation(s) at the text they "
              f"cited before the bump; run check_citations.py to confirm.")
    for doc, a, b in unpaired:
        print(f"  UNPAIRED {doc}: citation sequence changed ({a} -> {b}). "
              f"A human edited this document; re-check it by hand.")
    for doc, path, a, b, t_old, t_new in errors:
        print(f"  DRIFT {doc}: `{path}:{a}` -> `{b}`")
        print(f"        was: {t_old}")
        print(f"        now: {t_new}")

    print(f"\n{checked} citation line(s) compared across the pin change; "
          f"{skipped} unresolvable in one install; "
          f"{len(errors)} drifted, {len(unpaired)} unpaired")
    if errors or unpaired:
        print("FAIL: a citation points at different upstream text than it did "
              "before the bump. --fix cannot see this; it needs a person.")
        return 1
    print("PASS: every citation still points at the text it cited before.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
