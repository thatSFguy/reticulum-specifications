"""
Citation checker for SPEC.md and flows/ — resolves source citations against
the pinned upstream install (tools/requirements.txt).

The rule this enforces: **a line number is generated output, never input.**
A citation may carry a verbatim upstream snippet as its anchor; the checker
finds where that snippet actually lives in the pinned source and verifies the
cited line agrees. `--fix` rewrites drifted line numbers in place, so a
version bump becomes "bump the pin, run --fix, review the diff" instead of a
manual re-read of every citation in the document.

Citation forms recognised (all inside backticks, in prose or in a fenced
block as a leading `#` comment):

  ANCHORED       `RNS/Resource.py:199` -> `resource.storagepath = ...`
                 The snippet must appear in the file, whitespace-normalised.
                 If it is not at the cited line, that is drift: reported, and
                 rewritten by --fix. If it appears nowhere, that is a hard
                 error and --fix will not touch it, because the spec is
                 asserting something upstream does not say.

  ANCHORED-SYM   `LXMF/LXMessage.py::get_stamp` -> `RNS.Identity.truncated_hash(...)`
                 Same, but scoped to one symbol's body. No line to drift.

  SYMBOL         `RNS/Packet.py::prove`
                 The symbol must exist in the pinned source.

  LINE           `RNS/Resource.py:199`, `RNS/Resource.py:167-246`,
                 `RNS/Transport.py:2154, 2187, 2198`
                 Legacy form. Only bounds-checkable: every cited line must
                 exist in the file. Counted so the migration to anchored
                 citations is measurable.

  CONTINUATION   `:1549`
                 Bound to the most recent citation earlier in the document.

Also checks that pin declarations in document headers ("Pinned against
**RNS 1.5.0 / LXMF 1.1.1**", "**Last verified against:** ...") match
tools/requirements.txt, and so do inline current-pin claims anywhere in the
text ("... in RNS 1.5.7", "(LXMF 1.2.1)", "verified against RNS 1.5.7",
"upstream LXMF 1.2.1 ..."). Historical statements use "since", "through",
"as of", "≥", "Changed in" or "New in", which are not matched. Files listed in tools/citations-exempt.txt are
allowed to declare a stale pin, with a reason; an exemption that is no
longer needed is itself an error, so the list cannot go stale.

Sources outside the pinned install (NomadNet unless nomadnet is importable,
microReticulum, RNode_Firmware) cannot be resolved here and are counted as
skipped rather than failed.

Exit code 0 when there are no errors, 1 otherwise. --strict promotes
warnings (ambiguous snippets, unresolvable sources) to errors.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from dataclasses import dataclass


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_TARGETS = ["SPEC.md", "flows"]

ARROW = r"(?:→|->)"

RE_ANCHORED = re.compile(
    r"`(?P<path>[A-Za-z_][\w/]*\.py)"
    r"(?::(?P<lines>\d[\d,\s-]*?)|::(?P<symbol>[A-Za-z_][\w.]*))"
    r"`\s*" + ARROW + r"\s*`(?P<snippet>[^`]+)`"
)
RE_SYMBOL = re.compile(
    r"`(?P<path>[A-Za-z_][\w/]*\.py)::(?P<symbol>[A-Za-z_][\w.]*)"
)
RE_LINE = re.compile(
    r"`(?P<path>[A-Za-z_][\w/]*\.py):(?P<lines>\d[\d,\s-]*)`"
)
RE_ANCHORED_CONT = re.compile(
    r"`:(?P<lines>\d[\d,\s-]*)`\s*" + ARROW + r"\s*`(?P<snippet>[^`]+)`"
)
RE_CONTINUATION = re.compile(r"`:(?P<lines>\d[\d,\s-]*)`")
RE_FENCE_COMMENT = re.compile(
    r"^\s*#\s*(?P<path>[A-Za-z_][\w/]*\.py):(?P<lines>\d[\d,\s-]*)\s*$"
)

RE_PIN_DECL = re.compile(r"Pinned against \*\*(?P<body>[^*]+)\*\*")
RE_LAST_VERIFIED = re.compile(r"\*\*Last verified against:\*\*(?P<body>.*)$")
RE_PIN_TOKEN = re.compile(r"\b(RNS|LXMF|NomadNet)\s+`?(\d+\.\d+\.\d+)`?")

# Inline current-pin claims: "`Packet.py:90` ... in RNS 1.5.7", "(RNS 1.5.7)",
# "verified against LXMF 1.2.1", "upstream LXMF 1.2.1 only does ...". These
# assert something about the pinned version as surely as a header does, and a
# bump that rewrites only the header leaves them stale. History is written with
# other words -- "since", "through", "as of", "until", "≥", "Changed in",
# "New in" -- none of which match here. To state a fact about an older version
# that would otherwise match, use one of those.
RE_INLINE_PIN = re.compile(
    r"(?:(?<![Cc]hanged )(?<![Nn]ew )\b[Ii]n\s+|\bagainst\s+(?:\*\*)?"
    r"|\bupstream\s+|\()"
    r"`?(?P<tok>(?P<pkg>RNS|LXMF|NomadNet)\s+`?(?P<ver>\d+\.\d+\.\d+))"
)


def norm(s: str) -> str:
    """Whitespace-normalised form used for all snippet matching."""
    return re.sub(r"\s+", " ", s).strip()


@dataclass
class Finding:
    kind: str          # "error" | "warn" | "info"
    doc: str
    doc_line: int
    message: str
    fixable: bool = False   # True when a matching Fix was recorded


@dataclass
class Fix:
    doc: str
    doc_line: int
    old: str
    new: str


class SourceIndex:
    """Maps a citation path onto a file in the pinned install."""

    def __init__(self):
        self.roots = {}
        for pkg in ("RNS", "LXMF", "nomadnet"):
            try:
                mod = __import__(pkg)
                self.roots[pkg] = os.path.dirname(os.path.abspath(mod.__file__))
            except Exception:
                pass
        self._lines = {}
        self._symbols = {}
        self._basenames = None

    @property
    def available(self):
        return sorted(self.roots)

    def _basename_map(self):
        if self._basenames is None:
            self._basenames = {}
            for root in self.roots.values():
                for dirpath, _dirnames, filenames in os.walk(root):
                    for fn in filenames:
                        if fn.endswith(".py"):
                            self._basenames.setdefault(fn, []).append(
                                os.path.join(dirpath, fn))
        return self._basenames

    def resolve(self, cited_path: str):
        """Citation path -> absolute path in the pinned install, or None."""
        head, _, tail = cited_path.partition("/")
        if tail and head in self.roots:
            candidate = os.path.join(self.roots[head], *tail.split("/"))
            return candidate if os.path.isfile(candidate) else None
        if not tail:
            hits = self._basename_map().get(cited_path, [])
            if len(hits) == 1:
                return hits[0]
        return None

    def lines(self, abspath: str):
        if abspath not in self._lines:
            with open(abspath, "r", encoding="utf-8", errors="replace") as f:
                self._lines[abspath] = f.read().splitlines()
        return self._lines[abspath]

    def symbols(self, abspath: str):
        """qualname -> (start_line, end_line), 1-indexed inclusive."""
        if abspath in self._symbols:
            return self._symbols[abspath]
        table = {}
        try:
            tree = ast.parse("\n".join(self.lines(abspath)))
        except SyntaxError:
            self._symbols[abspath] = table
            return table

        def walk(node, prefix):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                      ast.ClassDef)):
                    qual = f"{prefix}.{child.name}" if prefix else child.name
                    end = getattr(child, "end_lineno", None) or child.lineno
                    table[qual] = (child.lineno, end)
                    walk(child, qual)

        walk(tree, "")
        # Allow citing a method by its bare name when that is unambiguous.
        bare = {}
        for qual, span in table.items():
            bare.setdefault(qual.rsplit(".", 1)[-1], []).append((qual, span))
        for name, entries in bare.items():
            if name not in table and len(entries) == 1:
                table[name] = entries[0][1]
        self._symbols[abspath] = table
        return table


def parse_line_spec(spec: str):
    """'167-246' / '2154, 2187, 2198' -> sorted list of cited line numbers."""
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                lo_i, hi_i = int(lo.strip()), int(hi.strip())
            except ValueError:
                continue
            out.extend([lo_i, hi_i])
        else:
            try:
                out.append(int(part))
            except ValueError:
                continue
    return out


def find_snippet(index: SourceIndex, abspath: str, snippet: str, scope=None):
    """Line numbers whose normalised text contains the normalised snippet."""
    needle = norm(snippet)
    if not needle:
        return []
    lines = index.lines(abspath)
    lo, hi = scope if scope else (1, len(lines))
    hits = []
    for n in range(lo, min(hi, len(lines)) + 1):
        if needle in norm(lines[n - 1]):
            hits.append(n)
    if hits:
        return hits
    # Fall back to a joined window, for snippets spanning a wrapped statement.
    window = 6
    for n in range(lo, min(hi, len(lines)) + 1):
        joined = norm(" ".join(lines[n - 1:n - 1 + window]))
        if needle in joined:
            hits.append(n)
            break
    return hits


SPAN_LIMIT = 200  # max physical lines apply_fixes searches for one fix


def logical_lines(lines):
    """Yield (first_lineno, text) with wrapped citations rejoined.

    Prose wraps, and a blockquote continuation carries a leading "> ", so an
    anchored citation routinely straddles two source lines. Merge forward
    while a backtick span is still open or an arrow is dangling, so the
    citation regexes see one string. Fenced blocks are never merged.
    """
    out = []
    in_fence = False
    i = 0
    while i < len(lines):
        raw = lines[i]
        if raw.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append((i + 1, raw))
            i += 1
            continue
        if in_fence:
            out.append((i + 1, raw))
            i += 1
            continue

        start, text = i, raw
        while i + 1 < len(lines) and not lines[i + 1].lstrip().startswith("```"):
            nxt_body = re.sub(r"^\s*>\s?", "", lines[i + 1])
            unbalanced = text.count("`") % 2 == 1
            dangling = re.search(ARROW + r"\s*$", text.rstrip()) is not None
            leading = re.match(r"^\s*" + ARROW, nxt_body) is not None
            if not (unbalanced or dangling or leading):
                break
            text = text.rstrip() + " " + nxt_body.strip()
            i += 1
        out.append((start + 1, text))
        i += 1
    return out


class Checker:
    def __init__(self, index: SourceIndex, strict: bool = False):
        self.index = index
        self.strict = strict
        self.findings: list[Finding] = []
        self.fixes: list[Fix] = []
        self.counts = {"anchored": 0, "symbol": 0, "line": 0,
                       "continuation": 0, "skipped": 0}

    def err(self, doc, n, msg, fixable=False):
        self.findings.append(Finding("error", doc, n, msg, fixable=fixable))

    def warn(self, doc, n, msg):
        kind = "error" if self.strict else "warn"
        self.findings.append(Finding(kind, doc, n, msg))

    # --- individual citation checks -------------------------------------

    @staticmethod
    def looks_like_citation(snippet):
        """`A.py:1-2` -> `B.py:3-4` is a call-flow arrow between two
        citations, not an anchored citation. An anchor snippet is upstream
        source text; it never contains a citation of its own."""
        return bool(re.search(r"[\w/]+\.py::?\d*", snippet))

    def check_range_order(self, doc, n, path, spec):
        """`2989-2893` is not a range. Nothing downstream rejects it: the
        anchor search simply covers no lines, or the bounds check passes."""
        for part in (spec or "").split(","):
            lo, sep, hi = part.strip().partition("-")
            if sep and lo.strip().isdigit() and hi.strip().isdigit() \
                    and int(lo) > int(hi):
                self.err(doc, n, f"`{path}:{spec}` — inverted range "
                                 f"{lo.strip()}-{hi.strip()}")

    def check_anchored(self, doc, n, path, lines_spec, symbol, snippet, display):
        """Resolve one anchored citation. `display` is the exact backticked
        left-hand side as written, so --fix can rewrite it in place."""
        if self.looks_like_citation(snippet):
            return
        self.check_range_order(doc, n, path, lines_spec)
        abspath = self.index.resolve(path)
        if abspath is None:
            self.counts["skipped"] += 1
            self.warn(doc, n, f"unresolvable source `{path}` (not in the "
                              f"pinned install: {', '.join(self.index.available)})")
            return
        self.counts["anchored"] += 1

        scope = None
        if symbol:
            table = self.index.symbols(abspath)
            if symbol not in table:
                self.err(doc, n, f"`{path}::{symbol}` — symbol not found in "
                                 f"the pinned source")
                return
            scope = table[symbol]

        hits = find_snippet(self.index, abspath, snippet, scope)
        if not hits:
            where = f"::{symbol}" if symbol else ""
            self.err(doc, n,
                     f"`{path}{where}` — anchor snippet not present in the "
                     f"pinned source. The spec is asserting something upstream "
                     f"does not say. Snippet: {norm(snippet)[:90]!r}")
            return

        if not lines_spec:
            return  # symbol-scoped anchor: no line number to drift

        cited = parse_line_spec(lines_spec)
        if not cited:
            return
        if any(c in hits for c in cited) or (
                len(cited) == 2 and any(cited[0] <= h <= cited[1] for h in hits)):
            return  # anchor sits at, or inside, the cited location

        if len(hits) > 1:
            self.warn(doc, n, f"{display} — anchor snippet is ambiguous "
                              f"({len(hits)} matches: "
                              f"{', '.join(map(str, hits[:5]))}); using the "
                              f"nearest to the cited line")
        target = min(hits, key=lambda h: abs(h - cited[0]))
        delta = target - cited[0]
        new_spec = ", ".join(
            "-".join(str(v + delta) for v in parse_line_spec(part))
            if "-" in part else str(parse_line_spec(part)[0] + delta)
            for part in lines_spec.split(",") if part.strip()
        )
        new_display = display.replace(lines_spec, new_spec, 1)
        self.err(doc, n, f"{display} — drifted; the anchor is at line {target}. "
                         f"Should be {new_display} (--fix rewrites this)",
                 fixable=True)
        self.fixes.append(Fix(doc, n, display, new_display))

    def check_symbol(self, doc, n, path, symbol):
        abspath = self.index.resolve(path)
        if abspath is None:
            self.counts["skipped"] += 1
            return
        self.counts["symbol"] += 1
        if symbol not in self.index.symbols(abspath):
            self.err(doc, n, f"`{path}::{symbol}` — symbol not found in the "
                             f"pinned source")

    def check_lines(self, doc, n, path, spec, kind="line"):
        self.check_range_order(doc, n, path, spec)
        abspath = self.index.resolve(path)
        if abspath is None:
            self.counts["skipped"] += 1
            return None
        self.counts[kind] += 1
        total = len(self.index.lines(abspath))
        for cited in parse_line_spec(spec):
            if cited > total:
                self.err(doc, n, f"`{path}:{spec}` — line {cited} is past the "
                                 f"end of the pinned file ({total} lines)")
                break
        return abspath

    # --- document walk ---------------------------------------------------

    def check_document(self, relpath, lines=None):
        if lines is None:
            abs_doc = os.path.join(REPO_ROOT, relpath)
            with open(abs_doc, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()

        last_path = None
        for n, raw in logical_lines(lines):
            fm = RE_FENCE_COMMENT.match(raw)
            if fm:
                self.check_lines(relpath, n, fm.group("path"), fm.group("lines"))
                if self.index.resolve(fm.group("path")):
                    last_path = fm.group("path")
                continue

            # Collect every citation on the line with its offset, then walk
            # them left to right: a `:NNN` continuation binds to the file
            # cited before it, which only works in positional order.
            claimed = []
            events = []

            def overlaps(m):
                return any(m.start() < e and m.end() > s_ for s_, e in claimed)

            for m in RE_ANCHORED.finditer(raw):
                if self.looks_like_citation(m.group("snippet")):
                    continue
                claimed.append((m.start(), m.end()))
                events.append((m.start(), "anchored", m))
            for m in RE_ANCHORED_CONT.finditer(raw):
                if overlaps(m) or self.looks_like_citation(m.group("snippet")):
                    continue
                claimed.append((m.start(), m.end()))
                events.append((m.start(), "anchored_cont", m))
            for rx, kind in ((RE_SYMBOL, "symbol"), (RE_LINE, "line"),
                             (RE_CONTINUATION, "continuation")):
                for m in rx.finditer(raw):
                    if overlaps(m):
                        continue
                    claimed.append((m.start(), m.end()))
                    events.append((m.start(), kind, m))

            for _pos, kind, m in sorted(events, key=lambda e: e[0]):
                if kind == "anchored":
                    self.check_anchored(
                        relpath, n, m.group("path"), m.group("lines"),
                        m.group("symbol"), m.group("snippet"),
                        f"`{m.group('path')}"
                        + (f":{m.group('lines')}" if m.group("lines")
                           else f"::{m.group('symbol')}") + "`")
                    if self.index.resolve(m.group("path")):
                        last_path = m.group("path")
                elif kind == "anchored_cont":
                    if last_path:
                        self.check_anchored(
                            relpath, n, last_path, m.group("lines"), None,
                            m.group("snippet"), f"`:{m.group('lines')}`")
                elif kind == "symbol":
                    self.check_symbol(relpath, n, m.group("path"), m.group("symbol"))
                    if self.index.resolve(m.group("path")):
                        last_path = m.group("path")
                elif kind == "line":
                    self.check_lines(relpath, n, m.group("path"), m.group("lines"))
                    if self.index.resolve(m.group("path")):
                        last_path = m.group("path")
                elif kind == "continuation" and last_path:
                    self.check_lines(relpath, n, last_path, m.group("lines"),
                                     kind="continuation")

    def apply_fixes(self):
        by_doc = {}
        for fix in self.fixes:
            by_doc.setdefault(fix.doc, []).append(fix)
        for doc, fixes in by_doc.items():
            abs_doc = os.path.join(REPO_ROOT, doc)
            with open(abs_doc, "r", encoding="utf-8") as f:
                lines = f.read().splitlines(keepends=True)
            for fix in fixes:
                # fix.doc_line is the FIRST physical line of a logical line
                # (see logical_lines), which can span many physical lines when
                # prose holds an unbalanced backtick, e.g. micron's
                # [label`target]. Search forward through that span; a fix that
                # lands nowhere must not be reported as applied.
                start = fix.doc_line - 1
                for idx in range(start, min(start + SPAN_LIMIT, len(lines))):
                    if fix.old in lines[idx]:
                        lines[idx] = lines[idx].replace(fix.old, fix.new, 1)
                        break
                else:
                    raise RuntimeError(
                        f"{doc}:{fix.doc_line}: --fix could not find "
                        f"{fix.old!r} to rewrite")
            with open(abs_doc, "w", encoding="utf-8") as f:
                f.writelines(lines)
        return len(self.fixes)


# --- pin declarations ----------------------------------------------------

def load_pins():
    pins = {}
    for name in ("requirements.txt", "requirements-docs.txt"):
        path = os.path.join(REPO_ROOT, "tools", name)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if "==" in line:
                    pkg, _, ver = line.partition("==")
                    pins[pkg.strip().lower()] = ver.strip()
    return pins


def load_exemptions():
    path = os.path.join(REPO_ROOT, "tools", "citations-exempt.txt")
    exempt = {}
    if not os.path.isfile(path):
        return exempt
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            doc, _, reason = line.partition(":")
            exempt[doc.strip()] = reason.strip()
    return exempt


def check_pins(checker: Checker, relpath, pins, exempt):
    abs_doc = os.path.join(REPO_ROOT, relpath)
    with open(abs_doc, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    mismatched = False
    for n, raw in enumerate(lines, start=1):
        for rx in (RE_PIN_DECL, RE_LAST_VERIFIED):
            m = rx.search(raw)
            if not m:
                continue
            for tm in RE_PIN_TOKEN.finditer(m.group("body")):
                pkg, ver = tm.group(1), tm.group(2)
                tok = tm.group(0)
                pinned = pins.get(pkg.lower())
                new_tok = tok.replace(ver, pinned) if pinned else tok
                if pinned and ver != pinned:
                    mismatched = True
                    msg = (f"pin declaration says {pkg} {ver}, but "
                           f"tools/ pins {pkg.lower()}=={pinned}")
                    if relpath in exempt:
                        checker.findings.append(
                            Finding("info", relpath, n,
                                    f"{msg} — exempt: {exempt[relpath]}"))
                    else:
                        checker.err(relpath, n,
                                    f"{msg} (--fix rewrites this)", fixable=True)
                        checker.fixes.append(Fix(relpath, n, tok, new_tok))
        if any(rx.search(raw) for rx in (RE_PIN_DECL, RE_LAST_VERIFIED)):
            continue                     # a header declaration, checked above
        for im in RE_INLINE_PIN.finditer(raw):
            pkg, ver, tok = im.group("pkg"), im.group("ver"), im.group("tok")
            pinned = pins.get(pkg.lower())
            if not pinned or ver == pinned:
                continue
            mismatched = True
            msg = (f"inline pin claim '{tok}', but tools/ pins "
                   f"{pkg.lower()}=={pinned}. If this describes an older "
                   f"version on purpose, say 'as of' / 'through' / 'since'")
            if relpath in exempt:
                checker.findings.append(
                    Finding("info", relpath, n, f"{msg} — exempt: {exempt[relpath]}"))
            else:
                checker.err(relpath, n, f"{msg} (--fix rewrites this)", fixable=True)
                checker.fixes.append(Fix(relpath, n, tok, tok.replace(ver, pinned)))
    if relpath in exempt and not mismatched:
        checker.err(relpath, 1,
                    "listed in tools/citations-exempt.txt but its pin "
                    "declaration is current — remove the exemption")



# The "good" cases need a real line number, and a hard-coded one breaks on
# every LXMF bump that moves LXMessage.py. {T} is replaced at run time with
# the line SELFTEST_ANCHOR occupies in the pinned install, {T-1} with the
# line before it.
SELFTEST_FILE = "LXMF/LXMessage.py"
SELFTEST_ANCHOR = "truncated_hash(self.outbound_ticket+self.message_id)"

SELFTESTS = [
    # (name, markdown, expected error substring or None for "must pass")
    ("anchor absent from upstream",
     "See (`LXMF/LXMessage.py:{T}` -> `SHA256(ticket || message_id)[:32]`).",
     "anchor snippet not present"),
    ("drifted line number",
     "See (`LXMF/LXMessage.py:{T-1}` -> "
     "`truncated_hash(self.outbound_ticket+self.message_id)`).",
     "drifted"),
    ("inverted range",
     "See (`LXMF/LXMessage.py:{T}-{T-1}` -> "
     "`truncated_hash(self.outbound_ticket+self.message_id)`).",
     "inverted range"),
    ("missing symbol",
     "See `RNS/Resource.py::no_such_method` for details.",
     "symbol not found"),
    ("line past end of file",
     "See `RNS/Link.py:99999` for details.",
     "past the end"),
    ("continuation anchor binds to the preceding file",
     "See `LXMF/LXMRouter.py:1523` and `:1548` -> "
     "`lxmf_data[:-LXStamper.STAMP_SIZE]`.",
     "drifted"),
    ("good anchor",
     "See (`LXMF/LXMessage.py:{T}` -> "
     "`truncated_hash(self.outbound_ticket+self.message_id)`).",
     None),
    ("good symbol",
     "See `RNS/Resource.py::Resource.assemble` for details.",
     None),
    ("arrow between two citations is not an anchor",
     "`RNS/Destination.py:611-645` -> `RNS/Identity.py:848-904`. Token decode.",
     None),
    ("anchor wrapped across a blockquote continuation",
     "> the derivation (`LXMF/LXMessage.py:{T}` ->\n"
     "> `truncated_hash(self.outbound_ticket+self.message_id)`) is 16 bytes.",
     None),
]


# (line, expected count of RE_INLINE_PIN matches). Current-pin phrasings must
# match; history phrasings must not, or every bump would rewrite history.
PIN_SELFTESTS = [
    ("(`RNS/Destination.py:85` → `RATCHET_COUNT = 512` in RNS 1.5.7)", 1),
    ("| `Transport.MAX_RANDOM_BLOBS = 64` (RNS 1.5.7) |", 1),
    ("(verified against LXMF 1.2.1 by `tools/verify_lxmf_fields.py`)", 1),
    ("Line citations in this section are against **NomadNet 1.4.4**", 1),
    ("upstream LXMF 1.2.1 only does the stripped form", 1),
    ("In RNS 1.5.7 the clamp is performed by transit relays", 1),
    ("Since RNS 1.5.2 the parser also rejects an empty data field", 0),
    ("Through RNS 1.4.2 the relay forwarded link DATA", 0),
    ("**Ingress bound (RNS ≥ 1.5.2).**", 0),
    ("> **Changed in RNS 1.5.0 — larger stream chunks.**", 0),
    ("| drains continuously | **New in RNS 1.5.0.** Dequeues", 0),
    ("Official as of LXMF 1.0.0 (2026-05-28)", 0),
    ("line 1282 as of RNS 1.5.2", 0),
]


def run_selftest(index):
    """Every failure mode the checker claims to catch must actually fail it."""
    failures = 0
    for line, want in PIN_SELFTESTS:
        got = len(RE_INLINE_PIN.findall(line))
        if got != want:
            print(f"  FAIL pin selftest {line!r}: {got} inline pin claim(s), "
                  f"expected {want}")
            failures += 1
    if not failures:
        print(f"  ok   {len(PIN_SELFTESTS)} inline-pin classifier cases")
    abspath = index.resolve(SELFTEST_FILE)
    hits = [i for i, l in enumerate(index.lines(abspath) if abspath else [], 1)
            if SELFTEST_ANCHOR in l]
    if len(hits) != 1:
        print(f"  FAIL selftest setup: {SELFTEST_ANCHOR!r} occurs {len(hits)} "
              f"time(s) in the pinned {SELFTEST_FILE}; pick a new anchor")
        return 1
    t = hits[0]
    for name, markdown, expected in SELFTESTS:
        markdown = markdown.replace("{T-1}", str(t - 1)).replace("{T}", str(t))
        checker = Checker(index)
        checker.check_document("<selftest>", markdown.split("\n"))
        errors = [f for f in checker.findings if f.kind == "error"]
        if expected is None:
            if errors:
                print(f"  FAIL selftest {name!r}: expected clean, got "
                      f"{errors[0].message}")
                failures += 1
            else:
                print(f"  ok   selftest {name!r} — clean, as expected")
        else:
            if not any(expected in f.message for f in errors):
                got = errors[0].message if errors else "no error at all"
                print(f"  FAIL selftest {name!r}: expected {expected!r}, got {got}")
                failures += 1
            else:
                print(f"  ok   selftest {name!r} — caught ({expected})")
    return failures


# --- entry point ---------------------------------------------------------

def collect_targets(targets):
    out = []
    for t in targets:
        abs_t = os.path.join(REPO_ROOT, t)
        if os.path.isdir(abs_t):
            for fn in sorted(os.listdir(abs_t)):
                if fn.endswith(".md"):
                    out.append(os.path.join(t, fn))
        elif os.path.isfile(abs_t):
            out.append(t)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", default=DEFAULT_TARGETS,
                    help="markdown files or directories (default: SPEC.md flows)")
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings as errors")
    ap.add_argument("--fix", action="store_true",
                    help="rewrite drifted line numbers on anchored citations")
    ap.add_argument("--selftest", action="store_true",
                    help="check that the checker catches each failure mode")
    args = ap.parse_args()

    index = SourceIndex()
    if not {"RNS", "LXMF"} <= set(index.roots):
        print("FAIL: RNS and LXMF must be importable — "
              "pip install -r tools/requirements.txt", file=sys.stderr)
        return 2

    import RNS
    print(f"check_citations.py against pinned install: "
          f"{', '.join(index.available)} (RNS {RNS.__version__})")

    if args.selftest:
        failures = run_selftest(index)
        if failures:
            print(f"FAIL: {failures} selftest(s) did not behave as documented")
            return 1
        print(f"PASS: {len(SELFTESTS)} selftests, "
              f"{len(PIN_SELFTESTS)} inline-pin cases")
        return 0

    pins = load_pins()
    exempt = load_exemptions()
    checker = Checker(index, strict=args.strict)

    docs = collect_targets(args.targets or DEFAULT_TARGETS)
    for doc in docs:
        checker.check_document(doc)
        check_pins(checker, doc, pins, exempt)

    if args.fix and checker.fixes:
        applied = checker.apply_fixes()
        print(f"\n--fix rewrote {applied} drifted line number(s); re-run to confirm")
        # Drift is fixable; a snippet that is nowhere in the pinned source is
        # not, and must not be masked by a successful --fix run.
        unfixable = [f for f in checker.findings
                     if f.kind == "error" and not f.fixable]
        for f in unfixable:
            print(f"  ERROR {f.doc}:{f.doc_line}: {f.message}")
        if unfixable:
            print(f"FAIL: {len(unfixable)} error(s) --fix cannot repair — "
                  f"these are claims upstream no longer supports")
            return 1
        return 0

    errors = [f for f in checker.findings if f.kind == "error"]
    warns = [f for f in checker.findings if f.kind == "warn"]
    infos = [f for f in checker.findings if f.kind == "info"]

    for f in infos:
        print(f"  info  {f.doc}:{f.doc_line}: {f.message}")
    for f in warns:
        print(f"  WARN  {f.doc}:{f.doc_line}: {f.message}")
    for f in errors:
        print(f"  ERROR {f.doc}:{f.doc_line}: {f.message}")

    c = checker.counts
    total_checkable = c["anchored"] + c["symbol"] + c["line"] + c["continuation"]
    anchored_pct = (100.0 * c["anchored"] / total_checkable) if total_checkable else 0.0
    print(f"\n{len(docs)} document(s); {total_checkable} resolvable citations — "
          f"{c['anchored']} anchored ({anchored_pct:.0f}%), {c['symbol']} symbol, "
          f"{c['line']} line-only, {c['continuation']} continuation, "
          f"{c['skipped']} skipped (source not in the pinned install)")

    if errors:
        print(f"FAIL: {len(errors)} error(s), {len(warns)} warning(s)")
        return 1
    print(f"PASS: 0 errors, {len(warns)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
