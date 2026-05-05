"""
One-shot helper that builds a navigation Table of Contents for SPEC.md
by extracting every H2 and H3 heading and computing the GitHub anchor
for each. The output is printed to stdout. To regenerate the ToC after
adding/removing/renaming headings:

    python tools/_gen_toc.py > /tmp/toc.md
    # paste contents into SPEC.md between the <!-- TOC --> markers

This is a maintenance helper, not a verifier; not listed in
`tools/README.md`. Delete if it stops being useful.
"""

from __future__ import annotations

import os
import re
import sys


REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC_PATH  = os.path.join(REPO_ROOT, "SPEC.md")


def slugify(s: str) -> str:
    s = s.lower()
    s = s.replace("`", "")
    # Drop everything except word chars (letters/digits/_), whitespace, and hyphen
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"-+", "-", s)
    return s.strip("-")


def main() -> int:
    with open(SPEC_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    in_fence = False
    entries = []
    for line in lines:
        stripped = line.rstrip("\n")
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m2 = re.match(r"^## (.+?)\s*$", stripped)
        m3 = re.match(r"^### (.+?)\s*$", stripped)
        if m2:
            title = m2.group(1)
            entries.append(("h2", title, slugify(title)))
        elif m3:
            title = m3.group(1)
            entries.append(("h3", title, slugify(title)))

    out = sys.stdout
    out.reconfigure(encoding="utf-8") if hasattr(out, "reconfigure") else None

    out.write("<!-- TOC: regenerate via `python tools/_gen_toc.py` -->\n")
    out.write("## Contents\n\n")
    for kind, title, slug in entries:
        if kind == "h2":
            out.write(f"- [{title}](#{slug})\n")
        else:
            out.write(f"  - [{title}](#{slug})\n")
    out.write("<!-- /TOC -->\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
