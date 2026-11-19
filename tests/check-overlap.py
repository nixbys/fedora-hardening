#!/usr/bin/env python3
"""Find wording in this repository that repeats a source's text word for word.

The project follows the guidance in docs/references.json, in its own words. This
fetches every page there and reports each run of MIN_RUN or more consecutive
words that also appears in the README, the docs or a code comment. A run in a
quotation (inside quotation marks, or a Markdown "> " block) is allowed: quoting
with a citation is fine, copying is not.

    python3 tests/check-overlap.py               # report; exit 1 if anything overlaps
    python3 tests/check-overlap.py --markdown F  # also write a Markdown report to F

Standard library only, like check-references.py, whose fetching it reuses.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIN_RUN = 12  # words; shorter runs are mostly shared technical phrases
SHINGLE = 8  # words per comparison window

_spec = importlib.util.spec_from_file_location("refs", ROOT / "tests" / "check-references.py")
refs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(refs)

WORD = re.compile(r"[a-z0-9]+(?:'[a-z]+)?")
QUOTED = re.compile(r"\"[^\"]{20,}\"|“[^”]{20,}”")
DOCS = ["README.md", "SECURITY.md", "THREAT_MODEL.md", "DEVELOPMENT.md", "TESTING.md", "CHANGELOG.md"]


def words(text: str) -> list[str]:
    return WORD.findall(text.lower())


def repo_lines() -> list[tuple[str, int, str]]:
    """(file, line number, prose) for the Markdown docs and code comments."""
    out = []
    files = [ROOT / d for d in DOCS] + sorted((ROOT / "docs").glob("*.md"))
    for f in files:
        if not f.is_file():
            continue
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            if line.lstrip().startswith(">"):
                continue  # a quotation
            out.append((str(f.relative_to(ROOT)), n, QUOTED.sub(" ", line)))
    code = [ROOT / "fedora-harden.sh", *ROOT.glob("core/*.sh"), *ROOT.glob("fedora/*/*.sh"),
            *ROOT.glob("libexec/*"), *ROOT.glob("tests/*.sh"), *ROOT.glob("*.py"), *ROOT.glob("tests/*.py")]
    for f in code:
        if not f.is_file():
            continue
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            s = line.strip()
            if s.startswith("#") and not s.startswith("#!"):
                out.append((str(f.relative_to(ROOT)), n, QUOTED.sub(" ", s.lstrip("# "))))
    return out


def overlaps(source_words: list[str], lines: list[tuple[str, int, str]]) -> list[tuple[str, int, str]]:
    """Runs of at least MIN_RUN words shared with the source: (file, line, text)."""
    grams = {tuple(source_words[i:i + SHINGLE]) for i in range(len(source_words) - SHINGLE + 1)}
    # The repo text as one stream per file, remembering which line each word is on,
    # so a sentence that wraps over several lines is still found.
    found = []
    by_file: dict[str, list[tuple[int, str]]] = {}
    for f, n, text in lines:
        by_file.setdefault(f, []).extend((n, w) for w in words(text))
    for f, toks in by_file.items():
        seq = [w for _, w in toks]
        hit = [False] * len(seq)
        for i in range(len(seq) - SHINGLE + 1):
            if tuple(seq[i:i + SHINGLE]) in grams:
                for j in range(i, i + SHINGLE):
                    hit[j] = True
        i = 0
        while i < len(seq):
            if not hit[i]:
                i += 1
                continue
            j = i
            while j < len(seq) and hit[j]:
                j += 1
            if j - i >= MIN_RUN:
                found.append((f, toks[i][0], " ".join(seq[i:j])))
            i = j
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--markdown", metavar="FILE", help="write a Markdown report")
    args = ap.parse_args()

    manifest = json.loads(refs.MANIFEST.read_text())
    lines = repo_lines()
    rows, errors = [], 0
    for src in manifest["sources"]:
        if src.get("type") not in ("html", "text"):
            continue
        try:
            text = refs.main_text(refs.fetch(src["url"]), src["type"], src.get("selector", ""))
        except (OSError, ValueError) as exc:
            print(f"ERROR    {src['id']:28} {type(exc).__name__}: {exc}")
            errors += 1
            continue
        hits = overlaps(words(text), lines)
        print(f"{'OVERLAP' if hits else 'OK':8} {src['id']:28} {len(hits)} passage(s)")
        for f, n, run in hits:
            print(f"         {f}:{n}: {run[:160]}")
            rows.append((src, f, n, run))

    if args.markdown and rows:
        out = [
            "Some text in this repository repeats a source word for word. Reword it in the",
            "project's own words, or quote it (quotation marks or a `>` block) with the citation.",
            "",
            "| Where | Source | Repeated words |",
            "|---|---|---|",
        ]
        for src, f, n, run in rows:
            out.append(f"| `{f}:{n}` | [{src['title']}]({src['url']}) | {run[:200]} |")
        Path(args.markdown).write_text("\n".join(out) + "\n")

    if errors:
        print(f"{errors} source(s) could not be checked", file=sys.stderr)
    return 1 if rows else 0


if __name__ == "__main__":
    sys.exit(main())
