#!/usr/bin/env python3
"""Detect changes in the guidance fedora-harden.sh is based on.

Reads docs/references.json, fetches every source and compares a fingerprint of
its main content with the stored one. GitHub-release sources are compared with
the version pinned in fedora-harden.sh.

    python3 tests/check-references.py              # report; exit 1 if anything changed
    python3 tests/check-references.py --update     # after review: store new fingerprints
    python3 tests/check-references.py --markdown F # also write a Markdown report to F

Standard library only, so it runs on a stock Fedora image and in CI.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html.parser
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "docs" / "references.json"
SCRIPT = ROOT / "fedora-harden.sh"
USER_AGENT = "fedora-harden-reference-check/1.0 (+https://github.com/nixbys/fedora-hardening)"


class _MainText(html.parser.HTMLParser):
    """Collect visible text inside the first matching container element.

    The container is a tag name, optionally with a class token ("div.col-md-8"),
    so a source can point at its article body and skip sidebars that change often.
    """

    SKIP = frozenset({"script", "style", "nav", "header", "footer", "noscript", "svg", "form"})

    def __init__(self, container: str) -> None:
        super().__init__(convert_charrefs=True)
        self.container, _, self.cls = container.partition(".")
        self.depth = 0  # nesting depth inside the container
        self.skip = 0
        self.done = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if self.done:
            return
        if self.depth == 0 and tag == self.container:
            classes = (dict(attrs).get("class") or "").split()
            if not self.cls or self.cls in classes:
                self.depth = 1
            return
        if self.depth:
            if tag == self.container:
                self.depth += 1
            if tag in self.SKIP:
                self.skip += 1

    def handle_endtag(self, tag: str) -> None:
        if not self.depth or self.done:
            return
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        if tag == self.container:
            self.depth -= 1
            if self.depth == 0:
                self.done = True

    def handle_data(self, data: str) -> None:
        if self.depth and not self.skip:
            self.parts.append(data)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode(resp.headers.get_content_charset() or "utf-8", "replace")


def main_text(body: str, kind: str, selector: str = "") -> str:
    if kind == "text":
        text = body
    else:
        text = ""
        for container in ([selector] if selector else []) + ["article", "main", "body"]:
            parser = _MainText(container)
            parser.feed(body)
            text = " ".join(parser.parts)
            if len(text.strip()) > 200:
                break
    return re.sub(r"\s+", " ", text).strip()


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def pinned(var: str) -> str:
    match = re.search(rf'^{re.escape(var)}="([^"]+)"', SCRIPT.read_text(), re.MULTILINE)
    return match.group(1) if match else ""


def latest_release(repo: str) -> str:
    data = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/latest"))
    return data["tag_name"]


def check(source: dict) -> tuple[str, str]:
    """Return (status, detail); status is ok, changed or error."""
    try:
        if source["type"] == "github-release":
            latest = latest_release(source["repo"])
            current = pinned(source["pinned_var"])
            source["_new"] = latest
            if latest == current:
                return "ok", f"pinned {current} is the latest release"
            return "changed", f"new release {latest} (script pins {current})"
        text = main_text(fetch(source["url"]), source["type"], source.get("selector", ""))
        new = fingerprint(text)
        source["_new"] = new
        if new == source.get("fingerprint"):
            return "ok", "unchanged"
        return "changed", "content changed since the last review"
    except (OSError, ValueError, KeyError) as exc:  # network/parse errors: reported, not fatal
        return "error", f"{type(exc).__name__}: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--update", action="store_true", help="store new fingerprints (after review)")
    ap.add_argument("--markdown", metavar="FILE", help="write a Markdown report")
    args = ap.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    rows = []
    for src in manifest["sources"]:
        status, detail = check(src)
        rows.append((src, status, detail))
        print(f"{status.upper():8} {src['id']:28} {detail}")

    changed = [r for r in rows if r[1] == "changed"]
    errors = [r for r in rows if r[1] == "error"]

    if args.markdown:
        lines = [
            "The guidance `fedora-harden.sh` follows has changed since it was last reviewed.",
            "",
            "| Source | Script sections | What changed |",
            "|---|---|---|",
        ]
        for src, status, detail in rows:
            if status != "ok":
                link = src.get("url") or f"https://github.com/{src['repo']}/releases"
                lines.append(f"| [{src['title']}]({link}) | {src['sections']} | {detail} |")
        lines += [
            "",
            "**To resolve:** read the changes, update `fedora-harden.sh` where the advice",
            "changed (bump `ARKENFOX_VERSION`/`ARKENFOX_SHA256` for a new arkenfox release),",
            "then run `python3 tests/check-references.py --update` and commit",
            "`docs/references.json`. This issue updates itself on the next weekly run.",
        ]
        Path(args.markdown).write_text("\n".join(lines) + "\n")

    if args.update:
        today = dt.date.today().isoformat()
        for src, status, _ in rows:
            if status != "error" and src.get("type") != "github-release":
                src["fingerprint"] = src["_new"]
                src["reviewed"] = today
            src.pop("_new", None)
        manifest["reviewed"] = today
        MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        print(f"Updated {MANIFEST.relative_to(ROOT)}")
        return 1 if errors else 0

    if errors:
        print(f"{len(errors)} source(s) could not be checked", file=sys.stderr)
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main())
