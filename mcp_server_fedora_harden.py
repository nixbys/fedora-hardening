#!/usr/bin/env python3
"""
Fedora Hardening Script - MCP Server

Exposes the project's development workflow (lint, podman tests, docs checks,
quality report) as MCP tools so an MCP client such as Claude can drive it.

Usage:
    pip install --user mcp
    claude mcp add fedora-harden-dev -- python3 /path/to/mcp_server_fedora_harden.py

Works with the MCP Python SDK 1.x (FastMCP) and 2.x (MCPServer).
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer
except ImportError:
    try:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError as exc:
        print(
            f"Error: MCP SDK not available ({exc}). Install with: pip install --user mcp",
            file=sys.stderr,
        )
        sys.exit(1)

# ============================================================================
# Configuration
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent
SCRIPT_PATH = PROJECT_ROOT / "fedora-harden.sh"
DEFAULT_TIMEOUT = 300
TEST_TIMEOUT = 3600
SECTION_LIST_RE = re.compile(r"^\d+[a-z]?(,\d+[a-z]?)*$")

mcp = MCPServer("fedora-harden-dev")


# ============================================================================
# Helpers
# ============================================================================


async def run_command(
    cmd: list[str], timeout: int = DEFAULT_TIMEOUT
) -> tuple[int, str, str]:
    """Run a command (no shell) in the project root; return (rc, stdout, stderr)."""
    if shutil.which(cmd[0]) is None and not (PROJECT_ROOT / cmd[0]).exists():
        return 127, "", f"{cmd[0]}: command not found"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=PROJECT_ROOT,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return 127, "", str(exc)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def tail(text: str, lines: int = 60) -> str:
    """Return the last N lines of text."""
    return "\n".join(text.splitlines()[-lines:])


async def _syntax() -> tuple[bool, str]:
    rc, _, err = await run_command(["bash", "-n", str(SCRIPT_PATH)])
    return rc == 0, err.strip() or "bash -n: OK"


async def _lint() -> tuple[bool, str]:
    # The static tier runs on Fedora 44 (natively, or inside the Fedora 44 lint image),
    # so results match CI regardless of the host's tool versions.
    rc, out, err = await run_command(
        ["./tests/run-suite.sh", "--tier", "static"], timeout=TEST_TIMEOUT
    )
    return rc == 0, f"exit code {rc}\n\n{tail(out, 40)}\n{tail(err, 10)}".rstrip()


async def _docs() -> tuple[bool, str]:
    issues: list[str] = []
    for doc in ["README.md", "TESTING.md", "QUICKSTART-TESTING.md", "DEVELOPMENT.md"]:
        if not (PROJECT_ROOT / doc).exists():
            issues.append(f"Missing: {doc}")
    content = SCRIPT_PATH.read_text(encoding="utf-8")
    functions = re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", content, re.MULTILINE)
    undocumented = [
        f for f in functions if not re.search(rf"^#\s*{re.escape(f)}\(\)", content, re.MULTILINE)
    ]
    if undocumented:
        issues.append(
            f"{len(undocumented)} function(s) without a '# name()' doc comment: "
            + ", ".join(undocumented[:15])
            + (" ..." if len(undocumented) > 15 else "")
        )
    return not issues, "\n".join(issues) or "Documentation complete"


async def _podman_test(mode: str, dry_run: bool, section: str | None) -> tuple[bool, str]:
    if mode not in ("quick", "full"):
        return False, f"Invalid mode {mode!r} (expected 'quick' or 'full')"
    if section and not SECTION_LIST_RE.match(section):
        return False, f"Invalid section list {section!r} (expected e.g. '5' or '5,7,10')"
    cmd = ["./test-in-podman.sh"]
    if mode == "quick":
        cmd.append("--quick")
    if dry_run:
        cmd.append("--dry-run")
    if section:
        cmd += ["--only", section]
    rc, out, err = await run_command(cmd, timeout=TEST_TIMEOUT)
    return rc == 0, f"exit code {rc}\n\n{tail(out, 80)}\n{tail(err, 20)}".rstrip()


def _fmt(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


# ============================================================================
# Tools
# ============================================================================


@mcp.tool(
    name="lint-script",
    description="Static tier on Fedora 44: shellcheck, shfmt, yamllint, hadolint, ruff, MCP smoke test",
)
async def lint_script() -> str:
    ok, detail = await _lint()
    return f"Lint: {_fmt(ok)}\n\n{detail}"


@mcp.tool(
    name="test-script",
    description=(
        "Run fedora-harden.sh in an isolated podman container. mode=quick (no systemd) "
        "or full (systemd). Without dry_run, changes are applied inside the container only."
    ),
)
async def test_script(mode: str = "quick", dry_run: bool = True, section: str | None = None) -> str:
    ok, detail = await _podman_test(mode, dry_run, section)
    return f"Tests: {_fmt(ok)}\n\n{detail}"


@mcp.tool(
    name="verify-script",
    description="Syntax check, lint, documentation check and a podman dry-run test",
)
async def verify_script(quick: bool = True, dry_run: bool = True) -> str:
    checks: dict[str, tuple[bool, str]] = {
        "syntax": await _syntax(),
        "lint": await _lint(),
        "documentation": await _docs(),
        "tests": await _podman_test("quick" if quick else "full", dry_run, None),
    }
    overall = all(ok for ok, _ in checks.values())
    summary = {name: _fmt(ok) for name, (ok, _) in checks.items()}
    details = "\n\n".join(f"## {name}\n{detail}" for name, (_, detail) in checks.items())
    return (
        f"Verification report ({datetime.now().isoformat(timespec='seconds')})\n"
        f"{json.dumps(summary, indent=2)}\n\nOverall: {_fmt(overall)}\n\n{details}"
    )


@mcp.tool(
    name="check-security",
    description="Scan the repository for verified leaked secrets (trufflehog or gitleaks)",
)
async def check_security() -> str:
    if shutil.which("trufflehog"):
        rc, out, err = await run_command(
            ["trufflehog", "filesystem", ".", "--only-verified", "--fail", "--no-update"]
        )
        tool = "trufflehog"
    elif shutil.which("gitleaks"):
        rc, out, err = await run_command(["gitleaks", "detect", "--no-banner", "--redact"])
        tool = "gitleaks"
    else:
        return "Security: SKIPPED — neither trufflehog nor gitleaks is installed"
    if rc == 0:
        return f"Security: PASS — {tool} found no secrets"
    return f"Security: FAIL — {tool} exit {rc}\n\n{tail(out or err, 60)}"


@mcp.tool(name="validate-docs", description="Check required docs and function doc comments")
async def validate_docs() -> str:
    ok, detail = await _docs()
    return f"Documentation: {_fmt(ok)}\n\n{detail}"


@mcp.tool(name="analyze-performance", description="Static size/complexity metrics for the script")
async def analyze_performance(profile: bool = False) -> str:
    content = SCRIPT_PATH.read_text(encoding="utf-8")
    lines = content.splitlines()
    functions = re.findall(r"^[A-Za-z_][A-Za-z0-9_]*\(\)\s*\{", content, re.MULTILINE)
    metrics: dict[str, object] = {
        "total_lines": len(lines),
        "functions": len(functions),
        "comment_lines": sum(1 for line in lines if line.lstrip().startswith("#")),
        "run_wrapper_calls": len(re.findall(r"\brun \"", content)),
        "eval_uses": len(re.findall(r"\beval\b", content)),
    }
    if profile:
        start = asyncio.get_running_loop().time()
        await run_command(["bash", "-n", str(SCRIPT_PATH)])
        metrics["syntax_check_ms"] = int((asyncio.get_running_loop().time() - start) * 1000)
    return f"Performance analysis:\n{json.dumps(metrics, indent=2)}"


@mcp.tool(
    name="generate-changelog",
    description="List commits since a ref (default: last tag, or the last 50 commits)",
)
async def generate_changelog(since: str = "") -> str:
    if since and not re.match(r"^[\w./-]+$", since):
        return f"Invalid ref: {since!r}"
    if not since:
        rc, out, _ = await run_command(["git", "describe", "--tags", "--abbrev=0"])
        since = out.strip() if rc == 0 else ""
    cmd = ["git", "log", "--no-merges", "--pretty=format:- %s (%h)"]
    cmd += [f"{since}..HEAD"] if since else ["-n", "50"]
    rc, out, err = await run_command(cmd)
    if rc != 0:
        return f"git log failed: {err.strip()}"
    return f"# Changelog{f' since {since}' if since else ''}\n\n{out or '(no commits)'}"


@mcp.tool(name="quality-report", description="Syntax, lint and documentation summary (no containers)")
async def quality_report() -> str:
    sections = {
        "syntax": await _syntax(),
        "lint": await _lint(),
        "documentation": await _docs(),
    }
    report = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "script": str(SCRIPT_PATH),
        "sections": {k: _fmt(ok) for k, (ok, _) in sections.items()},
    }
    report["overall"] = _fmt(all(ok for ok, _ in sections.values()))
    return f"Quality report:\n{json.dumps(report, indent=2)}"


@mcp.tool(
    name="setup-dev-environment",
    description="Run ./setup-dev.sh (pre-commit hooks + dev tools). dry_run shows the plan only.",
)
async def setup_dev_environment(dry_run: bool = True) -> str:
    cmd = ["./setup-dev.sh"] + (["--dry-run"] if dry_run else [])
    rc, out, err = await run_command(cmd, timeout=900)
    return f"setup-dev.sh exit {rc}\n\n{tail(out, 80)}\n{tail(err, 20)}".rstrip()


if __name__ == "__main__":
    mcp.run()
