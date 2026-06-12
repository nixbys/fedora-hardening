#!/usr/bin/env python3
"""
Fedora Hardening Script - MCP Server
Provides integrated development tools for fedora-harden.sh through Claude

Features:
- One-command verification workflow
- Automated testing and linting
- Performance benchmarking
- Documentation validation
- Security scanning
- Changelog/version management
- Quality metrics reporting

Usage:
    mcp install mcp_server_fedora_harden.py
    # Then use in Claude with /mcp fedora-harden commands
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from mcp.server import Server, stdio_server
    from mcp.types import Tool, TextContent, ToolResult
except ImportError:
    print("Error: MCP SDK not installed. Install with: pip install mcp", file=sys.stderr)
    sys.exit(1)

# ============================================================================
# Configuration
# ============================================================================

PROJECT_ROOT = Path(__file__).parent.absolute()
SCRIPT_NAME = "fedora-harden.sh"
SCRIPT_PATH = PROJECT_ROOT / SCRIPT_NAME

# Tool versions (update as needed)
MIN_PYTHON_VERSION = (3, 8)
REQUIRED_TOOLS = {
    "bash": "bash",
    "podman": "podman",
    "git": "git",
}

# ============================================================================
# MCP Server Implementation
# ============================================================================

server = Server("fedora-harden-dev")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available development tools."""
    return [
        Tool(
            name="verify-script",
            description="Run comprehensive verification: syntax check, linting, tests, security scan",
            inputSchema={
                "type": "object",
                "properties": {
                    "quick": {
                        "type": "boolean",
                        "description": "Quick mode (no full test suite)",
                        "default": True,
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Run tests in dry-run mode (no changes)",
                        "default": True,
                    },
                },
            },
        ),
        Tool(
            name="lint-script",
            description="Run shellcheck and shfmt on the script",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="test-script",
            description="Run test suite in podman container",
            inputSchema={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["quick", "full"],
                        "description": "Test mode (quick=no systemd, full=with systemd)",
                        "default": "quick",
                    },
                    "section": {
                        "type": "string",
                        "description": "Run specific section (e.g., '5' for firewalld)",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Use --dry-run flag",
                        "default": True,
                    },
                },
            },
        ),
        Tool(
            name="check-security",
            description="Run security scans: secrets detection, dependency analysis",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="validate-docs",
            description="Validate documentation completeness and consistency",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="analyze-performance",
            description="Analyze script performance: complexity, function counts, execution time",
            inputSchema={
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "boolean",
                        "description": "Run performance profiling (slower)",
                        "default": False,
                    },
                },
            },
        ),
        Tool(
            name="update-version",
            description="Update version number with semantic versioning",
            inputSchema={
                "type": "object",
                "properties": {
                    "bump": {
                        "type": "string",
                        "enum": ["major", "minor", "patch"],
                        "description": "Version bump type",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Show what would change without making changes",
                        "default": True,
                    },
                },
            },
        ),
        Tool(
            name="generate-changelog",
            description="Generate changelog from git commits (conventional commits)",
            inputSchema={
                "type": "object",
                "properties": {
                    "since": {
                        "type": "string",
                        "description": "Generate since this version (default: last tag)",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Show what would change",
                        "default": True,
                    },
                },
            },
        ),
        Tool(
            name="create-release",
            description="Create a new release (tag, changelog, artifacts)",
            inputSchema={
                "type": "object",
                "properties": {
                    "version": {
                        "type": "string",
                        "description": "Version number (e.g., 2.0.0)",
                    },
                    "draft": {
                        "type": "boolean",
                        "description": "Create as draft (don't publish)",
                        "default": True,
                    },
                },
            },
        ),
        Tool(
            name="quality-report",
            description="Generate comprehensive quality metrics and report",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="setup-dev-environment",
            description="Setup local development environment (pre-commit hooks, dependencies)",
            inputSchema={
                "type": "object",
                "properties": {
                    "dry_run": {
                        "type": "boolean",
                        "description": "Show what would be installed",
                        "default": True,
                    },
                },
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> ToolResult:
    """Execute tool with given arguments."""

    try:
        if name == "verify-script":
            return await verify_script(arguments)
        elif name == "lint-script":
            return await lint_script(arguments)
        elif name == "test-script":
            return await test_script(arguments)
        elif name == "check-security":
            return await check_security(arguments)
        elif name == "validate-docs":
            return await validate_docs(arguments)
        elif name == "analyze-performance":
            return await analyze_performance(arguments)
        elif name == "update-version":
            return await update_version(arguments)
        elif name == "generate-changelog":
            return await generate_changelog(arguments)
        elif name == "create-release":
            return await create_release(arguments)
        elif name == "quality-report":
            return await quality_report(arguments)
        elif name == "setup-dev-environment":
            return await setup_dev_environment(arguments)
        else:
            return ToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {name}")]
            )
    except Exception as e:
        return ToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Error executing {name}: {str(e)}",
                )
            ],
            isError=True,
        )


# ============================================================================
# Tool Implementations
# ============================================================================


async def run_command(cmd: list[str], cwd: Path = None) -> tuple[int, str, str]:
    """Run shell command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd or PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out after 5 minutes"
    except Exception as e:
        return -1, "", str(e)


async def verify_script(args: dict) -> ToolResult:
    """Run comprehensive verification workflow."""
    quick = args.get("quick", True)
    dry_run = args.get("dry_run", True)

    results = {
        "timestamp": datetime.now().isoformat(),
        "checks": {},
        "overall_status": "PASS",
    }

    # 1. Syntax check
    rc, _, err = await run_command(["bash", "-n", str(SCRIPT_PATH)])
    results["checks"]["syntax"] = "PASS" if rc == 0 else f"FAIL: {err}"
    if rc != 0:
        results["overall_status"] = "FAIL"

    # 2. Lint
    lint_result = await lint_script({})
    results["checks"]["linting"] = (
        "PASS" if "issues" not in lint_result.content[0].text else "WARN"
    )

    # 3. Security
    sec_result = await check_security({})
    results["checks"]["security"] = (
        "PASS" if "no issues" in sec_result.content[0].text.lower() else "WARN"
    )

    # 4. Tests
    test_result = await test_script(
        {"mode": "quick" if quick else "full", "dry_run": dry_run}
    )
    results["checks"]["tests"] = (
        "PASS" if "completed successfully" in test_result.content[0].text else "WARN"
    )

    # 5. Documentation
    doc_result = await validate_docs({})
    results["checks"]["documentation"] = (
        "PASS" if "complete" in doc_result.content[0].text.lower() else "WARN"
    )

    return ToolResult(
        content=[
            TextContent(
                type="text",
                text=f"Verification Report:\n{json.dumps(results, indent=2)}\n\nOverall Status: {results['overall_status']}",
            )
        ]
    )


async def lint_script(args: dict) -> ToolResult:
    """Run shellcheck and shfmt."""
    issues = []

    # shellcheck
    rc, stdout, stderr = await run_command(
        ["shellcheck", "--format=gcc", str(SCRIPT_PATH)]
    )
    if rc != 0 and stdout:
        issues.append(f"shellcheck issues:\n{stdout}")

    # shfmt --check
    rc, _, stderr = await run_command(["shfmt", "-d", str(SCRIPT_PATH)])
    if rc != 0 and stderr:
        issues.append(f"shfmt formatting issues:\n{stderr}")

    status = (
        f"Found {len(issues)} issue categories"
        if issues
        else "✓ No linting issues found"
    )
    return ToolResult(
        content=[TextContent(type="text", text=f"{status}\n\n{chr(10).join(issues)}")]
    )


async def test_script(args: dict) -> ToolResult:
    """Run test suite."""
    mode = args.get("mode", "quick")
    section = args.get("section")
    dry_run = args.get("dry_run", True)

    cmd = ["./test-in-podman.sh"]
    if mode == "quick":
        cmd.append("--quick")
    if dry_run:
        cmd.append("--dry-run")
    if section:
        cmd.extend(["--only", section])

    rc, stdout, stderr = await run_command(cmd)
    status = "✓ Tests passed" if rc == 0 else f"✗ Tests failed (rc={rc})"

    return ToolResult(
        content=[
            TextContent(
                type="text",
                text=f"{status}\n\n{stdout}\n{stderr if stderr else ''}",
            )
        ]
    )


async def check_security(args: dict) -> ToolResult:
    """Run security scans."""
    issues = []

    # Check for secrets with trufflehog
    rc, stdout, stderr = await run_command(
        ["trufflehog", "filesystem", ".", "--only-verified"]
    )
    if rc == 0 and stdout:
        issues.append(f"⚠ Secrets found:\n{stdout}")

    # Check script for common security issues
    with open(SCRIPT_PATH) as f:
        content = f.read()
        security_patterns = [
            (r"eval\s+", "Dangerous eval usage"),
            (r"\$\(.*\)", "Command substitution (verify safety)"),
            (r"rm\s+-rf\s+/", "Dangerous rm -rf pattern"),
        ]
        for pattern, desc in security_patterns:
            if re.search(pattern, content):
                issues.append(f"⚠ {desc} found - review for safety")

    status = "✓ No security issues found" if not issues else f"Found {len(issues)} warnings"
    return ToolResult(
        content=[TextContent(type="text", text=f"{status}\n\n{chr(10).join(issues)}")]
    )


async def validate_docs(args: dict) -> ToolResult:
    """Validate documentation completeness."""
    issues = []

    # Check for required documentation files
    required_docs = ["TESTING.md", "QUICKSTART-TESTING.md", "README.md"]
    for doc in required_docs:
        if not (PROJECT_ROOT / doc).exists():
            issues.append(f"Missing: {doc}")

    # Check script has main docstring
    with open(SCRIPT_PATH) as f:
        content = f.read()
        if not re.search(r"^#\s+.*Fedora.*Security", content, re.MULTILINE):
            issues.append("Script missing main header documentation")

    # Check all functions documented
    functions = re.findall(r"^([a-z_]+)\(\)\s*\{", content, re.MULTILINE)
    undocumented = []
    for func in functions:
        func_pattern = f"# {func}\\(\\)"
        if func_pattern not in content:
            undocumented.append(func)

    if undocumented:
        issues.append(f"Undocumented functions: {', '.join(undocumented[:5])}")

    status = (
        "✓ Documentation complete and consistent"
        if not issues
        else f"Found {len(issues)} documentation gaps"
    )
    return ToolResult(
        content=[TextContent(type="text", text=f"{status}\n\n{chr(10).join(issues)}")]
    )


async def analyze_performance(args: dict) -> ToolResult:
    """Analyze script performance metrics."""
    with open(SCRIPT_PATH) as f:
        content = f.read()

    metrics = {
        "total_lines": len(content.splitlines()),
        "functions": len(re.findall(r"^[a-z_]+\(\)", content, re.MULTILINE)),
        "comments": len(re.findall(r"^\s*#", content, re.MULTILINE)),
        "errors_handled": len(
            re.findall(r"\|\||\|\||&& \(set -e", content)
        ),
    }

    # Calculate complexity score
    complexity = metrics["functions"] * 5 + metrics["lines"] // 50
    metrics["estimated_complexity"] = "Low" if complexity < 50 else (
        "Medium" if complexity < 100 else "High"
    )

    # Test execution time (optional)
    if args.get("profile"):
        import time

        start = time.time()
        await run_command(["bash", "-n", str(SCRIPT_PATH)])
        metrics["syntax_check_ms"] = int((time.time() - start) * 1000)

    return ToolResult(
        content=[
            TextContent(
                type="text",
                text=f"Performance Analysis:\n{json.dumps(metrics, indent=2)}",
            )
        ]
    )


async def update_version(args: dict) -> ToolResult:
    """Update version number."""
    # This would need version file implementation
    bump = args.get("bump", "patch")
    dry_run = args.get("dry_run", True)

    return ToolResult(
        content=[
            TextContent(
                type="text",
                text=f"Version update ({bump}) - DRY RUN\nImplementation needed: version file management",
            )
        ]
    )


async def generate_changelog(args: dict) -> ToolResult:
    """Generate changelog from conventional commits."""
    since = args.get("since", "")
    dry_run = args.get("dry_run", True)

    cmd = ["git", "log", "--oneline"]
    if since:
        cmd.extend([f"{since}..HEAD"])

    rc, stdout, stderr = await run_command(cmd)

    changelog = "# Changelog\n\n"
    for line in stdout.splitlines()[:20]:  # Last 20 commits
        if line.strip():
            changelog += f"- {line}\n"

    return ToolResult(
        content=[TextContent(type="text", text=changelog)]
    )


async def create_release(args: dict) -> ToolResult:
    """Create a new release."""
    version = args.get("version")
    draft = args.get("draft", True)

    if not version:
        return ToolResult(
            content=[TextContent(type="text", text="Version required (e.g., 2.0.0)")],
            isError=True,
        )

    return ToolResult(
        content=[
            TextContent(
                type="text",
                text=f"Would create release {version} (draft={draft})\nImplementation needed: GitHub API integration",
            )
        ]
    )


async def quality_report(args: dict) -> ToolResult:
    """Generate comprehensive quality report."""
    report = {
        "generated": datetime.now().isoformat(),
        "script": str(SCRIPT_PATH),
        "sections": {},
    }

    # Syntax
    rc, _, _ = await run_command(["bash", "-n", str(SCRIPT_PATH)])
    report["sections"]["syntax"] = "PASS" if rc == 0 else "FAIL"

    # Tests
    rc, _, _ = await run_command(["./test-in-podman.sh", "--quick", "--dry-run"])
    report["sections"]["tests"] = "PASS" if rc == 0 else "WARN"

    # Linting
    rc, _, _ = await run_command(["shellcheck", str(SCRIPT_PATH)])
    report["sections"]["linting"] = "PASS" if rc == 0 else "WARN"

    # Docs
    required_docs = ["TESTING.md", "QUICKSTART-TESTING.md"]
    docs_complete = all((PROJECT_ROOT / doc).exists() for doc in required_docs)
    report["sections"]["documentation"] = "PASS" if docs_complete else "WARN"

    # Overall
    report["overall"] = "PASS" if all(
        v == "PASS" for v in report["sections"].values()
    ) else "WARN"

    return ToolResult(
        content=[
            TextContent(
                type="text",
                text=f"Quality Report:\n{json.dumps(report, indent=2)}",
            )
        ]
    )


async def setup_dev_environment(args: dict) -> ToolResult:
    """Setup development environment."""
    dry_run = args.get("dry_run", True)

    setup_steps = [
        "pip install pre-commit",
        "pre-commit install",
        "pre-commit install --hook-type commit-msg",
        "pip install shellcheck-py shfmt hadolint commitizen",
    ]

    if dry_run:
        return ToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Would execute (DRY RUN):\n" + "\n".join(f"  {step}" for step in setup_steps),
                )
            ]
        )
    else:
        results = []
        for step in setup_steps:
            rc, stdout, stderr = await run_command(step.split())
            results.append(f"{'✓' if rc == 0 else '✗'} {step}")

        return ToolResult(
            content=[TextContent(type="text", text="\n".join(results))]
        )


# ============================================================================
# Server Setup
# ============================================================================


async def main():
    """Start the MCP server."""
    async with stdio_server(server):
        pass


if __name__ == "__main__":
    asyncio.run(main())
