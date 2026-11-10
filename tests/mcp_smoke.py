#!/usr/bin/env python3
"""Smoke test for mcp_server_fedora_harden.py over real MCP stdio transport.

Starts the server, lists its tools and calls the side-effect-free ones.
Exit code 0 on success. Usage: python3 tests/mcp_smoke.py <path-to-server.py>
"""

from __future__ import annotations

import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED_TOOLS = {
    "analyze-performance",
    "check-security",
    "generate-changelog",
    "lint-script",
    "quality-report",
    "setup-dev-environment",
    "test-script",
    "validate-docs",
    "verify-script",
}


def is_error(result: object) -> bool:
    # mcp 1.x uses isError, 2.x uses is_error
    return bool(getattr(result, "is_error", getattr(result, "isError", False)))


async def main(server: str) -> int:
    failures: list[str] = []
    params = StdioServerParameters(command=sys.executable, args=[server])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = {t.name for t in (await session.list_tools()).tools}
        if tools != EXPECTED_TOOLS:
            failures.append(f"tool set mismatch: {sorted(tools ^ EXPECTED_TOOLS)}")

        calls = {
            "analyze-performance": ({"profile": True}, '"total_lines"'),
            "validate-docs": ({}, "Documentation:"),
            # Input validation must reject shell metacharacters before running anything
            "test-script": ({"section": "5; rm -rf /"}, "Invalid section list"),
        }
        for name, (args, expect) in calls.items():
            result = await session.call_tool(name, args)
            text = result.content[0].text if result.content else ""
            status = "ok" if (not is_error(result) and expect in text) else "FAIL"
            print(f"{status}: {name} -> {text.splitlines()[0] if text else '(empty)'}")
            if status != "ok":
                failures.append(f"{name}: expected {expect!r} in output")

    for failure in failures:
        print(f"FAIL: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1])))
