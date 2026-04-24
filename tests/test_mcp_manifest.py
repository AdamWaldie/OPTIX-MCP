"""End-to-end manifest test for the OPTIX MCP stdio server.

Spawns stdio.py as a subprocess (using OPTIX_INTERNAL_SECRET to bypass the
live API-key check), then exercises the MCP initialize / tools/list /
prompts/list requests and asserts that exactly 28 tools and 2 prompts are
advertised.

Run with:
    pytest "OPTIX MCP/tests/test_mcp_manifest.py"
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

MCP_DIR = Path(__file__).parent.parent
STUB_KEY = "stub-key-for-test"

EXPECTED_TOOL_COUNT = 28
EXPECTED_TOOL_NAMES = {
    "feed.get",
    "search.indicator",
    "incident.report",
    "entity.get",
    "account.status",
    "document.get",
    "search.documents",
    "report.list",
    "report.get",
    "detection.attack_matrix",
    "watchlist.list",
    "watchlist.add",
    "watchlist.remove",
    "feed.headlines",
    "feed.cards",
    "ioc.context",
    "detection.coverage_gaps",
    "search.ai",
    "entity.research",
    "entity.ask",
    "detection.rule",
    "detection.tradecraft",
    "report.generate",
    "feedback.vote",
    "feed.save_view",
    "ioc.triage",
    "actor.profile",
    "actor.list",
}

EXPECTED_PROMPT_COUNT = 2
EXPECTED_PROMPT_NAMES = {"threat-brief", "ioc-triage"}


def _build_env() -> dict[str, str]:
    """Build the subprocess environment.

    Starts from the full inherited environment so that installed packages
    (e.g. those in .pythonlibs) remain discoverable, then overrides the
    OPTIX credentials with the internal-secret stub that bypasses the live
    API-key validation in auth.py.
    """
    env = os.environ.copy()
    env["OPTIX_API_KEY"] = STUB_KEY
    env["OPTIX_INTERNAL_SECRET"] = STUB_KEY
    return env


async def _fetch_manifest() -> tuple[set[str], set[str]]:
    """Launch the stdio server and return (tool_names, prompt_names)."""
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["stdio.py"],
        env=_build_env(),
        cwd=MCP_DIR,
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            prompts_result = await session.list_prompts()

    tool_names = {t.name for t in tools_result.tools}
    prompt_names = {p.name for p in prompts_result.prompts}
    return tool_names, prompt_names


def test_tools_and_prompts_manifest() -> None:
    """stdio.py must advertise exactly 28 tools and 2 prompts."""
    tool_names, prompt_names = asyncio.run(_fetch_manifest())

    missing_tools = EXPECTED_TOOL_NAMES - tool_names
    extra_tools = tool_names - EXPECTED_TOOL_NAMES

    assert len(tool_names) == EXPECTED_TOOL_COUNT, (
        f"Expected {EXPECTED_TOOL_COUNT} tools, got {len(tool_names)}.\n"
        f"Extra: {extra_tools}\n"
        f"Missing: {missing_tools}"
    )
    assert tool_names == EXPECTED_TOOL_NAMES, (
        f"Tool name mismatch.\nExtra: {extra_tools}\nMissing: {missing_tools}"
    )

    missing_prompts = EXPECTED_PROMPT_NAMES - prompt_names
    extra_prompts = prompt_names - EXPECTED_PROMPT_NAMES

    assert len(prompt_names) == EXPECTED_PROMPT_COUNT, (
        f"Expected {EXPECTED_PROMPT_COUNT} prompts, got {len(prompt_names)}.\n"
        f"Extra: {extra_prompts}\n"
        f"Missing: {missing_prompts}"
    )
    assert prompt_names == EXPECTED_PROMPT_NAMES, (
        f"Prompt name mismatch.\nExtra: {extra_prompts}\nMissing: {missing_prompts}"
    )
