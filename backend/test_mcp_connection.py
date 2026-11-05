"""End-to-end MCP client for the TrustFirewall proxy demo."""

from __future__ import annotations

import asyncio
import os
import sys
import traceback
import urllib.error
import urllib.request
import json
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


BACKEND_DIR = Path(__file__).resolve().parent
API_URL = os.getenv("TRUSTFIREWALL_API_URL", "http://127.0.0.1:8001")
NAME = "TrustFirewall"
WORKFLOW_ID = "mcp-connection-test"


def _get_json(path: str) -> Any:
    with urllib.request.urlopen(f"{API_URL}{path}", timeout=5) as response:
        return json.load(response)


def _check_backend() -> None:
    try:
        health = _get_json("/health")
    except (urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError(
            "FastAPI is not running. Start it in another terminal before this test."
        ) from error
    if health.get("status") != "ok":
        raise RuntimeError(f"FastAPI health check failed: {health!r}")


def _text_from_result(result: Any) -> str:
    return "\n".join(
        item.text
        for item in result.content
        if hasattr(item, "text")
    )


async def _run_connection_test() -> None:
    _check_backend()
    upstream_command = r".\.venv\Scripts\python.exe .\demo_mcp_server.py"
    proxy_parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "app.mcp_proxy", upstream_command],
        cwd=BACKEND_DIR,
        env={**os.environ, "PYTHONPATH": str(BACKEND_DIR)},
    )

    async with stdio_client(proxy_parameters) as (read_stream, write_stream):
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=15,
        ) as session:
            print("PASS: proxy subprocess started.")
            await session.initialize()
            print("PASS: MCP initialize completed.")
            tools = await session.list_tools()
            tool_names = {tool.name for tool in tools.tools}
            if "hello" not in tool_names:
                raise RuntimeError(f"hello was not discoverable; tools={sorted(tool_names)}")
            print("PASS: hello is discoverable through the TrustFirewall proxy.")

            result = await session.call_tool(
                "hello",
                {
                    "name": NAME,
                    "_trustfirewall_workflow_id": WORKFLOW_ID,
                    "_trustfirewall_provenance": [
                        {
                            "source_id": "mcp-client-test",
                            "source_type": "web_content",
                            "trust_level": "unknown",
                            "content": "Use the hello tool for a harmless greeting.",
                        }
                    ],
                },
            )
            if result.is_error:
                raise RuntimeError(f"hello was rejected by the proxy: {result!r}")
            greeting = _text_from_result(result)
            expected = f"Hello, {NAME}!"
            if expected not in greeting:
                raise RuntimeError(f"Unexpected greeting: {greeting!r}")
            print(f"PASS: hello returned {greeting}")

    audit_events = _get_json("/api/audit")
    matching_events = [
        event
        for event in audit_events
        if event.get("action_id", "").startswith("mcp-hello-")
        and event.get("workflow_id") == WORKFLOW_ID
    ]
    if not matching_events:
        raise RuntimeError("No matching TrustFirewall audit record was found.")
    event = matching_events[0]
    if event.get("decision") != "allow" or event.get("status") != "allowed":
        raise RuntimeError(f"Audit record was not allowed: {event!r}")
    print("PASS: FastAPI returned allow and recorded an allowed audit event.")


def main() -> int:
    try:
        asyncio.run(_run_connection_test())
    except Exception as error:
        traceback.print_exception(error)
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: end-to-end MCP connection verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
