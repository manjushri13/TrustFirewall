"""Small MCP server used to exercise the TrustFirewall proxy."""

import os
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:
    from mcp.server.mcpserver import MCPServer as FastMCP


server = FastMCP("TrustFirewall Demo Server")


def _record_hello_call() -> None:
    counter_path = os.getenv("TRUSTFIREWALL_DEMO_COUNTER_FILE")
    if counter_path is None:
        return
    path = Path(counter_path)
    try:
        count = int(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        count = 0
    path.write_text(str(count + 1), encoding="utf-8")


@server.tool()
def hello(name: str) -> str:
    """Return a greeting from the demo MCP server."""
    _record_hello_call()
    return f"Hello, {name}! TrustFirewall Demo Server is working."


if __name__ == "__main__":
    server.run(transport="stdio")
