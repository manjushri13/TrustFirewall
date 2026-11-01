# TrustFirewall MCP proxy

## What is intercepted

VS Code supports MCP servers, but its public extension API does not expose a
general pre-execution hook for every built-in Copilot or extension tool. The
TrustFirewall integration therefore provides an honest MCP stdio proxy:

```text
VS Code / compatible MCP client
        |
        v
TrustFirewall MCP proxy -- POST /api/intercept --> FastAPI policy engine
        |
        v
configured upstream MCP server
```

Only MCP `tools/call` messages routed through this proxy are intercepted.
Native VS Code/Copilot tools configured outside the proxy are not intercepted.
Do not describe this integration as a global VS Code tool hook.

## Run the proxy

Start the policy API first:

```powershell
Set-Location .\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Set the command for the upstream MCP server and start the proxy:

```powershell
$env:TRUSTFIREWALL_UPSTREAM_COMMAND = "python path\to\upstream_server.py"
Set-Location .\backend
$env:PYTHONPATH = (Get-Location).Path
.\.venv\Scripts\python.exe -m app.mcp_proxy
```

The proxy also accepts `--api-url` and an upstream command positional argument.
It uses newline-delimited JSON-RPC over stdin/stdout and writes no protocol
diagnostics to stdout. JSON-RPC notifications are forwarded without waiting for
a response, as required by MCP clients.

## Run the demo MCP server through TrustFirewall

The demo server is a harmless test server with one `hello` tool. It is not a
production MCP server.

In **Terminal 1**, from the project root, start the FastAPI policy backend:

```powershell
Set-Location .\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

In **Terminal 2**, from the project root, start the TrustFirewall proxy with
the demo server as its upstream:

```powershell
Set-Location .\backend
$env:PYTHONPATH = (Get-Location).Path
.\.venv\Scripts\python.exe -m app.mcp_proxy ".\.venv\Scripts\python.exe .\demo_mcp_server.py"
```

An MCP client can now connect to the proxy's stdin/stdout. The client sends
`initialize`, lists tools, and calls `hello`; the proxy sends the tool call to
the policy API before forwarding an allowed request to the demo server. The
proxy removes TrustFirewall control metadata before the upstream call and
keeps protocol responses on stdout. This demo does not provide a client or a
production deployment configuration.

## Provenance metadata

MCP clients can attach optional control metadata in the tool arguments:

```json
{
  "_trustfirewall_permissions": ["read_sensitive"],
  "_trustfirewall_provenance": [
    {
      "source_id": "agent-system-policy",
      "source_type": "system_policy",
      "trust_level": "trusted",
      "content": "Read only the requested project notes."
    }
  ]
}
```

The submitted `trust_level` is never accepted as proof of trust. The proxy
downgrades external provenance metadata to `unknown`; trusted system or user
instructions must be created through the backend's trusted-source path.

The proxy removes these `_trustfirewall_*` fields before forwarding an allowed
call upstream. If provenance is omitted, the policy engine flags the call and
the upstream tool is not called.

## Decisions

- `allow`: forwarded to the upstream MCP server.
- `flag`: returned as a JSON-RPC error with an approval request ID. The
  dashboard can approve or deny it. A compatible client may retry with
  `_trustfirewall_approval_request_id` set to the approved ID.
- `block`: returned as a JSON-RPC error and never forwarded. Dashboard approval
  cannot override a deterministic block.

The approval and audit state is currently in memory for this prototype. Restarting
the FastAPI process clears pending requests and the dashboard history.
