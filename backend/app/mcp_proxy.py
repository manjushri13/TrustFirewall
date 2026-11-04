"""MCP stdio proxy that gates upstream tools through TrustFirewall.

This proxy only intercepts MCP tools routed through it. It does not intercept
VS Code built-in tools or Copilot tools that are configured outside this server.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

from .models import (
    ActionProposal,
    DocumentFinding,
    DocumentProvenance,
    ProvenanceSource,
    TrustLevel,
)


def build_action_proposal(
    request_id: str | int,
    tool_name: str,
    arguments: dict[str, Any],
) -> tuple[ActionProposal, dict[str, Any]]:
    forwarded_arguments = dict(arguments)
    raw_provenance = forwarded_arguments.pop("_trustfirewall_provenance", [])
    approval_request_id = forwarded_arguments.pop("_trustfirewall_approval_request_id", None)
    workflow_id = forwarded_arguments.pop("_trustfirewall_workflow_id", None)
    provenance_refs = forwarded_arguments.pop("_trustfirewall_provenance_refs", [])
    permissions = forwarded_arguments.pop("_trustfirewall_permissions", [])
    user_task = forwarded_arguments.pop("_trustfirewall_user_task", None)
    raw_document_provenance = forwarded_arguments.pop(
        "_trustfirewall_document_provenance",
        [],
    )
    raw_document_findings = forwarded_arguments.pop(
        "_trustfirewall_document_findings",
        [],
    )
    action_fingerprint = hashlib.sha256(
        json.dumps(
            {"tool": tool_name, "arguments": forwarded_arguments},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:24]
    provenance = [
        ProvenanceSource.model_validate(item).model_copy(
            update={"trust_level": TrustLevel.UNKNOWN}
        )
        for item in raw_provenance
    ]
    proposal = ActionProposal(
        action_id=f"mcp-{tool_name}-{action_fingerprint}",
        action_type="mcp_tool_call",
        description=f"Call MCP tool '{tool_name}' with structured arguments.",
        target=tool_name,
        permissions=permissions,
        provenance=provenance,
        provenance_refs=provenance_refs,
        approval_request_id=approval_request_id,
        workflow_id=workflow_id,
        user_task=user_task,
        document_provenance=[
            DocumentProvenance.model_validate(item).model_copy(
                update={"trust_level": TrustLevel.UNTRUSTED}
            )
            for item in raw_document_provenance
        ],
        document_findings=[
            DocumentFinding.model_validate(item)
            for item in raw_document_findings
        ],
    )
    return proposal, forwarded_arguments


class MCPProxy:
    def __init__(self, api_url: str, upstream_command: str) -> None:
        self.api_url = api_url.rstrip("/")
        self.upstream_command = upstream_command
        self.upstream: subprocess.Popen[str] | None = None

    def start(self) -> None:
        command = shlex.split(self.upstream_command, posix=False)
        if not command:
            raise ValueError("TRUSTFIREWALL_UPSTREAM_COMMAND must not be empty.")
        self.upstream = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

    def stop(self) -> None:
        if self.upstream and self.upstream.poll() is None:
            self.upstream.terminate()

    def forward(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if self.upstream is None or self.upstream.stdin is None or self.upstream.stdout is None:
            raise RuntimeError("The upstream MCP server is not running.")
        self.upstream.stdin.write(json.dumps(request) + "\n")
        self.upstream.stdin.flush()
        if "id" not in request:
            return None
        for line in self.upstream.stdout:
            response = json.loads(line)
            if response.get("id") == request.get("id"):
                return response
        raise RuntimeError("The upstream MCP server closed its output.")

    def gate(self, proposal: ActionProposal) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.api_url}/api/intercept",
            data=json.dumps(proposal.model_dump(mode="json")).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"TrustFirewall gate rejected the request: {detail}") from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"TrustFirewall API is unavailable: {error.reason}") from error

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if request.get("method") != "tools/call":
            return self.forward(request)

        params = request.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or not isinstance(arguments, dict):
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32602, "message": "tools/call requires a name and object arguments."},
            }
        proposal, forwarded_arguments = build_action_proposal(
            request.get("id", "unknown"),
            tool_name,
            arguments,
        )
        gate_result = self.gate(proposal)
        decision = gate_result.get("decision")
        execution = gate_result.get("execution")
        if decision not in {"allow", "flag", "block"} or (
            decision == "allow" and execution != "allowed"
        ) or (decision != "allow" and execution == "allowed"):
            raise RuntimeError("TrustFirewall returned an invalid or unsafe gate decision.")
        if execution != "allowed":
            message = (
                "MCP tool call blocked by TrustFirewall."
                if gate_result["decision"] == "block"
                else "MCP tool call is pending explicit TrustFirewall approval."
            )
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {
                    "code": -32001 if gate_result["decision"] == "block" else -32002,
                    "message": message,
                    "data": {
                        "request_id": gate_result["request_id"],
                        "decision": gate_result["decision"],
                        "risk_score": gate_result["risk_score"],
                        "recommended_next_step": gate_result["recommended_next_step"],
                    },
                },
            }
        forwarded_request = dict(request)
        forwarded_request["params"] = dict(params)
        forwarded_request["params"]["arguments"] = forwarded_arguments
        return self.forward(forwarded_request)


def _requests(stream: Iterator[str]) -> Iterator[dict[str, Any]]:
    for line in stream:
        if line.strip():
            yield json.loads(line)


def main() -> int:
    parser = argparse.ArgumentParser(description="TrustFirewall MCP stdio proxy")
    parser.add_argument(
        "--api-url",
        default=os.getenv("TRUSTFIREWALL_API_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "upstream",
        nargs="?",
        default=os.getenv("TRUSTFIREWALL_UPSTREAM_COMMAND"),
        help="Command for the upstream MCP server.",
    )
    args = parser.parse_args()
    if not args.upstream:
        parser.error("Provide an upstream command or TRUSTFIREWALL_UPSTREAM_COMMAND.")
    proxy = MCPProxy(args.api_url, args.upstream)
    proxy.start()
    try:
        for request in _requests(sys.stdin):
            response = proxy.handle(request)
            if response is not None:
                print(json.dumps(response), flush=True)
    finally:
        proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
