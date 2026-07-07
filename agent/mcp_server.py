"""
ClickFixed — MCP Server (Firestore Threat Intelligence Tools)
============================================================

This module implements a local MCP (Model Context Protocol) server that
exposes Firestore threat-intelligence operations as standardized tools
consumable by any MCP-compatible LLM agent.

In the ClickFixed architecture this file serves two roles:
  1. **Local Development / Hybrid Mode**: Run this as a subprocess MCP server
     and point the ADK pipeline's MCPToolset at it via stdio transport.
  2. **Reference Implementation**: Documents the tool schema consumed by the
     ADK Workflow agents in agent.py via Google's hosted Firestore MCP server.

Usage (local stdio transport):
    python mcp_server.py

ADK Agent Integration (see agent.py):
    from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, SseConnectionParams, StdioServerParameters

    # Option A — Google-hosted Firestore MCP (production, used in agent.py)
    firestore_tools, _exit_stack = await MCPToolset.from_server(
        connection_params=SseConnectionParams(
            url="https://firestore.googleapis.com/mcp",
            headers={"Authorization": f"Bearer {gcp_access_token}"}
        )
    )

    # Option B — This local MCP server (development / offline)
    firestore_tools, _exit_stack = await MCPToolset.from_server(
        connection_params=StdioServerParameters(
            command="python",
            args=["agent/mcp_server.py"]
        )
    )
"""

import asyncio
import json
import hashlib
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

# MCP Python SDK — installed via `pip install mcp`
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types as mcp_types

# ── Configuration ─────────────────────────────────────────────
FIRESTORE_PROJECT_ID = os.environ.get("FIRESTORE_PROJECT_ID", "")
FIRESTORE_COLLECTION = "clickfix_threats"
SIGNATURES_COLLECTION = "clickfix_signatures"


# ── Helpers ───────────────────────────────────────────────────

def _sha256(value: str) -> str:
    """Return a SHA-256 hex digest as a stable document ID."""
    return hashlib.sha256(value.encode()).hexdigest()


def _victim_origin(url: str) -> str:
    """
    Extract only the scheme+host from a URL.
    Privacy: never store path, query params, or fragments — only the origin.
    """
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return url


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _get_gcp_access_token() -> str | None:
    """Fetch GCP Access Token from instance metadata when running on Cloud Run."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "http://metadata.google.internal/computeMetadata/v1/instance/"
                "service-accounts/default/token",
                headers={"Metadata-Flavor": "Google"},
                timeout=2.0,
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
    except Exception:
        pass
    return None


async def _firestore_headers() -> dict:
    token = await _get_gcp_access_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def _firestore_base_url(collection: str, doc_id: str = "") -> str:
    path = f"{collection}/{doc_id}" if doc_id else collection
    return (
        f"https://firestore.googleapis.com/v1/projects/{FIRESTORE_PROJECT_ID}"
        f"/databases/(default)/documents/{path}"
    )


# ══ MCP Server Definition ═════════════════════════════════════

server = Server("clickfixed-firestore-mcp")


@server.list_tools()
async def list_tools() -> list[mcp_types.Tool]:
    """
    Advertise the available MCP tools to the LLM agent.
    The ADK MCPToolset discovers these at runtime and makes them
    available as callable functions during agent inference.
    """
    return [
        mcp_types.Tool(
            name="store_threat_report",
            description=(
                "Persist a ClickFix threat report to Firestore. "
                "Uses SHA-256(culprit_js_url) as the document ID to deduplicate reports "
                "from multiple victim origins. Only the culprit asset URL and victim "
                "origin (scheme+host) are stored — never full URLs with query parameters."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "victim_url": {
                        "type": "string",
                        "description": "Full URL of the compromised page (sanitized to origin before storage)"
                    },
                    "culprit_js_url": {
                        "type": "string",
                        "description": "URL of the malicious JavaScript asset injected by the attacker"
                    },
                    "clipboard_payload": {
                        "type": "string",
                        "description": "The raw clipboard payload intercepted from the attack"
                    },
                    "patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Regex signature patterns generated by the Threat Intel Synthesizer agent"
                    },
                    "security_assessment": {
                        "type": "string",
                        "description": "CSP/header audit output from the Security Auditor agent"
                    },
                    "privacy_assessment": {
                        "type": "string",
                        "description": "Tracker/pixel analysis output from the Privacy Auditor agent"
                    },
                    "malware_analysis": {
                        "type": "string",
                        "description": "De-obfuscation report from the Malware Analyst agent"
                    }
                },
                "required": ["victim_url", "clipboard_payload"]
            }
        ),
        mcp_types.Tool(
            name="check_duplicate_threat",
            description=(
                "Check whether a threat from this culprit URL has already been reported. "
                "Returns existing doc metadata if found, or null if this is a new threat. "
                "Use this before calling store_threat_report to avoid redundant submissions."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "culprit_js_url": {
                        "type": "string",
                        "description": "URL of the malicious JavaScript asset to look up"
                    }
                },
                "required": ["culprit_js_url"]
            }
        ),
        mcp_types.Tool(
            name="get_active_signatures",
            description=(
                "Fetch the current list of active regex threat signatures from Firestore "
                "(clickfix_signatures/active). These patterns are used by the Chrome extension "
                "for fast, local pre-screening of clipboard payloads."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        mcp_types.Tool(
            name="publish_signatures",
            description=(
                "Merge new regex patterns into the active signatures feed in Firestore "
                "(clickfix_signatures/active). The extension polls this endpoint to immunize "
                "itself against newly-discovered attack patterns. Deduplicates before writing."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "New regex signatures to merge into the global feed"
                    }
                },
                "required": ["patterns"]
            }
        ),
    ]


@server.call_tool()
async def call_tool(
    name: str,
    arguments: dict
) -> list[mcp_types.TextContent]:
    """
    Dispatch MCP tool calls from the LLM to the appropriate Firestore operation.
    Each tool maps to a REST call to the Firestore v1 API, authenticated with
    a GCP service-account token fetched from the instance metadata service.
    """
    if not FIRESTORE_PROJECT_ID:
        return [mcp_types.TextContent(
            type="text",
            text=json.dumps({"error": "FIRESTORE_PROJECT_ID environment variable not set."})
        )]

    headers = await _firestore_headers()

    # ── Tool: check_duplicate_threat ──────────────────────────
    if name == "check_duplicate_threat":
        culprit_js_url = arguments.get("culprit_js_url", "")
        if not culprit_js_url:
            return [mcp_types.TextContent(type="text", text=json.dumps({"exists": False}))]

        doc_id = _sha256(culprit_js_url)
        url = _firestore_base_url(FIRESTORE_COLLECTION, doc_id)

        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code == 200:
            fields = resp.json().get("fields", {})
            report_count = fields.get("report_count", {}).get("integerValue", "1")
            first_seen = fields.get("first_seen", {}).get("stringValue", "")
            return [mcp_types.TextContent(type="text", text=json.dumps({
                "exists": True,
                "doc_id": doc_id,
                "report_count": int(report_count),
                "first_seen": first_seen
            }))]

        return [mcp_types.TextContent(type="text", text=json.dumps({"exists": False}))]

    # ── Tool: store_threat_report ─────────────────────────────
    elif name == "store_threat_report":
        victim_url = arguments.get("victim_url", "")
        culprit_js_url = arguments.get("culprit_js_url", "")
        clipboard_payload = arguments.get("clipboard_payload", "")
        patterns = arguments.get("patterns", [])
        security_assessment = arguments.get("security_assessment", "")
        privacy_assessment = arguments.get("privacy_assessment", "")
        malware_analysis = arguments.get("malware_analysis", "")

        # Privacy: store only the origin, never the full URL
        origin = _victim_origin(victim_url)
        doc_id = _sha256(culprit_js_url) if culprit_js_url else _sha256(clipboard_payload)
        url = _firestore_base_url(FIRESTORE_COLLECTION, doc_id)

        # Fetch existing record for deduplication / incrementing report_count
        existing_origins = [origin]
        report_count = 1
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                fields = resp.json().get("fields", {})
                origins_vals = (
                    fields.get("victim_origins", {})
                    .get("arrayValue", {})
                    .get("values", [])
                )
                existing_list = [v.get("stringValue") for v in origins_vals if "stringValue" in v]
                if origin not in existing_list:
                    existing_list.append(origin)
                existing_origins = existing_list
                report_count = int(fields.get("report_count", {}).get("integerValue", "1")) + 1

        body = {
            "fields": {
                "culprit_js_url": {"stringValue": culprit_js_url or ""},
                "victim_origins": {
                    "arrayValue": {"values": [{"stringValue": o} for o in existing_origins]}
                },
                "payload_hash": {"stringValue": _sha256(clipboard_payload)},
                "first_seen": {"stringValue": _now_iso()},
                "last_seen": {"stringValue": _now_iso()},
                "report_count": {"integerValue": str(report_count)},
                "patterns": {
                    "arrayValue": {"values": [{"stringValue": p} for p in patterns]}
                },
                "security_assessment": {"stringValue": security_assessment},
                "privacy_assessment": {"stringValue": privacy_assessment},
                "malware_analysis": {"stringValue": malware_analysis},
            }
        }

        patch_url = (
            url
            + "?updateMask.fieldPaths=culprit_js_url"
            + "&updateMask.fieldPaths=victim_origins"
            + "&updateMask.fieldPaths=payload_hash"
            + "&updateMask.fieldPaths=last_seen"
            + "&updateMask.fieldPaths=report_count"
            + "&updateMask.fieldPaths=patterns"
            + "&updateMask.fieldPaths=security_assessment"
            + "&updateMask.fieldPaths=privacy_assessment"
            + "&updateMask.fieldPaths=malware_analysis"
        )
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.patch(patch_url, headers=headers, json=body)

        success = resp.status_code in (200, 201)
        return [mcp_types.TextContent(type="text", text=json.dumps({
            "stored": success,
            "doc_id": doc_id,
            "report_count": report_count,
            "http_status": resp.status_code
        }))]

    # ── Tool: get_active_signatures ───────────────────────────
    elif name == "get_active_signatures":
        url = _firestore_base_url(SIGNATURES_COLLECTION, "active")
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code == 200:
            vals = (
                resp.json()
                .get("fields", {})
                .get("patterns", {})
                .get("arrayValue", {})
                .get("values", [])
            )
            patterns = [v.get("stringValue") for v in vals if "stringValue" in v]
            return [mcp_types.TextContent(type="text", text=json.dumps({
                "count": len(patterns),
                "patterns": patterns
            }))]

        return [mcp_types.TextContent(type="text", text=json.dumps({"count": 0, "patterns": []}))]

    # ── Tool: publish_signatures ──────────────────────────────
    elif name == "publish_signatures":
        new_patterns = arguments.get("patterns", [])

        # Fetch current signatures for deduplication merge
        existing_url = _firestore_base_url(SIGNATURES_COLLECTION, "active")
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(existing_url, headers=headers)

        current_patterns = []
        if resp.status_code == 200:
            vals = (
                resp.json()
                .get("fields", {})
                .get("patterns", {})
                .get("arrayValue", {})
                .get("values", [])
            )
            current_patterns = [v.get("stringValue") for v in vals if "stringValue" in v]

        # Deduplicate merge
        merged = list(set(current_patterns) | {p for p in new_patterns if p})

        body = {
            "fields": {
                "patterns": {
                    "arrayValue": {"values": [{"stringValue": p} for p in merged]}
                }
            }
        }
        patch_url = existing_url + "?updateMask.fieldPaths=patterns"
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.patch(patch_url, headers=headers, json=body)

        return [mcp_types.TextContent(type="text", text=json.dumps({
            "published": resp.status_code in (200, 201),
            "total_signatures": len(merged),
            "new_signatures_added": len(merged) - len(current_patterns),
            "http_status": resp.status_code
        }))]

    else:
        return [mcp_types.TextContent(
            type="text",
            text=json.dumps({"error": f"Unknown tool: {name}"})
        )]


# ══ Entry Point ═══════════════════════════════════════════════

async def main():
    """Run the MCP server using stdio transport (standard MCP convention)."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
