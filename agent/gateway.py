"""
ClickFixed — Gateway Proxy
==========================

Public web-facing endpoint deployed to Cloud Run.
Acts as a security proxy and routing layer:
  1. Serves GET /signatures (fetches directly from Firestore).
  2. Serves POST /analyze (direct low-latency model call to Gemini).
  3. Serves POST /a2a/handoff (authenticates and invokes the deployed Vertex AI Agent Engine pipeline).
"""

import asyncio
import os
import re
import vertexai
from vertexai.preview import reasoning_engines
from starlette.applications import Starlette
from starlette.responses import JSONResponse
import httpx

# ── Configuration ─────────────────────────────────────────────
GOOGLE_API_KEY                = os.environ.get("GOOGLE_API_KEY", "")
FIRESTORE_PROJECT_ID          = os.environ.get("FIRESTORE_PROJECT_ID", "")
REASONING_ENGINE_DISPLAY_NAME = os.environ.get("REASONING_ENGINE_DISPLAY_NAME", "ClickFixed Threat Pipeline")
LOCATION                      = os.environ.get("LOCATION", "us-central1")
GEMINI_MODEL                  = "gemini-2.5-flash"

ANALYSIS_PROMPT = (
    "You are a cybersecurity threat analysis agent specializing in ClickFix social engineering attacks.\n"
    "ClickFix (ClearFake, FakeUpdates) tricks users into pasting malicious terminal commands from their clipboard.\n"
    "Look for: PowerShell, mshta, wscript, cmd /c, iex, Invoke-Expression, curl/wget downloads, Base64 payloads, "
    "-WindowStyle Hidden, -ExecutionPolicy Bypass, certutil, bitsadmin, rundll32.\n"
    "Respond ONLY with a valid JSON object — no markdown, no code fences:\n"
    '{"malicious": true, "reason": "concise explanation"} or {"malicious": false, "reason": "brief explanation"}'
)

# Initialize Vertex AI
if FIRESTORE_PROJECT_ID:
    vertexai.init(project=FIRESTORE_PROJECT_ID, location=LOCATION)

_cached_engine = None

async def get_reasoning_engine():
    global _cached_engine
    if _cached_engine is not None:
        return _cached_engine
    
    if not FIRESTORE_PROJECT_ID:
        print("[ClickFixed Gateway] FIRESTORE_PROJECT_ID is not configured.")
        return None
        
    try:
        loop = asyncio.get_running_loop()
        engines = await loop.run_in_executor(
            None,
            lambda: reasoning_engines.ReasoningEngine.list(
                filter=f'display_name="{REASONING_ENGINE_DISPLAY_NAME}"'
            )
        )
        if engines:
            _cached_engine = engines[0]
            print(f"[ClickFixed Gateway] Resolved Reasoning Engine: {_cached_engine.resource_name}")
            return _cached_engine
        else:
            print(f"[ClickFixed Gateway] No deployed Reasoning Engine found with display name: {REASONING_ENGINE_DISPLAY_NAME}")
    except Exception as exc:
        print(f"[ClickFixed Gateway] Error listing/resolving Reasoning Engines: {exc}")
    return None


async def _get_gcp_access_token() -> str | None:
    """Fetch GCP Access Token from instance metadata service when running on Cloud Run."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                headers={"Metadata-Flavor": "Google"},
                timeout=2.0
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
    except Exception:
        pass
    return None


async def _fetch_signatures_from_firestore(project_id: str) -> list:
    """Fetch patterns array from clickfix_signatures/active in Firestore."""
    token = await _get_gcp_access_token()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/clickfix_signatures/active"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                patterns_val = data.get("fields", {}).get("patterns", {}).get("arrayValue", {}).get("values", [])
                return [item.get("stringValue") for item in patterns_val if "stringValue" in item]
    except Exception as exc:
        print(f"[ClickFixed Gateway] Firestore signature lookup failed: {exc}")
    return []


# ── Endpoint Handlers ─────────────────────────────────────────

async def get_signatures(request):
    """
    Exposes the latest threat signature regexes.
    Attempts to read from Firestore (collection: clickfix_signatures, doc: active).
    Falls back to a static list if Firestore is empty or unreachable.
    """
    default_signatures = [
        "powershell",
        "\\bpwsh\\b",
        "wscript",
        "mshta",
        "cscript",
        "cmd\\s*\\/[cCkK]",
        "\\biex\\b",
        "invoke-expression",
        "invoke-webrequest",
        "\\bcurl\\b.*http",
        "\\bwget\\b.*http",
        "bitsadmin",
        "certutil",
        "-windowstyle\\s+hidden",
        "-w\\s+hidden",
        "-noninteractive",
        "-encodedcommand",
        "-enc\\b",
        "-executionpolicy\\s+bypass",
        "-exec\\s+bypass",
        "-ep\\s+bypass",
        "-noprofile",
        "-nop\\b",
        "start-process",
        "\\.downloadstring\\(",
        "\\.downloadfile\\(",
        "new-object\\s+net\\.webclient",
        "shellexecute",
        "regsvr32",
        "rundll32",
        "schtasks",
        "reg\\s+add",
        "scrobj\\.dll",
        "\\\\\\\\[a-z0-9\\-]+\\\\"
    ]
    
    if FIRESTORE_PROJECT_ID:
        signatures = await _fetch_signatures_from_firestore(FIRESTORE_PROJECT_ID)
        if signatures:
            return JSONResponse({"signatures": signatures})
            
    return JSONResponse({"signatures": default_signatures})


async def analyze_endpoint(request):
    """
    Relays threat analysis requests to Gemini using the Cloud Agent's API Key
    or Vertex AI, eliminating the need for clients to configure their own local keys.
    """
    try:
        body = await request.json()
        payload = body.get("payload", "")
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)

    if not payload:
        return JSONResponse({"malicious": False, "reason": "Empty payload"})

    from google import genai
    from google.genai import types
    import json

    prompt = f"Analyze this intercepted clipboard payload:\n\n---\n{payload[:2500]}\n---"

    try:
        if GOOGLE_API_KEY:
            client = genai.Client(api_key=GOOGLE_API_KEY)
        else:
            client = genai.Client(vertexai=True, project=FIRESTORE_PROJECT_ID, location=LOCATION)

        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=ANALYSIS_PROMPT,
                    temperature=0.2,
                    response_mime_type="application/json"
                )
            )
        )
        raw_text = response.text
        match = re.search(r"\{[\s\S]*?\}", raw_text)
        if not match:
            raise ValueError(f"No JSON found in model output: {raw_text[:100]}")
        result = json.loads(match.group(0))
        return JSONResponse({
            "malicious": bool(result.get("malicious", False)),
            "reason": str(result.get("reason", "Analyzed by Cloud Agent"))
        })
    except Exception as exc:
        print(f"[ClickFixed Gateway] Cloud Agent developer API analysis failed: {exc}")
        return JSONResponse({
            "malicious": False,
            "reason": f"Analysis error on cloud agent: {str(exc)}"
        })


async def run_pipeline_task(body: dict):
    """Invokes the remote Reasoning Engine pipeline asynchronously in the background."""
    try:
        engine = await get_reasoning_engine()
        if not engine:
            print("[ClickFixed Gateway] Skip invoking: No reasoning engine resolved yet.")
            return

        loop = asyncio.get_running_loop()
        def invoke_stream():
            # Invoke the remote Reasoning Engine's stream_query method
            events = engine.stream_query(
                message=body,
                user_id="extension_sensor"
            )
            for event in events:
                # Traces the reasoning progress in the container logs
                print(f"[ClickFixed Gateway] reasoning-step: {event}")
        
        await loop.run_in_executor(None, invoke_stream)
    except Exception as exc:
        print(f"[ClickFixed Gateway] Error running remote pipeline: {exc}")


async def handoff_endpoint(request):
    """
    A2A Handoff Endpoint. Receives telemetry, forwards it to Vertex AI Agent Engine
    asynchronously, and returns a fast HTTP 200 response to the client extension.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)
        
    # Dispatch reasoning engine workflow asynchronously
    asyncio.create_task(run_pipeline_task(body))
    
    return JSONResponse({"status": "received", "message": "Workflow started successfully."})


async def get_agent_card(request):
    """
    Exposes the A2A Agent Card JSON metadata manifest for discovery.
    """
    card_data = {
        "name": "ClickFixed Threat Pipeline",
        "displayName": "ClickFixed Threat Pipeline",
        "description": "Multi-agent threat intelligence pipeline that audits DOM parameters and clipboard command payloads for ClickFix/ClearFake attacks.",
        "supported_protocols": ["a2a"],
        "a2a_handoff_url": "https://your-cloud-run-url.run.app/a2a/handoff",
        "input_schema": {
            "type": "object",
            "properties": {
                "victim_url": {"type": "string"},
                "culprit_js_url": {"type": "string"},
                "clipboard_payload": {"type": "string"},
                "raw_dom": {"type": "string"}
            },
            "required": ["victim_url", "clipboard_payload"]
        }
    }
    return JSONResponse(card_data)


# ── App Setup ─────────────────────────────────────────────────

a2a_app = Starlette()
a2a_app.add_route("/signatures", get_signatures, methods=["GET"])
a2a_app.add_route("/analyze", analyze_endpoint, methods=["POST"])
a2a_app.add_route("/a2a/handoff", handoff_endpoint, methods=["POST"])
a2a_app.add_route("/.well-known/agent-card.json", get_agent_card, methods=["GET"])
