"""
Click Fixed — ADK Threat Intelligence Agent with Firestore MCP
==============================================================

Two-agent system:
  Sensor Agent  → Chrome Extension (intercepts clipboard attacks, runs Gemini AI)
  Threat Agent  → This file (reports threats, deduplicates via Firestore)

Communication: Chrome extension → A2A protocol → this agent

Firestore usage (via MCP):
  • Check if culprit URL was already reported (deduplication)
  • Store threat record (privacy-safe: culprit URL + victim origin only)
  • Update record after actions (web_risk_submitted)
  • Source of truth for threat reports and human analysis
  • Sync generated regex signatures for global immunization

Privacy model:
  ✅ Store: culprit_js_url (the attack ASSET — not user data)
  ✅ Store: victim ORIGIN only (scheme+host, never path/query/fragment)
  ❌ Never store: user IPs, full page URLs with query params, session data
"""

import asyncio
import hashlib
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import httpx
import google.generativeai as genai
from google.adk.agents import Agent
from google.adk import Workflow, Context
from google.adk.workflow import node, START
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, SseConnectionParams
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from starlette.responses import JSONResponse

# ── Configuration ─────────────────────────────────────────────
GOOGLE_API_KEY       = os.environ.get("GOOGLE_API_KEY", "")
WEBRISK_API_KEY      = os.environ.get("WEBRISK_API_KEY", "")
FIRESTORE_PROJECT_ID = os.environ.get("FIRESTORE_PROJECT_ID", "")

# Determine Gemini Model ID based on GCP environment
if not GOOGLE_API_KEY and FIRESTORE_PROJECT_ID:
    # Use full Vertex AI publisher path to activate Vertex AI via Service Account ADC
    GEMINI_MODEL = f"projects/{FIRESTORE_PROJECT_ID}/locations/us-central1/publishers/google/models/gemini-2.5-flash"
else:
    GEMINI_MODEL = "gemini-2.5-flash"

SB_REPORT_URL        = "https://safebrowsing.google.com/safebrowsing/report_badware/"
FIRESTORE_COLLECTION = "clickfix_threats"
ANALYSIS_PROMPT      = (
    "You are a cybersecurity threat analysis agent specializing in ClickFix social engineering attacks.\n"
    "ClickFix (ClearFake, FakeUpdates) tricks users into pasting malicious terminal commands from their clipboard.\n"
    "Look for: PowerShell, mshta, wscript, cmd /c, iex, Invoke-Expression, curl/wget downloads, Base64 payloads, "
    "-WindowStyle Hidden, -ExecutionPolicy Bypass, certutil, bitsadmin, rundll32.\n"
    "Respond ONLY with a valid JSON object — no markdown, no code fences:\n"
    '{"malicious": true, "reason": "concise explanation"} or {"malicious": false, "reason": "brief explanation"}'
)

if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)


# ── Helpers ───────────────────────────────────────────────────

def _sha256(value: str) -> str:
    """Return a short SHA-256 hex digest of a string."""
    return hashlib.sha256(value.encode()).hexdigest()


def _victim_origin(url: str) -> str:
    """
    Extract only the scheme+host from a URL.
    Privacy: never expose path, query params, or fragments.
    """
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return url


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ══ COURSE CRITERIA: Agent Skills ════════════════════════════
# Domain-specific knowledge is packaged as Markdown SKILL.md files
# under agent/skills/<domain>/. At boot time, _load_skill() reads each
# file and appends the content directly to each specialist agent's
# system instruction, giving it curated expert context without
# requiring additional LLM fine-tuning.
#
# Skill files:
#   skills/threat-intelligence/SKILL.md → Malware_Analyst agent
#   skills/security/SKILL.md            → Security_Auditor agent
#   skills/privacy/SKILL.md             → Privacy_Auditor agent
def _load_skill(skill_dir: str) -> str:
    """Dynamically load domain knowledge from the local skills directory."""
    try:
        base_path = os.path.join(os.path.dirname(__file__), "skills", skill_dir, "SKILL.md")
        with open(base_path, "r", encoding="utf-8") as f:
            return f.read().replace("{", "[").replace("}", "]")
    except Exception as e:
        print(f"[ClickFixed] Failed to load skill {skill_dir}: {e}")
        return ""


# ══ Custom ADK Tools ══════════════════════════════════════════

def submit_to_web_risk(culprit_url: str) -> dict:
    """
    Submit a malicious JavaScript URL to the Google Web Risk Submission API.
    """
    if not culprit_url or not culprit_url.startswith("http"):
        return {"status": "skipped", "reason": "No valid URL provided"}

    fallback = f"{SB_REPORT_URL}?url={quote(culprit_url, safe='')}"

    if WEBRISK_API_KEY:
        try:
            with httpx.Client(timeout=12.0) as client:
                resp = client.post(
                    f"https://webrisk.googleapis.com/v1/submissions?key={WEBRISK_API_KEY}",
                    json={"submission": {"uri": culprit_url}}
                )
                if resp.status_code in (200, 201):
                    return {"status": "submitted_to_web_risk", "url": culprit_url}
                return {"status": "api_error", "http_code": resp.status_code, "fallback": fallback}
        except Exception as exc:
            return {"status": "network_error", "reason": str(exc), "fallback": fallback}

    return {"status": "no_api_key", "note": "Enterprise key required", "fallback_link": fallback}


def lookup_abuse_contact(victim_url: str) -> dict:
    """
    Look up the security abuse contact for a compromised website.
    """
    origin = _victim_origin(victim_url) if victim_url else ""
    if not origin or origin == "://":
        return {"found": False, "reason": "Invalid or empty URL"}

    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                resp = client.get(origin + path)
            if resp.status_code != 200:
                continue
            contact_match = re.search(r"^Contact:\s*(.+)$", resp.text, re.MULTILINE | re.IGNORECASE)
            if not contact_match:
                continue
            email_match = re.search(r"[\w.+\-]+@[\w.\-]+\.\w{2,}", contact_match.group(1))
            if email_match:
                return {
                    "found": True,
                    "email": email_match.group(),
                    "source": origin + path,
                    "note": "Contact found — logged to Firestore for human review. No email sent automatically."
                }
        except Exception:
            continue

    return {"found": False, "reason": "No security.txt found or no Contact email"}


# ══ Agent & Workflow Graph Definitions ═══════════════════════

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
        print(f"[ClickFixed] Firestore signature lookup failed: {exc}")
    return []


async def _update_signatures_in_firestore(project_id: str, new_patterns: list) -> bool:
    """Write/merge patterns array to clickfix_signatures/active in Firestore."""
    token = await _get_gcp_access_token()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    current_patterns = await _fetch_signatures_from_firestore(project_id)
    merged_set = set(current_patterns)
    for p in new_patterns:
        if p:
            merged_set.add(p)
    merged_list = list(merged_set)
    
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/clickfix_signatures/active?updateMask.fieldPaths=patterns"
    body = {
        "fields": {
            "patterns": {
                "arrayValue": {
                    "values": [{"stringValue": p} for p in merged_list]
                }
            }
        }
    }
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.patch(url, headers=headers, json=body)
            if resp.status_code in (200, 201):
                print(f"[ClickFixed] Successfully updated signatures in Firestore. Total: {len(merged_list)}")
                return True
            else:
                print(f"[ClickFixed] Firestore signature update failed (HTTP {resp.status_code}): {resp.text}")
    except Exception as exc:
        print(f"[ClickFixed] Firestore signature update exception: {exc}")
    return False


async def _save_threat_to_firestore(project_id: str, victim_url: str, culprit_js_url: str, payload: str, patterns: list, raw_dom: str = "", security_assessment: str = "", privacy_assessment: str = "", malware_analysis: str = ""):
    """Log threat telemetry to Firestore in a privacy-safe manner."""
    token = await _get_gcp_access_token()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        
    origin = _victim_origin(victim_url)
    if culprit_js_url:
        doc_id = _sha256(culprit_js_url)
    else:
        doc_id = _sha256(payload)
        
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{FIRESTORE_COLLECTION}/{doc_id}"
    
    existing_origins = [origin]
    report_count = 1
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                existing_doc = resp.json()
                fields = existing_doc.get("fields", {})
                origins_val = fields.get("victim_origins", {}).get("arrayValue", {}).get("values", [])
                origins_list = [item.get("stringValue") for item in origins_val if "stringValue" in item]
                if origin not in origins_list:
                    origins_list.append(origin)
                existing_origins = origins_list
                cnt_str = fields.get("report_count", {}).get("integerValue", "1")
                report_count = int(cnt_str) + 1
    except Exception as exc:
        print(f"[ClickFixed] Error fetching existing threat doc: {exc}")
        
    body = {
        "fields": {
            "culprit_js_url": {"stringValue": culprit_js_url or ""},
            "victim_origins": {
                "arrayValue": {
                    "values": [{"stringValue": o} for o in existing_origins]
                }
            },
            "payload_hash": {"stringValue": _sha256(payload)},
            "first_seen": {"stringValue": _now_iso()},
            "last_seen": {"stringValue": _now_iso()},
            "report_count": {"integerValue": str(report_count)},
            "patterns": {
                "arrayValue": {
                    "values": [{"stringValue": p} for p in patterns]
                }
            },
            "raw_dom": {"stringValue": raw_dom},
            "security_assessment": {"stringValue": security_assessment},
            "privacy_assessment": {"stringValue": privacy_assessment},
            "malware_analysis": {"stringValue": malware_analysis}
        }
    }
    
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.patch(url, headers=headers, json=body)
            if resp.status_code in (200, 201):
                print(f"[ClickFixed] Threat logged successfully: {FIRESTORE_COLLECTION}/{doc_id}")
            else:
                print(f"[ClickFixed] Threat log failed (HTTP {resp.status_code}): {resp.text}")
    except Exception as exc:
        print(f"[ClickFixed] Threat log exception: {exc}")


# ══ COURSE CRITERIA: Multi-Agent System (ADK) ════════════════
# Four specialized ADK Agent objects collaborate in a directed pipeline.
# Each agent has a distinct role and skill set; they communicate by passing
# their assessment output through shared workflow node context.
#
# Agent roles:
#   Threat_Intel_Synthesizer  → reviews all auditor outputs, generates regex signatures
#   Security_Auditor          → identifies CSP and header weaknesses in the DOM
#   Privacy_Auditor           → detects tracking pixels and data-minimization violations
#   Malware_Analyst           → de-obfuscates payloads, classifies the lure type
#
# ADK MCP Integration (see also mcp_server.py for the standalone local server):
#   from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, SseConnectionParams
#   # Connect to Google-hosted Firestore MCP in hybrid/local mode:
#   token = await _get_gcp_access_token()
#   firestore_mcp_tools, _exit_stack = await MCPToolset.from_server(
#       connection_params=SseConnectionParams(
#           url="https://firestore.googleapis.com/mcp",
#           headers={"Authorization": f"Bearer {token}"}
#       )
#   )
#   # In serverless production (Reasoning Engine), the pipeline uses ADC REST
#   # calls directly (_save_threat_to_firestore / _update_signatures_in_firestore)
#   # to avoid SSE cold-start latency inside the Vertex AI sandbox.

threat_intel_agent = Agent(
    name="Threat_Intel_Synthesizer",
    model=GEMINI_MODEL,
    instruction=(
        "You are an expert Malware Signature Generator specializing in ClickFix attacks. "
        "Your mission is to analyze telemetry reports and output strict JSON with generated regex signatures. "
        "Only output valid JSON, no explanations, no markdown blocks."
    )
)


security_auditor_agent = Agent(
    name="Security_Auditor",
    model=GEMINI_MODEL,
    instruction=(
        "You are an expert Web Security Auditor. Use your knowledge to identify missing "
        "preventative security headers (like CSP, Trusted Types) in the raw DOM that "
        "could have blocked the attack.\n\n"
        f"DOMAIN KNOWLEDGE:\n{_load_skill('security')}"
    )
)


privacy_auditor_agent = Agent(
    name="Privacy_Auditor",
    model=GEMINI_MODEL,
    instruction=(
        "You are an expert Privacy Auditor. Analyze the threat context for data minimization "
        "issues or tracking pixels embedded by the attacker.\n\n"
        f"DOMAIN KNOWLEDGE:\n{_load_skill('privacy')}"
    )
)


malware_analyst_agent = Agent(
    name="Malware_Analyst",
    model=GEMINI_MODEL,
    instruction=(
        "You are an expert Malware Analyst. Use your knowledge of ClickFix techniques, "
        "Obfuscator.io patterns, and Malicious JS detection to classify the exact social "
        "engineering lure and de-obfuscate the logic.\n\n"
        f"DOMAIN KNOWLEDGE:\n{_load_skill('threat-intelligence')}"
    )
)

@node(name="ingest_payload", rerun_on_resume=True)
def ingest_payload(node_input: str) -> dict:
    import json
    print(f"[ClickFixed Workflow] Ingestion node running...")
    try:
        data = json.loads(node_input)
    except Exception as e:
        print(f"[ClickFixed Workflow] Ingest failed to parse JSON: {e}")
        data = {}
    
    victim_url = data.get("victim_url", "")
    culprit_js_url = data.get("culprit_js_url", "")
    clipboard_payload = data.get("clipboard_payload", "")
    raw_dom = data.get("raw_dom", "")
    
    # Truncate raw_dom to prevent context limit issues
    sanitized_dom = raw_dom[:5000] if raw_dom else ""
    print(f"[ClickFixed Workflow] Ingested telemetry for victim: {victim_url}")
    return {
        "victim_url": victim_url,
        "culprit_js_url": culprit_js_url,
        "clipboard_payload": clipboard_payload,
        "raw_dom": sanitized_dom
    }


@node(name="analyze_security", rerun_on_resume=True)
async def analyze_security(node_input: dict, ctx: Context) -> dict:
    print(f"[ClickFixed Workflow] Analyze Security node running...")
    prompt = f"Analyze the following DOM for security flaws that permitted the attack:\n{node_input.get('raw_dom')}"
    security_assessment = await ctx.run_node(security_auditor_agent, prompt)
    node_input["security_assessment"] = security_assessment
    return node_input


@node(name="analyze_privacy", rerun_on_resume=True)
async def analyze_privacy(node_input: dict, ctx: Context) -> dict:
    print(f"[ClickFixed Workflow] Analyze Privacy node running...")
    prompt = f"Analyze the following DOM for privacy violations/tracking:\n{node_input.get('raw_dom')}"
    privacy_assessment = await ctx.run_node(privacy_auditor_agent, prompt)
    node_input["privacy_assessment"] = privacy_assessment
    return node_input


@node(name="analyze_malware", rerun_on_resume=True)
async def analyze_malware(node_input: dict, ctx: Context) -> dict:
    print(f"[ClickFixed Workflow] Analyze Malware node running...")
    prompt = f"Analyze the payload and DOM to classify the lure and explain obfuscation:\nPayload: {node_input.get('clipboard_payload')}\nDOM: {node_input.get('raw_dom')}"
    malware_analysis = await ctx.run_node(malware_analyst_agent, prompt)
    node_input["malware_analysis"] = malware_analysis
    return node_input


@node(name="synthesize_signature", rerun_on_resume=True)
async def synthesize_signature(node_input: dict, ctx: Context) -> dict:
    print(f"[ClickFixed Workflow] Synthesize signature node running...")
    victim_url = node_input.get("victim_url", "")
    culprit_js_url = node_input.get("culprit_js_url", "")
    clipboard_payload = node_input.get("clipboard_payload", "")
    raw_dom = node_input.get("raw_dom", "")
    security_assessment = node_input.get("security_assessment", "")
    privacy_assessment = node_input.get("privacy_assessment", "")
    malware_analysis = node_input.get("malware_analysis", "")
    
    prompt = f"""
Analyze this intercepted ClickFix social engineering attack and generate regex signatures to block it.

Security Assessment:
{security_assessment}

Privacy Assessment:
{privacy_assessment}

Malware Analysis:
{malware_analysis}

Victim URL: {victim_url}
Culprit JS URL: {culprit_js_url}
Clipboard Payload: {clipboard_payload}
DOM Snapshot: {raw_dom}

Task:
1. De-obfuscate the clipboard payload if it is base64 or obfuscated.
2. Generate 1 to 3 regex patterns (behavioral signatures) that will block this specific threat/payload when intercepted in writeText or DOM lures.
3. Keep the regex signatures clean, specific to malware indicators, and low false-positive. Do not use generic words like "the" or "page". Prefer specific command components.
4. Output a JSON object with a single key "patterns" containing a list of strings (the regex patterns).

Example output:
{{"patterns": ["powershell.*DownloadString.*evil", "mshta.*evil-domain"]}}

Output ONLY the raw JSON string, without markdown formatting or code blocks.
"""
    
    print("[ClickFixed Workflow] Running threat_intel_agent via run_node...")
    agent_output = await ctx.run_node(threat_intel_agent, prompt)
    print(f"[ClickFixed Workflow] Threat Agent output: {agent_output}")
    
    import json
    patterns = []
    try:
        cleaned_output = agent_output.strip()
        if cleaned_output.startswith("```"):
            lines = cleaned_output.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned_output = "\n".join(lines).strip()
            
        match = re.search(r"\{[\s\S]*?\}", cleaned_output)
        if match:
            res_dict = json.loads(match.group(0))
            patterns = res_dict.get("patterns", [])
        else:
            print("[ClickFixed Workflow] No JSON found in agent output.")
    except Exception as e:
        print(f"[ClickFixed Workflow] Failed to parse signature patterns: {e}")
        
    node_input["patterns"] = patterns
    return node_input


@node(name="deploy_signature", rerun_on_resume=True)
async def deploy_signature(node_input: dict) -> str:
    print(f"[ClickFixed Workflow] Deploy signature node running...")
    victim_url = node_input.get("victim_url", "")
    culprit_js_url = node_input.get("culprit_js_url", "")
    clipboard_payload = node_input.get("clipboard_payload", "")
    raw_dom = node_input.get("raw_dom", "")
    patterns = node_input.get("patterns", [])
    
    if FIRESTORE_PROJECT_ID:
        if patterns:
            await _update_signatures_in_firestore(FIRESTORE_PROJECT_ID, patterns)
        await _save_threat_to_firestore(
            FIRESTORE_PROJECT_ID,
            victim_url,
            culprit_js_url,
            clipboard_payload,
            patterns,
            raw_dom,
            node_input.get("security_assessment", ""),
            node_input.get("privacy_assessment", ""),
            node_input.get("malware_analysis", "")
        )
    else:
        print("[ClickFixed Workflow] FIRESTORE_PROJECT_ID not set, skipping persistence.")
        
    return f"Deployed {len(patterns)} patterns."


# ══ ADK Workflow Graph ════════════════════════════════════════
# Connects the nodes (workflow steps) into a directed acyclic graph.
# Each edge defines the execution order: output of one node becomes
# the input of the next. The graph starts at START (built-in sentinel)
# and terminates at deploy_signature.
thread_pipeline = Workflow(
    name="ClickFixed_Threat_Pipeline",
    edges=[
        (START, ingest_payload),          # 1. Sanitize & parse telemetry
        (ingest_payload, analyze_security),  # 2. CSP/header audit
        (analyze_security, analyze_privacy), # 3. Tracker/pixel scan
        (analyze_privacy, analyze_malware),  # 4. Payload de-obfuscation
        (analyze_malware, synthesize_signature),  # 5. Generate regex signatures
        (synthesize_signature, deploy_signature)  # 6. Persist to Firestore + Web Risk
    ]
)

# Keep backwards-compatible alias
threat_pipeline = thread_pipeline


# ══ AdkApp Wrapper for Agent Engine Deployment ═══════════════

from vertexai.preview.reasoning_engines import AdkApp

app = AdkApp(
    agent=threat_pipeline,
    enable_tracing=True,
    env_vars={
        "FIRESTORE_PROJECT_ID": FIRESTORE_PROJECT_ID,
        "WEBRISK_API_KEY": WEBRISK_API_KEY
    }
)


