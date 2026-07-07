# ClickFixed: Proactive AI-Powered Edge-to-Cloud Multi-Agent Clipboard Shield

On-device DOM clipboard protection powered by Gemini Nano, a Google ADK multi-agent threat intelligence pipeline on Vertex AI Agent Engine, and a Cloud Run gateway proxy.

---

## ⏱️ A Note on Timing

ClickFixed's first commit landed on **June 21, 2026**.

On **July 2, 2026** — roughly eleven days later — Opera announced **[Paste Protect](https://blogs.opera.com/news/2026/07/opera-launches-paste-protect/)**, a native browser feature designed specifically to defend against ClickFix-style clipboard hijacking. Paste Protect monitors clipboard writes, blocks suspicious commands before they reach the user, and surfaces a red security indicator in the address bar — a remarkably similar philosophy to what we had already shipped.

It was covered by *BleepingComputer*, *Engadget*, *Lifehacker*, and *gHacks*, among others.

We want to be very clear: we have absolutely no way of knowing whether ClickFixed had anything to do with Opera's roadmap. Major browser features take months to design and ship, and the ClickFix threat has been growing for well over a year. The timing is almost certainly a coincidence.

*Almost certainly.*

Either way, we think it's a meaningful signal: the security community is converging on the same conclusion we reached — that clipboard interception at the browser layer is the right place to stop these attacks. We just happen to have shipped an AI-native, agent-powered take on it first. 🙂

---

## Project Description

### 1. Problem Statement: The Deception of ClickFix

Social engineering campaigns like ClickFix (also known as ClearFake or FakeUpdates) have emerged as highly successful infection vectors. Attackers compromise legitimate websites to inject script overlays displaying deceptive browser alerts or Captcha human-verification modals. Users are instructed to press keyboard shortcuts (Win + R), copy an automated system repair script, paste it into their system console, and execute it. 

Traditional heuristic-based web shields fail to stop this threat because:

1. **Interception Evasion**: Malicious scripts write to the clipboard using modern APIs (like Blob writes in ClipboardItem) that bypass standard text hooks.
2. **Payload Obfuscation**: Attackers use caret-inserts (c^m^d) and backticks (p`o`w`e`r`s`h`e`l`l) to evade regular signature scanners.
3. **Local Context Ignorance**: The browser doesn't check if the data being written contains shell commands before execution.

---

### 2. The Solution: ClickFixed Protection

ClickFixed is an edge-to-cloud security framework that stops clipboard hijacking at point-zero. It operates in two tiers:

**Tier 1: On-Device Sensor Agent (Chrome Extension)**

* **Main World Interception**: Hooks into `navigator.clipboard.writeText` and the newer `ClipboardItem` API at browser startup before page scripts load.
* **Proactive Lure Deletion**: A MutationObserver actively scans the page DOM. When a modal captcha lure is injected, it is immediately deleted from the page to prevent user interaction.
* **Edge AI Verdicts**: If a clipboard write is caught, the extension prompts Chrome's built-in Gemini Nano model for a zero-latency, privacy-safe classification. If malicious, the write is blocked.
* **Tamper-Proof Alert Warning**: Alerts are injected via a closed-mode Shadow DOM, ensuring the malicious site cannot suppress or manipulate the security warning.

**Tier 2: Google ADK Multi-Agent Threat Intel (Agent Engine & Gateway)**

* If Gemini Nano is unavailable or flags a payload requiring deeper verification, the extension hands over sanitized DOM context and payloads to a secure Cloud Run Gateway proxy, which routes the request to the deployed Google ADK reasoning pipeline on Vertex AI Agent Engine using the standard Agent-to-Agent (A2A) protocol.

---

### 3. Architecture: The Google ADK Graph Pipeline

The threat backend is powered by a graph-based multi-agent architecture built with the Google ADK framework. The data flow follows this pipeline:

```text
[Chrome Browser Sandbox]
  Clipboard Hook / DOM Interceptor ──► local Gemini Nano Edge AI
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
             [Malicious: Block write]                [Requires Deep Scan]
                        │                                     │
             [Shadow DOM warning alert]               [A2A Telemetry Handoff]
                                                               │
                                                               ▼
                                                     [Cloud Run API Gateway]
                                                               │
                                                               ▼
                                                    [Vertex AI Agent Engine]
                                                               │
                                                     [Ingestion Layer]
                                                               │
                                                     [Security Auditor Agent]
                                                               │
                                                     [Privacy Auditor Agent]
                                                               │
                                                     [Malware Analyst Agent]
                                                               │
                                                     [Threat Intel Synthesizer]
                                                               │
                                           ┌───────────────────┼───────────────────┐
                                           ▼                   ▼                   ▼
                                  [Firestore via MCP]  [Web Risk Submission]  [Abuse Contact Lookup]
```

* **Ingestion Node**: Sanitizes full URLs to protect victim privacy, removing paths, fragments, and queries.
* **Security Auditor Agent** (Skills: security/SKILL.md): Audits the DOM context to see why the injection was possible (CSP weaknesses).
* **Privacy Auditor Agent** (Skills: privacy/SKILL.md): Scans the page to see if attacker code is leaking browser cookies or tracking visitor IPs.
* **Malware Analyst Agent** (Skills: threat-intelligence/SKILL.md): De-obfuscates caret symbols, backticks, base64 strings, and de-cloaks malicious payloads.
* **Threat Intel Synthesizer**: Reviews all auditor assessments, compiles active signatures (regex patterns), and writes them to the signature feed.

---

### 4. Demonstrating Key Course Concepts

#### Concept 1: Multi-Agent System (ADK)

The Cloud Threat Agent backend instantiates specialized ADK agents connected in a pipeline:

```python
security_auditor_agent = Agent(name="Security_Auditor", model=GEMINI_MODEL, instruction=SEC_INSTRUCTION)
privacy_auditor_agent = Agent(name="Privacy_Auditor", model=GEMINI_MODEL, instruction=PRIV_INSTRUCTION)
malware_analyst_agent = Agent(name="Malware_Analyst", model=GEMINI_MODEL, instruction=MAL_INSTRUCTION)
threat_intel_agent = Agent(name="Threat_Intel_Synthesizer", model=GEMINI_MODEL, instruction=SYNTH_INSTRUCTION)
```

These agents process the threat in sequence, communicating assessments via a shared Context.

#### Concept 2: MCP Server

Our ADK pipeline is designed with native support for the Model Context Protocol (MCP) toolset to dynamically connect to GCP services (like Firestore) or custom threat intelligence sources:

```python
token = await _get_gcp_access_token()
headers = {"Authorization": f"Bearer {token}"} if token else {}

firestore_mcp_tools, _exit_stack = await MCPToolset.from_server(
    connection_params=SseConnectionParams(
        url="https://firestore.googleapis.com/mcp",
        headers=headers
    )
)
```

To optimize serverless execution inside the **Vertex AI Agent Platform (Reasoning Engine)** (where establishing persistent SSE connections to external MCP servers can introduce cold-start latency), the pipeline implements a robust dual-mode design:
1. **Local/Hybrid Mode (MCP)**: The LLM dynamically invokes MCP tools to run threat deduplication queries and inspect collections.
2. **Serverless Production Mode (ADC REST)**: The pipeline interacts with GCP Firestore securely via the direct Firestore REST API using Google Application Default Credentials (ADC) token generation. The agent fetches credentials dynamically from `metadata.google.internal` at runtime, ensuring zero-config secure database access without exposing credentials.

#### Concept 3: Agent Skills (CLI and Core Files)

Domain-specific intelligence is injected dynamically via file-based skills:

* `threat-intelligence/SKILL.md` teaches the Malware Analyst agent how base64 obfuscation and Captcha CAPTURE overlays operate.
* `security/SKILL.md` guides the Security Auditor on Content-Security-Policy (CSP) and Trusted Types restrictions.
* `privacy/SKILL.md` specifies tracking parameters and data minimization standards.

At boot, the ADK agent calls `_load_skill()` to read these markdown definitions and append them directly to the LLM system instructions.

#### Concept 4: Security & Privacy Features

* **ClipboardItem API Interception**: Monkey-patches lower-level APIs to block advanced payload vectors.
* **Tamper-Proof Closed Shadow DOM**: Displays security blocks through closed Shadow roots that target pages cannot access or modify via scripting.
* **URL Sanitization**: Telemetry automatically strips URL queries/fragments off-device, sharing only target domain origins (victim_url) to ensure data privacy.

#### Concept 5: Deployability & Infrastructure-as-Code (IaC)

* **Terraform Infrastructure Automation**: We automated the provisioning and teardown of the entire GCP threat intelligence pipeline using Terraform ([infra/](infra/)).
  - **Spin Up**: Automatically enables required APIs (Cloud Run, Firestore, Vertex AI, Web Risk, Artifact Registry, Cloud Storage), provisions a Firestore database in Native mode, creates a GCS staging bucket, creates an Artifact Registry repository, creates a dedicated service account with minimum-privilege IAM permissions, and deploys the Cloud Run Gateway proxy service.
  - **Take Down**: Running `terraform destroy` instantly tears down all provisioned services, preventing running costs.
* **Lightweight Containerization**: The API gateway proxy is fully containerized using a lightweight Dockerfile and hosted on Cloud Run with restricted resource limits (1 CPU, 512MB RAM) for high efficiency.
* **Connectivity Diagnostics**: The Chrome Extension options page (`options.html`) includes live connectivity status monitors and health-check ping tests for both local Gemini Nano edge and remote Cloud Run nodes.

#### Concept 6: Antigravity IDE Agent Collaboration

Antigravity served as the central coder during development, accomplishing the following tasks:

* *Reconstruction*: Rebuilt corrupt extension JS files from chronological execution logs.
* *Optimization*: Replaced verbose warning logs with structured info streams to bypass developer warning badges in Chrome.
* *Verification*: Set up the browser subagent to record E2E interactive walkthrough validations of the simulator dashboard, compiling screenshot evidence of our proactive clipboard protection blocks.
* *Presentation*: Authored presentation.html as a single-page animated presentation tool demonstrating local blocks, fallbacks, and ADK cascade sequences.

---

## Attachments & Links

* **Chrome Web Store Listing**: [ClickFixed on Chrome Web Store](https://chromewebstore.google.com/detail/click-fixed/eolbjikeobaakljmancpfgommfpmhgfp)
* **Source Repository**: https://github.com/Marontis/clickfixed
* **Interactive Architecture Demo**: https://marontis.github.io/clickfixed/
* **Local Test Simulator Page**: https://marontis.github.io/clickfixed/test_clickfix.html
* **GCP Deployable Endpoint**: `https://your-cloud-run-url.run.app`
* **ADK Schema Definition**: [firestore_schema.py](agent/firestore_schema.py)


