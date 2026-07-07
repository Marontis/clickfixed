// ============================================================
// Click Fixed — Background Service Worker (MV3)
//
// Two-agent architecture:
//   SENSOR AGENT  (this file) — Gemini Nano edge AI + ADK Agent Cloud Fallback
//   THREAT AGENT  (ADK)       — Web Risk + security.txt + A2A workflow
//
// API keys are completely removed from the extension.
// All heavy lifting and API key requirements are delegated to the Cloud Agent.
// ============================================================

const DEFAULT_AGENT_URL = 'https://your-cloud-run-url.run.app';

// ── Init ─────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    // Fresh install only — don't wipe existing counters on update.
    chrome.storage.local.set({
      detections:   [],
      totalBlocked: 0,
      aiMode:       'Detecting...',
      signatures:   []
    });
    console.log('[ClickFixed] 🛡️ Extension installed.');
  } else if (details.reason === 'update') {
    // On update: preserve counters, just ensure new keys exist.
    const existing = await chrome.storage.local.get(['detections', 'totalBlocked', 'aiMode', 'signatures']);
    const patch = {};
    if (!Array.isArray(existing.detections))  patch.detections   = [];
    if (existing.totalBlocked == null)         patch.totalBlocked = 0;
    if (!existing.aiMode)                      patch.aiMode       = 'Detecting...';
    if (!Array.isArray(existing.signatures))   patch.signatures   = [];
    if (Object.keys(patch).length > 0) chrome.storage.local.set(patch);
    console.log(`[ClickFixed] 🔄 Extension updated to v${chrome.runtime.getManifest().version}.`);
  }

  // Setup alarms for periodic threat signature synchronization (every 60 mins)
  // and a keep-warm ping every 10 mins to prevent Cloud Run cold starts.
  chrome.alarms.create('signature_sync', { periodInMinutes: 60 });
  chrome.alarms.create('keep_warm',      { periodInMinutes: 10 });
  await syncSignatures();
});

chrome.runtime.onStartup.addListener(async () => {
  await syncSignatures();
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'signature_sync') {
    await syncSignatures();
  } else if (alarm.name === 'keep_warm') {
    // Lightweight ping to keep the Cloud Run instance warm.
    // Reuses /signatures — no AI inference cost, just a GET.
    await syncSignatures();
  }
});

// ── Message Passing ──────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'REPORT_THREAT') {
    handleThreatDetected(sender.tab, request.payload);
    handleA2AHandoff(request.payload);
    sendResponse({ received: true });
  } else if (request.type === 'THREAT_DETECTED') {
    // Alias kept for backward compatibility with content_script.js dual-send.
    // Counter increment is already handled by REPORT_THREAT; this just
    // updates the badge if somehow only this message arrives.
    if (sender.tab?.id) {
      chrome.action.setBadgeText({ text: '!', tabId: sender.tab.id });
      chrome.action.setBadgeBackgroundColor({ color: '#dc2626', tabId: sender.tab.id });
      chrome.action.setBadgeTextColor({ color: '#ffffff', tabId: sender.tab.id });
    }
    sendResponse({ received: true });
  } else if (request.type === 'UPDATE_AI_MODE') {
    chrome.storage.local.set({ aiMode: request.mode });
    sendResponse({ success: true });
  } else if (request.type === 'ANALYZE_PAYLOAD') {
    handleAnalyzePayload(request.payload, sendResponse);
    return true; // Keep channel open for async response
  }
  return true;
});

// ── Badge & Storage Update ────────────────────────────────────
async function handleThreatDetected(tab, detection) {
  if (tab?.id) {
    chrome.action.setBadgeText({ text: '!', tabId: tab.id });
    chrome.action.setBadgeBackgroundColor({ color: '#dc2626', tabId: tab.id });
    chrome.action.setBadgeTextColor({ color: '#ffffff', tabId: tab.id });
  }

  const { totalBlocked = 0, detections = [] } = await chrome.storage.local.get(['totalBlocked', 'detections']);
  const updated = detection ? [detection, ...detections].slice(0, 50) : detections;
  await chrome.storage.local.set({
    totalBlocked: totalBlocked + 1,
    detections:   updated
  });
}

// ── Cloud AI Fallback ─────────────────────────────────────────
async function handleAnalyzePayload(payload, sendResponse) {
  const baseUrl = DEFAULT_AGENT_URL.replace(/\/$/, '');
  try {
    const response = await fetch(`${baseUrl}/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ payload }),
      signal:  AbortSignal.timeout(10_000)
    });

    if (response.ok) {
      const result = await response.json();
      sendResponse({
        malicious: Boolean(result.malicious),
        reason:    String(result.reason || 'Analyzed by Cloud Agent')
      });
    } else {
      console.info(`[ClickFixed] Cloud Threat Agent returned HTTP ${response.status}`);
      sendResponse({ malicious: false, reason: 'Cloud Agent returned error status.' });
    }
  } catch (err) {
    console.info('[ClickFixed] Cloud Threat Agent analyze failed:', err.message);
    sendResponse({ malicious: false, reason: 'Could not contact Cloud Agent.' });
  }
}

// ── Signature Syncing ─────────────────────────────────────────
async function syncSignatures() {
  const baseUrl = DEFAULT_AGENT_URL.replace(/\/$/, '');
  try {
    const response = await fetch(`${baseUrl}/signatures`, {
      signal: AbortSignal.timeout(5_000)
    });
    if (response.ok) {
      const data = await response.json();
      if (data && Array.isArray(data.signatures)) {
        await chrome.storage.local.set({ signatures: data.signatures });
        console.log(`[ClickFixed] ✅ Synced ${data.signatures.length} threat signature patterns from agent.`);
      }
    } else {
      console.info(`[ClickFixed] Agent signatures returned HTTP ${response.status}`);
    }
  } catch (err) {
    console.info('[ClickFixed] Signature sync failed:', err.message);
  }
}

/** Forward proactive threat detections to the ADK A2A workflow backend. */
async function handleA2AHandoff(data) {
  const baseUrl = DEFAULT_AGENT_URL.replace(/\/$/, '');
  try {
    console.log(`[ClickFixed] Handoff telemetry to ADK Workflow backend: ${baseUrl}/a2a/handoff`);
    const response = await fetch(`${baseUrl}/a2a/handoff`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(data),
      signal:  AbortSignal.timeout(10_000)
    });
    if (response.ok) {
      console.log('[ClickFixed] ✅ Telemetry handoff succeeded.');
    } else {
      console.info(`[ClickFixed] ADK Workflow handoff HTTP error: ${response.status}`);
    }
  } catch (err) {
    console.info('[ClickFixed] ADK Workflow handoff network error:', err.message);
  }
}
