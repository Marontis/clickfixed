// ============================================================
// Click Fixed — Content Script (Isolated World)
//
// Responsibilities:
//   1. Inject injected.js into the page's main world
//   2. Bridge postMessage events from injected.js to the AI pipeline
//   3. Run the hybrid AI evaluation (Gemini Nano → Cloud fallback)
//   4. Send the verdict back to injected.js to allow/block the write
//   5. Trigger the Shadow DOM warning UI on malicious verdict
//   6. Report threat to the background service worker
// ============================================================

(function () {
  'use strict';

  const commToken = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);

  // ── 1. Inject Config and Main World Script ───────────────────
  async function setupAndInject() {
    try {
      const data = await chrome.storage.local.get('signatures');
      const sigs = data.signatures || [];
      
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('injected.js');
      document.documentElement.prepend(script);
      
      script.addEventListener('load', () => {
        script.remove();
        // Send the token and signatures to injected.js
        const initPayload = JSON.stringify({
          __source: 'clickfix_content_init',
          token: commToken,
          signatures: sigs
        });
        window.postMessage(initPayload, '*');
      }, { once: true });
    } catch (err) {
      console.info('[ClickFixed] Failed to load stored signatures:', err.message);
    }
  }

  setupAndInject();

  // ── Warm Gemini Nano Session (cached, created once) ───────────
  // Creating a LanguageModel session takes ~2-3s. We create it eagerly
  // on page load so it is ready by the time a threat arrives.
  let _warmNanoSession = null;
  let _nanoSessionPromise = null;

  async function getOrCreateNanoSession() {
    if (_warmNanoSession) return _warmNanoSession;
    if (_nanoSessionPromise) return _nanoSessionPromise;

    _nanoSessionPromise = (async () => {
      try {
        if (!('LanguageModel' in window)) return null;
        const availability = await LanguageModel.availability({
          expectedInputs:  [{ type: 'text', languages: ['en'] }],
          expectedOutputs: [{ type: 'text', languages: ['en'] }]
        });
        if (availability === 'unavailable') return null;

        const session = await LanguageModel.create({
          expectedInputs:  [{ type: 'text', languages: ['en'] }],
          expectedOutputs: [{ type: 'text', languages: ['en'] }],
          initialPrompts: [{
            role: 'system',
            content: `You are a security analysis AI. Analyze this clipboard text. If it is a malicious PowerShell, cmd, or shell payload from a ClickFix social engineering attack, reply with malicious: true.
Respond ONLY with valid JSON:
{"malicious": true, "reason": "explanation"} or {"malicious": false, "reason": "explanation"}`
          }]
        });
        _warmNanoSession = session;
        console.debug('[ClickFixed] Gemini Nano session warmed and cached.');
        return session;
      } catch (err) {
        console.info('[ClickFixed] Nano session warm-up failed:', err.message);
        return null;
      }
    })();

    return _nanoSessionPromise;
  }

  // Begin warming session immediately in background (don't await).
  getOrCreateNanoSession();

  // ── 2. Detect & Report AI Mode ────────────────────────────────
  (async function detectAIMode() {
    try {
      if ('LanguageModel' in window) {
        const availability = await LanguageModel.availability({
          expectedInputs:  [{ type: 'text', languages: ['en'] }],
          expectedOutputs: [{ type: 'text', languages: ['en'] }]
        });
        const mode = availability === 'available'
          ? 'Gemini Nano (Edge)'
          : availability === 'downloadable'
          ? 'Gemini Nano (Downloading...)'
          : 'Gemini Cloud (Fallback)';
        chrome.runtime.sendMessage({ type: 'UPDATE_AI_MODE', mode });
      } else {
        chrome.runtime.sendMessage({ type: 'UPDATE_AI_MODE', mode: 'Gemini Cloud (Fallback)' });
      }
    } catch {
      chrome.runtime.sendMessage({ type: 'UPDATE_AI_MODE', mode: 'Gemini Cloud (Fallback)' });
    }
  })();

  // ── 3. Message Bridge — injected.js ⇄ AI pipeline ────────────
  window.addEventListener('message', async (event) => {
    if (event.source !== window) return;
    
    let data = event.data;
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data);
      } catch (e) {
        return; // Ignore non-JSON strings
      }
    }

    if (data?.__source !== 'clickfix_injected') return;
    if (data?.type !== `CLICKFIX_SUSPECT_${commToken}`) return;

    const { payload, culpritUrl, victimUrl, timestamp, via, highConfidence } = data;
    console.debug(`[ClickFixed] Suspect payload intercepted via ${via}. highConfidence=${highConfidence}`);

    // Normalize payload to strip caret/backtick obfuscation
    const normalizedPayload = normalizePayload(payload);

    // ── HIGH-CONFIDENCE FAST PATH ─────────────────────────────────
    // For Base64/multi-pattern payloads, block immediately (injected.js
    // already threw; this path handles the warning UI + telemetry).
    // AI still runs in background for forensics — we just don't wait for it.
    if (highConfidence) {
      const immediateVerdict = JSON.stringify({
        __source: 'clickfix_content',
        type: `CLICKFIX_VERDICT_${commToken}`,
        verdict: 'malicious'
      });
      window.postMessage(immediateVerdict, '*');

      if (typeof window.__clickfixShowWarning === 'function') {
        window.__clickfixShowWarning({
          reason: 'High-confidence heuristic match (Base64 payload or multiple execution patterns)',
          culpritUrl: culpritUrl || null,
          victimUrl: victimUrl || sanitizeCurrentUrl()
        });
      }

      // Run AI asynchronously for telemetry — don't block on it.
      (async () => {
        let verdict = { malicious: true, reason: 'High-confidence heuristic block' };
        let aiMode = 'heuristic';
        try {
          const result = await evaluatePayload(normalizedPayload);
          verdict = result.verdict;
          aiMode  = result.aiMode;
        } catch (_) {}

        const payloadHash = await hashText(payload);
        const detection = {
          id:              Date.now(),
          timestamp:       timestamp || new Date().toISOString(),
          victim_url:      victimUrl,
          culprit_js_url:  culpritUrl,
          payload_hash:    payloadHash,
          ai_confidence:   verdict.reason,
          ai_mode:         aiMode
        };
        chrome.runtime.sendMessage({ type: 'REPORT_THREAT', payload: {
          timestamp:          detection.timestamp,
          victim_url:         detection.victim_url,
          culprit_js_url:     detection.culprit_js_url,
          payload_hash:       payloadHash,
          ai_confidence:      verdict.reason,
          raw_payload:        payload,
          normalized_payload: normalizedPayload
        }});
      })();

      return; // Done — clipboard already blocked, warning shown.
    }

    // ── STANDARD AI PATH (low-confidence heuristic match) ────────
    // Evaluate with the hybrid AI pipeline
    let verdict = { malicious: false, reason: '' };
    let aiMode = 'unknown';

    try {
      ({ verdict, aiMode } = await evaluatePayload(normalizedPayload));
    } catch (err) {
      console.info('[ClickFixed] Evaluation pipeline error:', err);
    }

    // ── 4. Return verdict to injected.js ─────────────────────────
    const verdictPayload = JSON.stringify({
      __source: 'clickfix_content',
      type: `CLICKFIX_VERDICT_${commToken}`,
      verdict: verdict.malicious ? 'malicious' : 'safe'
    });
    window.postMessage(verdictPayload, '*');

    // ── 5. If malicious → show warning UI ───────────────────────
    if (verdict.malicious) {
      if (typeof window.__clickfixShowWarning === 'function') {
        window.__clickfixShowWarning({
          reason: verdict.reason,
          culpritUrl: culpritUrl || null,
          victimUrl: victimUrl || sanitizeCurrentUrl()
        });
      }

      // Build forensic detection record
      const payloadHash = await hashText(payload);
      const detection = {
        id: Date.now(),
        timestamp: timestamp || new Date().toISOString(),
        victim_url: victimUrl,
        culprit_js_url: culpritUrl,
        payload_hash: payloadHash,
        ai_confidence: verdict.reason,
        ai_mode: aiMode
      };

      // ── 6. Report to background ────────────────────────────────
      chrome.runtime.sendMessage({
        type: 'THREAT_DETECTED',
        detection
      });

      chrome.runtime.sendMessage({
        type: 'REPORT_THREAT',
        payload: {
          timestamp: detection.timestamp,
          victim_url: detection.victim_url,
          culprit_js_url: detection.culprit_js_url,
          payload_hash: payloadHash,
          ai_confidence: verdict.reason,
          raw_payload: payload,
          normalized_payload: normalizedPayload
        }
      });
    }
  });

  // Defeats caret/backtick obfuscation by cleaning command string first
  function normalizePayload(text) {
    if (!text || typeof text !== 'string') return '';
    let normalized = text.replace(/`/g, ''); // Remove PowerShell backticks
    normalized = normalized.replace(/\^/g, ''); // Remove CMD carets
    return normalized.replace(/\s+/g, ' '); // Normalize spaces
  }

  // ── Hybrid AI Pipeline ────────────────────────────────────────
  async function evaluatePayload(payload) {
    // Plan A: Gemini Nano (on-device, zero latency)
    const edgeResult = await tryEdgeAI(payload);
    if (edgeResult !== null) {
      chrome.runtime.sendMessage({ type: 'UPDATE_AI_MODE', mode: 'Gemini Nano (Edge)' });
      return { verdict: edgeResult, aiMode: 'Gemini Nano' };
    }

    // Plan B: Gemini 2.0 Flash via Python backend
    chrome.runtime.sendMessage({ type: 'UPDATE_AI_MODE', mode: 'Gemini Cloud (Fallback)' });
    const cloudResult = await tryCloudAI(payload);
    return { verdict: cloudResult, aiMode: 'Gemini Cloud' };
  }

  async function tryEdgeAI(payload) {
    try {
      // Reuse the cached warm session — avoids ~2-3s LanguageModel.create() per call.
      const session = await getOrCreateNanoSession();
      if (!session) return null;

      const raw = await session.prompt(payload);
      // Note: don't destroy() — we're keeping the session warm for reuse.
      // If the session errors on a future prompt, getOrCreateNanoSession will
      // detect the stale reference via try/catch and recreate it.

      const jsonMatch = raw.match(/\{[\s\S]*?\}/);
      if (!jsonMatch) return null;
      const parsed = JSON.parse(jsonMatch[0]);
      return { malicious: Boolean(parsed.malicious), reason: String(parsed.reason || '') };
    } catch (err) {
      console.info('[ClickFixed] Edge AI (Gemini Nano) error:', err.message);
      // Session may be stale — clear cache so it's recreated next time.
      _warmNanoSession = null;
      _nanoSessionPromise = null;
      return null;
    }
  }

  async function tryCloudAI(payload) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: 'ANALYZE_PAYLOAD', payload },
        (response) => {
          if (chrome.runtime.lastError || !response) {
            console.info('[ClickFixed] Cloud AI failed. Defaulting to safe.');
            resolve({ malicious: false, reason: 'AI evaluation unavailable.' });
          } else {
            resolve({
              malicious: Boolean(response.malicious),
              reason: String(response.reason || '')
            });
          }
        }
      );
    });
  }

  // ── Utilities ─────────────────────────────────────────────────
  async function hashText(text) {
    const data = new TextEncoder().encode(text);
    const buffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function sanitizeCurrentUrl() {
    try {
      const u = new URL(window.location.href);
      return u.origin + u.pathname;
    } catch {
      return null;
    }
  }

  // ── Proactive DOM Scan (Phase 6) ───────────────────────────
  let proactiveEvaluating = false;
  const evaluatedHashes = new Set();

  function getSimpleHash(str) {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
      hash = (hash * 33) ^ str.charCodeAt(i);
    }
    return hash >>> 0;
  }

  function hasBeenEvaluated(html) {
    const hash = getSimpleHash(html.slice(0, 1000));
    return evaluatedHashes.has(hash);
  }

  function markEvaluated(html) {
    const hash = getSimpleHash(html.slice(0, 1000));
    evaluatedHashes.add(hash);
    if (evaluatedHashes.size > 50) {
      const first = evaluatedHashes.values().next().value;
      evaluatedHashes.delete(first);
    }
  }

  function isSuspiciousLureText(text) {
    if (!text || text.length > 10000) return false;
    const lower = text.toLowerCase();
    
    const hasWinR = lower.includes("win+r") || lower.includes("windows+r") || lower.includes("windows key + r") || (lower.includes("press") && lower.includes(" r ") && (lower.includes("windows") || lower.includes("win")));
    const hasPowerShell = lower.includes("powershell") || lower.includes("cmd.exe") || lower.includes("cmd /c") || lower.includes("mshta") || lower.includes("command prompt") || lower.includes(" terminal ");
    const hasPaste = lower.includes("paste") || lower.includes("ctrl+v") || lower.includes("ctrl + v") || lower.includes("copy the");
    const hasVerify = lower.includes("verify") || lower.includes("captcha") || lower.includes("robot") || lower.includes("human") || lower.includes("fix") || lower.includes("update") || lower.includes("install");
    
    if (hasWinR && (hasPaste || hasVerify)) return true;
    if (hasPowerShell && hasPaste && hasVerify) return true;
    
    return false;
  }

  async function tryEdgeAIProactive(promptText) {
    try {
      if (!('LanguageModel' in window)) return null;

      const availability = await LanguageModel.availability({
        expectedInputs:  [{ type: 'text', languages: ['en'] }],
        expectedOutputs: [{ type: 'text', languages: ['en'] }]
      });
      if (availability === 'unavailable') return null;

      const session = await LanguageModel.create({
        expectedInputs:  [{ type: 'text', languages: ['en'] }],
        expectedOutputs: [{ type: 'text', languages: ['en'] }],
        initialPrompts: [{
          role: 'system',
          content: `You are a security analysis AI. Analyze this UI text. If it is instructing a user to press Windows+R, copy command, or run PowerShell to verify/fix an issue, reply with malicious: true.
Respond ONLY with valid JSON:
{"malicious": true, "reason": "explanation"} or {"malicious": false, "reason": "explanation"}`
        }]
      });

      const raw = await session.prompt(promptText);
      session.destroy();

      const jsonMatch = raw.match(/\{[\s\S]*?\}/);
      if (!jsonMatch) return null;
      const parsed = JSON.parse(jsonMatch[0]);
      return { malicious: Boolean(parsed.malicious), reason: String(parsed.reason || '') };
    } catch (err) {
      console.info('[ClickFixed] Edge AI Proactive unavailable:', err.message);
      return null;
    }
  }

  async function tryCloudAIProactive(promptText) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: 'ANALYZE_PAYLOAD', payload: promptText },
        (response) => {
          if (chrome.runtime.lastError || !response) {
            console.info('[ClickFixed] Proactive Cloud AI failed. Defaulting to safe.');
            resolve({ malicious: false, reason: 'AI evaluation unavailable.' });
          } else {
            resolve({
              malicious: Boolean(response.malicious),
              reason: String(response.reason || '')
            });
          }
        }
      );
    });
  }

  async function runProactiveEval(text, outerHTML, node) {
    let verdict = { malicious: false, reason: '' };
    let aiMode = 'unknown';

    // Hide node during AI check
    const originalDisplay = node.style.display;
    node.style.display = 'none';

    try {
      const edgePrompt = `Analyze this UI text. Is it instructing a user to press Windows+R, open a terminal, or copy a script to fix an error?\n\nText:\n${text.slice(0, 1500)}`;
      
      const edgeResult = await tryEdgeAIProactive(edgePrompt);
      if (edgeResult !== null) {
        verdict = edgeResult;
        aiMode = 'Gemini Nano (Proactive)';
      } else {
        const cloudResult = await tryCloudAIProactive(edgePrompt);
        verdict = cloudResult;
        aiMode = 'Gemini Cloud (Proactive)';
      }
    } catch (err) {
      console.info('[ClickFixed] Proactive AI eval failed:', err);
    }

    if (verdict.malicious) {
      console.info('[ClickFixed] Proactive Block triggered!');
      node.remove(); // Remove the malicious DOM node
      
      if (typeof window.__clickfixShowWarning === 'function') {
        window.__clickfixShowWarning({
          reason: verdict.reason,
          culpritUrl: 'Proactive DOM Scan',
          victimUrl: sanitizeCurrentUrl()
        });
      }

      const commandMatch = outerHTML.match(/(?:powershell|cmd|iex|mshta|certutil|bitsadmin)[^<>]*/i) ||
                           outerHTML.match(/[A-Za-z0-9+/=]{40,}/);
      const clipboardPayload = commandMatch ? commandMatch[0].trim() : "Proactive DOM warning triggered - payload embedded in DOM.";

      const payloadHash = await hashText(clipboardPayload);
      const detection = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        victim_url: window.location.href,
        culprit_js_url: 'Proactive DOM Scan',
        payload_hash: payloadHash,
        ai_confidence: verdict.reason,
        ai_mode: aiMode
      };
      
      chrome.runtime.sendMessage({
        type: 'THREAT_DETECTED',
        detection
      });

      chrome.runtime.sendMessage({
        type: 'REPORT_THREAT',
        payload: {
          timestamp: detection.timestamp,
          victim_url: detection.victim_url,
          culprit_js_url: detection.culprit_js_url,
          payload_hash: payloadHash,
          ai_confidence: verdict.reason,
          raw_payload: clipboardPayload,
          normalized_payload: clipboardPayload
        }
      });
    } else {
      // Restore node display style if safe
      node.style.display = originalDisplay;
    }
  }

  function initProactiveObserver() {
    const observer = new MutationObserver((mutations) => {
      if (proactiveEvaluating) return;
      
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const text = node.textContent || "";
            if (isSuspiciousLureText(text)) {
              const outerHTML = node.outerHTML || "";
              
              if (hasBeenEvaluated(outerHTML)) continue;
              markEvaluated(outerHTML);
              
              proactiveEvaluating = true;
              console.debug("[ClickFixed] Heuristic match! Triggering proactive AI scan...");
              
              runProactiveEval(text, outerHTML, node).finally(() => {
                proactiveEvaluating = false;
              });
              return;
            }
          }
        }
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initProactiveObserver);
  } else {
    initProactiveObserver();
  }
})();
