// ============================================================
// Click Fixed — Injected Script (Main World)
// Runs in the PAGE's JavaScript context (not isolated world).
// This is required to monkey-patch navigator.clipboard.writeText.
//
// Communication: postMessage ⇄ content_script.js (isolated world)
// ============================================================

(function () {
  'use strict';

  const SOURCE_TAG = 'clickfix_injected';
  let commToken = '';
  let activePatterns = [];
  let initialized = false;
  let callTimestamps = [];
  const RATE_LIMIT_WINDOW_MS = 3000;
  const RATE_LIMIT_MAX = 5;

  const EXECUTION_PATTERNS = [
    /powershell/i,
    /cmd\.exe/i,
    /mshta/i,
    /certutil/i,
    /bitsadmin/i,
    /wscript/i,
    /cscript/i,
    /cmd\s*\/[cCkK]/,
    /scrobj\.dll/i,
    /\\\\[a-z0-9\-]+\\/i  // UNC path pattern
  ];

  // Large Base64 blocks (>80 chars) are a strong ClickFix indicator
  const BASE64_PATTERN = /[A-Za-z0-9+/]{80,}={0,2}/;

  // ── 1. Listen for config initialization from isolated content script ──
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    let data = event.data;
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data);
      } catch (e) {
        return; // Ignore non-JSON strings
      }
    }

    if (data?.__source !== 'clickfix_content_init') return;
    if (initialized) return; // Initialize once

    initialized = true;
    commToken = data.token || '';
    
    const dynamicSigs = data.signatures || [];
    if (dynamicSigs.length > 0) {
      try {
        activePatterns = dynamicSigs.map((pat) => new RegExp(pat, 'i'));
        console.debug(`[ClickFixed] Loaded ${activePatterns.length} threat signatures from extension.`);
      } catch (e) {
        console.info('[ClickFixed] Error compiling dynamic signatures, using default fallbacks.');
      }
    }
  });

  // Defeats caret/backtick obfuscation by cleaning command string first
  function normalizePayload(text) {
    if (!text || typeof text !== 'string') return '';
    let normalized = text.replace(/`/g, ''); // Remove PowerShell backticks
    normalized = normalized.replace(/\^/g, ''); // Remove CMD carets
    return normalized.replace(/\s+/g, ' '); // Normalize spaces
  }

  function heuristicFilter(text) {
    if (!text || typeof text !== 'string') return false;
    if (text.trim().length < 10) return false;
    if (BASE64_PATTERN.test(text)) return true;
    
    const normalized = normalizePayload(text);
    const matchedDefault = EXECUTION_PATTERNS.some((re) => re.test(normalized));
    if (matchedDefault) return true;

    // Check dynamic signature cache
    return activePatterns.some((re) => re.test(normalized));
  }

  // High-confidence: Base64 blob present OR 2+ execution patterns match.
  // Safe to block immediately without waiting for AI verdict.
  function isHighConfidence(text) {
    if (!text || typeof text !== 'string') return false;
    if (BASE64_PATTERN.test(text)) return true;
    const normalized = normalizePayload(text);
    const matchCount = EXECUTION_PATTERNS.filter((re) => re.test(normalized)).length;
    return matchCount >= 2;
  }

  // ── Stack Trace Attribution ───────────────────────────────────
  function parseCulpritUrl(stack) {
    if (!stack) return 'Unknown';
    const matches = stack.match(/https?:\/\/[^\s\)]+/g);
    if (matches) {
      return matches[0];
    }
    return 'Inline Script';
  }

  // ── URL Sanitizer (STRIDE — no PII in telemetry) ─────────────
  function sanitizeUrl(href) {
    try {
      const u = new URL(href);
      return u.origin + u.pathname;
    } catch {
      return href || '';
    }
  }

  function isRateLimited() {
    const now = Date.now();
    callTimestamps = callTimestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (callTimestamps.length >= RATE_LIMIT_MAX) return true;
    callTimestamps.push(now);
    return false;
  }

  // ── Verdict Listener ─────────────────────────────────────────
  function waitForVerdict(timeoutMs = 10_000) {
    return new Promise((resolve) => {
      const handler = (event) => {
        if (event.source !== window) return;
        
        let data = event.data;
        if (typeof data === 'string') {
          try {
            data = JSON.parse(data);
          } catch (e) {
            return;
          }
        }

        if (data?.__source !== 'clickfix_content') return;
        if (data?.type !== `CLICKFIX_VERDICT_${commToken}`) return;

        window.removeEventListener('message', handler);
        resolve(data.verdict); // 'malicious' | 'safe'
      };

      window.addEventListener('message', handler);

      // Default to BLOCKED on timeout (fail-safe / secure default)
      setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve('malicious');
      }, timeoutMs);
    });
  }

  // ── Monkey-Patch navigator.clipboard APIs ──────────────────────
  const _originalWrite = navigator.clipboard.write.bind(navigator.clipboard);
  const _originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);

  // Patch writeText
  navigator.clipboard.writeText = async function interceptedWriteText(text) {
    if (heuristicFilter(text) && !isRateLimited()) {
      const stack = new Error().stack;
      const culpritUrl = parseCulpritUrl(stack);
      const victimUrl = sanitizeUrl(window.location.href);
      const highConfidence = isHighConfidence(text);

      const suspectPayload = JSON.stringify({
        __source: SOURCE_TAG,
        type: `CLICKFIX_SUSPECT_${commToken}`,
        payload: text,
        culpritUrl,
        victimUrl,
        timestamp: new Date().toISOString(),
        via: 'writeText',
        highConfidence
      });

      window.postMessage(suspectPayload, '*');

      // High-confidence: block immediately; AI confirms in background.
      // Low-confidence: wait for full AI verdict (up to 10s).
      if (highConfidence) {
        throw new DOMException(
          'Clipboard write blocked by Click Fixed security policy.',
          'NotAllowedError'
        );
      }

      const verdict = await waitForVerdict();
      if (verdict === 'malicious') {
        throw new DOMException(
          'Clipboard write blocked by Click Fixed security policy.',
          'NotAllowedError'
        );
      }
    }
    return _originalWriteText(text);
  };

  // Patch write
  navigator.clipboard.write = async function interceptedWrite(data) {
    try {
      for (const item of data) {
        if (item.types.includes('text/plain')) {
          const blob = await item.getType('text/plain');
          const text = await blob.text();
          if (heuristicFilter(text) && !isRateLimited()) {
            const stack = new Error().stack;
            const culpritUrl = parseCulpritUrl(stack);
            const victimUrl = sanitizeUrl(window.location.href);
            const highConfidence = isHighConfidence(text);

            const suspectPayload = JSON.stringify({
              __source: SOURCE_TAG,
              type: `CLICKFIX_SUSPECT_${commToken}`,
              payload: text,
              culpritUrl,
              victimUrl,
              timestamp: new Date().toISOString(),
              via: 'write',
              highConfidence
            });

            window.postMessage(suspectPayload, '*');

            if (highConfidence) {
              throw new DOMException(
                'Clipboard write blocked by Click Fixed security policy.',
                'NotAllowedError'
              );
            }

            const verdict = await waitForVerdict();
            if (verdict === 'malicious') {
              throw new DOMException(
                'Clipboard write blocked by Click Fixed security policy.',
                'NotAllowedError'
              );
            }
          }
        }
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === 'NotAllowedError') {
        throw err;
      }
      console.info('[ClickFixed] Clipboard write check error:', err.message);
    }
    return _originalWrite(data);
  };

  // Hook: document 'copy' event
  document.addEventListener('copy', function onCopyIntercept(e) {
    const text = e.clipboardData?.getData('text/plain') || '';
    if (!heuristicFilter(text) || isRateLimited()) return;

    e.preventDefault(); // Block copy immediately for synchronous path

    const stack = new Error().stack;
    const culpritUrl = parseCulpritUrl(stack);
    const victimUrl = sanitizeUrl(window.location.href);
    const highConfidence = isHighConfidence(text);

    const suspectPayload = JSON.stringify({
      __source: SOURCE_TAG,
      type: `CLICKFIX_SUSPECT_${commToken}`,
      payload: text,
      culpritUrl,
      victimUrl,
      timestamp: new Date().toISOString(),
      via: 'copyEvent',
      highConfidence
    });

    window.postMessage(suspectPayload, '*');
  }, true); // Capture phase

  console.debug('[ClickFixed] 🛡️ Clipboard interceptor active.');
})();
