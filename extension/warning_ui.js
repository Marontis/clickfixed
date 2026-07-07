// ============================================================
// Click Fixed — Shadow DOM Warning UI (Floating Panel)
//
// Loaded as a content script (isolated world). Has full DOM
// access to inject the Shadow DOM panel without being affected
// by the malicious site's CSS or JavaScript.
//
// Uses mode:'closed' Shadow DOM — the page's JS cannot reference
// or remove the shadow root, making it tamper-proof.
// ============================================================

(function () {
  'use strict';

  // Exposed to content_script.js (shared isolated world)
  window.__clickfixShowWarning = function showWarning({ reason, culpritUrl, victimUrl }) {
    // Remove any existing panel first
    const existing = document.getElementById('__clickfix_root__');
    if (existing) existing.remove();

    // Host element — fixed positioning via inline style (outside shadow)
    const host = document.createElement('div');
    host.id = '__clickfix_root__';
    host.style.cssText = [
      'position:fixed',
      'bottom:24px',
      'right:24px',
      'z-index:2147483647',
      'pointer-events:none' // Allow interaction only through shadow root
    ].join(';');

    // Closed Shadow DOM — page JS cannot call host.shadowRoot
    const shadow = host.attachShadow({ mode: 'closed' });

    // Static panel structure (dynamic content set via textContent below)
    shadow.innerHTML = `
<style>
  *, *::before, *::after { box-sizing: border-box; }
  .clickfixed-panel {
    background: #1e1e2e;
    color: #cdd6f4;
    font-family: system-ui, -apple-system, sans-serif;
    padding: 20px;
    border-radius: 8px;
    border: 2px solid #dc2626;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    pointer-events: auto; /* Enable interaction inside panel */
  }
  .cf-header { display: flex; align-items: center; gap: 10px; font-weight: bold; color: #f38ba8; margin-bottom: 15px; }
  .cf-desc { font-size: 14px; margin-bottom: 15px; line-height: 1.5; }
  .cf-meta { background: #11111b; padding: 10px; border-radius: 6px; font-size: 12px; margin-bottom: 15px; font-family: monospace; word-break: break-all; }
  .cf-btn-row { display: flex; gap: 10px; }
  .cf-close { background: #313244; border: none; color: #cdd6f4; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: 500; }
  .cf-close:hover { background: #45475a; }
  .cf-report { background: #dc2626; border: none; color: #ffffff; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: 500; }
  .cf-report:hover { background: #b91c1c; }
  .meta-row { display: flex; margin-bottom: 4px; }
  .meta-row:last-child { margin-bottom: 0; }
  .meta-label { color: #f38ba8; font-weight: 600; width: 80px; flex-shrink: 0; }
  .meta-val { color: #a6adc8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
<div class="clickfixed-panel">
  <div class="cf-header">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
    Click Fixed: Threat Blocked
  </div>
  <div class="cf-desc" id="descEl"></div>
  <div class="cf-meta" id="metaSection"></div>
  <div class="cf-btn-row">
    <button class="cf-close" id="closeBtn">Dismiss Warning</button>
    <button class="cf-report" id="reportBtn">Report Site</button>
  </div>
</div>
`;

    const descEl = shadow.getElementById('descEl');
    descEl.textContent = reason || 'A malicious clipboard payload detected and blocked.';

    // Build meta rows for culprit and victim URLs
    const metaSection = shadow.getElementById('metaSection');
    function addMeta(label, value) {
      if (!value) return;
      const row = document.createElement('div');
      row.className = 'meta-row';
      const lbl = document.createElement('span');
      lbl.className = 'meta-label';
      lbl.textContent = label;
      const val = document.createElement('span');
      val.className = 'meta-val';
      val.textContent = value.length > 55 ? value.slice(0, 52) + '…' : value;
      val.title = value;
      row.appendChild(lbl);
      row.appendChild(val);
      metaSection.appendChild(row);
    }

    if (culpritUrl) addMeta('Culprit JS', culpritUrl);
    if (victimUrl)  addMeta('Page', victimUrl);

    // ── Wire up buttons ───────────────────────────────────────────
    shadow.getElementById('closeBtn').addEventListener('click', () => host.remove());

    shadow.getElementById('reportBtn').addEventListener('click', () => {
      const target = culpritUrl || victimUrl || '';
      const reportUrl = target
        ? `https://safebrowsing.google.com/safebrowsing/report_badware/?url=${encodeURIComponent(target)}`
        : 'https://safebrowsing.google.com/safebrowsing/report_badware/';
      window.open(reportUrl, '_blank', 'noopener,noreferrer');
      host.remove();
    });

    // Append to DOM
    document.documentElement.appendChild(host);

    // Auto-dismiss after 45 seconds
    setTimeout(() => host.isConnected && host.remove(), 45_000);
  };
})();
