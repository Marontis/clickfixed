// ============================================================
// Click Fixed — Popup Script
// Reads detection history and AI mode from chrome.storage.local
// and renders the live threat dashboard.
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  // Set version dynamically from manifest
  const versionText = document.getElementById('versionText');
  if (versionText) {
    versionText.textContent = `Click Fixed v${chrome.runtime.getManifest().version}`;
  }

  loadDashboard();

  // Live updates when storage changes (e.g. new detection on another tab)
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.detections || changes.totalBlocked || changes.aiMode) {
      loadDashboard();
    }
  });
});

async function loadDashboard() {
  try {
    const data = await chrome.storage.local.get(['detections', 'totalBlocked', 'aiMode']);
    const detections = data.detections || [];
    const totalBlocked = data.totalBlocked || 0;
    const aiMode = data.aiMode || 'Detecting...';

    renderStats(totalBlocked, detections);
    renderAIMode(aiMode);
    renderDetections(detections);
  } catch (err) {
    console.info('[ClickFixed] Error loading dashboard:', err.message);
  }
}

// ── Stats ─────────────────────────────────────────────────────
function renderStats(totalBlocked, detections) {
  const totalEl = document.getElementById('totalBlocked');
  const sessionEl = document.getElementById('sessionCount');

  totalEl.textContent = totalBlocked;
  if (totalBlocked === 0) {
    totalEl.classList.add('safe');
  } else {
    totalEl.classList.remove('safe');
  }

  // Count detections in the last 24 hours
  const oneDayAgo = Date.now() - 86_400_000;
  const sessionCount = detections.filter(d => d.timestamp && new Date(d.timestamp).getTime() > oneDayAgo).length;
  sessionEl.textContent = sessionCount;
  if (sessionCount === 0) {
    sessionEl.classList.add('safe');
  } else {
    sessionEl.classList.remove('safe');
  }
}

// ── AI Mode ───────────────────────────────────────────────────
function renderAIMode(aiMode) {
  const chipLabel = document.getElementById('aiChipLabel');
  const chipIcon = document.getElementById('aiChipIcon');
  const cardName = document.getElementById('aiCardName');
  const cardDesc = document.getElementById('aiCardDesc');
  const cardDot = document.getElementById('aiCardDot');

  if (!chipLabel || !cardName) return;

  if (aiMode.includes('Nano') || aiMode.includes('Edge')) {
    chipLabel.textContent = 'Edge AI';
    chipIcon.textContent = '⚡';
    cardName.textContent = 'Gemini Nano';
    cardDesc.textContent = 'Proactive edge-AI classification active';
    cardDot.style.background = 'var(--accent-green)';
    cardDot.style.boxShadow = '0 0 6px var(--accent-green)';
  } else if (aiMode.includes('Downloading')) {
    chipLabel.textContent = 'Downloading';
    chipIcon.textContent = '⏳';
    cardName.textContent = 'Gemini Nano (Downloading...)';
    cardDesc.textContent = 'Downloading model updates on device';
    cardDot.style.background = 'var(--accent-purple)';
    cardDot.style.boxShadow = '0 0 6px var(--accent-purple)';
  } else if (aiMode.includes('Cloud') || aiMode.includes('Fallback')) {
    chipLabel.textContent = 'Cloud AI';
    chipIcon.textContent = '☁️';
    cardName.textContent = 'Gemini Flash';
    cardDesc.textContent = 'Using Cloud fallback for detection';
    cardDot.style.background = 'var(--accent-blue)';
    cardDot.style.boxShadow = '0 0 6px var(--accent-blue)';
  } else {
    chipLabel.textContent = 'Checking';
    chipIcon.textContent = '🔍';
    cardName.textContent = 'Detecting...';
    cardDesc.textContent = 'Checking available AI engine capability';
    cardDot.style.background = 'var(--accent-purple)';
    cardDot.style.boxShadow = '0 0 6px var(--accent-purple)';
  }
}

// ── Detections Feed ──────────────────────────────────────────
function renderDetections(detections) {
  const listEl = document.getElementById('detectionsList');
  const emptyState = document.getElementById('emptyState');

  if (!listEl) return;

  // Clear existing items but preserve emptyState
  const items = listEl.querySelectorAll('.detection-item');
  items.forEach(item => item.remove());

  if (!detections || detections.length === 0) {
    if (emptyState) emptyState.style.display = 'flex';
    return;
  }

  if (emptyState) emptyState.style.display = 'none';

  // Render top 5 recent detections
  detections.slice(0, 5).forEach(d => {
    const item = document.createElement('div');
    item.className = 'detection-item';

    let domain = 'Unknown site';
    try {
      if (d.victim_url) {
        domain = new URL(d.victim_url).hostname;
      }
    } catch (e) {
      domain = d.victim_url || 'Unknown site';
    }

    const dateStr = d.timestamp ? relativeTime(new Date(d.timestamp)) : 'just now';
    const reason = d.ai_confidence || 'Malicious command execution blocked';

    item.innerHTML = `
      <div class="d-header">
        <span class="d-icon">🚨</span>
        <span class="d-url" title="${escapeHtml(d.victim_url || '')}">${escapeHtml(domain)}</span>
        <span class="d-time">${escapeHtml(dateStr)}</span>
      </div>
      <div class="d-reason">${escapeHtml(reason)}</div>
    `;
    listEl.appendChild(item);
  });
}

// ── Helpers ───────────────────────────────────────────────────
function relativeTime(date) {
  const diff = Date.now() - date.getTime();
  if (diff < 60_000)          return 'just now';
  if (diff < 3_600_000)       return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000)      return `${Math.floor(diff / 3_600_000)}h ago`;
  return date.toLocaleDateString();
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
