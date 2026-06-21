# Chrome Web Store Listing — Click Fixed

> Last Updated: 2026-06-19

## Store Listing

**Extension Name**
Click Fixed

**Short Description**
Proactive AI-powered defense against ClickFix / ClearFake / FakeUpdates social engineering attacks. Powered by Gemini.

**Detailed Description**
Click Fixed is an on-device cybersecurity shield that stops clipboard-hijacking attacks at point zero.

Clipboard-hijack attacks (often called ClickFix, ClearFake, or FakeUpdates) compromise legitimate websites and display deceptive errors (like fake CAPTCHAs or browser updates), tricking you into running code by copying a malicious command to your clipboard and instructing you to paste it into your command line. Click Fixed prevents this completely by monkey-patching DOM clipboard events at browser startup. 

It intercepts clipboard writes and uses Chrome's built-in AI (Gemini Nano) or a secure cloud fallback to analyze payloads for malicious shell commands, blocking the write if flagged. When an attack is blocked, a secure, tamper-proof warning panel appears immediately to display the AI's reasoning and prevent accidental execution.

For privacy, Click Fixed sanitizes all tab URLs before sending telemetry to Google Web Risk or your security database, stripping query parameters and fragments so your personal browsing activity is never exposed.

For support, feedback, or custom deployment guides, visit the official project repository.

**Category**
Developer Tools

**Single Purpose**
Intercepts and blocks malicious clipboard-hijacking command injection attacks using AI analysis.

**Primary Language**
English

## Graphics & Assets

| Asset | Dimensions | Status | Filename |
|-------|-----------|--------|----------|
| Store Icon | 128×128 PNG | ✅ Ready | `extension/icons/icon128.png` |
| Screenshot 1 | 1280×800 PNG | ✅ Ready | `store_assets/screenshot1.png` |
| Screenshot 2 | 1280×800 PNG | ✅ Ready | `store_assets/screenshot2.png` |

### Screenshot Notes
*   **Screenshot 1**: Demonstrates the warning panel sliding in on a test page (e.g. `test_clickfix.html`) to showcase the user-facing alert UI.
*   **Screenshot 2**: Shows the Options page dashboard indicating active status for Gemini Nano (Edge AI) and backend agent URL connection checks.

## Permissions Justification

| Permission | Type | Justification |
|------------|------|---------------|
| `clipboardRead` | permissions | Required to inspect intercepted clipboard text for potential threat indicators before allowing writes. |
| `storage` | permissions | Saves user preferences (A2A threat agent URL) and local block counts on the device. |
| `tabs` | permissions | Allows the background worker to update the badge count and alert status on the extension icon per-tab. |
| `scripting` | permissions | Injects the clipboard monkey-patch interceptor (`injected.js`) into pages at the earliest possible stage. |
| `activeTab` | permissions | Grants the extension permissions to access tab contexts when showing the status popup. |
| `alarms` | permissions | Runs a background alarm every hour to sync threat signature regexes from the server. |
| `host_permissions: <all_urls>` | host_permissions | Clipboard hijacking scripts are dynamically loaded on compromised pages across any domain. Universal access is required for real-time interception. |

## Privacy & Data Use

### Data Collection

**Does the extension collect user data?** Yes

| Data Type | Collected? | Transmitted Off-Device? | Purpose | Shared with Third Parties? |
|-----------|-----------|------------------------|---------|---------------------------|
| Personally identifiable info | No | No | N/A | No |
| Web history | No | No | N/A | No |
| Website content | Yes | Yes | Compromised page origin and malicious script URL are sent to your database and Google Web Risk to burn threat infrastructure. | No |

### Data Use Certification
- [x] Data is NOT sold to third parties
- [x] Data is NOT used for purposes unrelated to the extension's core functionality
- [x] Data is NOT used for creditworthiness or lending purposes

## Privacy Policy

**Privacy Policy URL**
`https://github.com/yourusername/clickfixed/blob/main/PRIVACY.md`

## Distribution

**Visibility**: Public
**Regions**: All regions

## Developer Info

**Publisher Name**
Click Fixed Security Project

**Contact Email**
security-alerts@clickfixed.example.com

## Version History

| Version | Date | Changes | Status |
|---------|------|---------|--------|
| 1.0.0 | 2026-06-19 | Initial Release (Gemini Nano Edge AI + Cloud Fallback + A2A Sync) | Released |
| 1.1.0 | 2026-06-21 | Added Proactive Lure Detection and physical DOM removal for fake verification modals | Draft |
