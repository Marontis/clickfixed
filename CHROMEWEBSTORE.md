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
| `storage` | permissions | Saves user preferences and local block counts on the device. |
| `alarms` | permissions | Runs a background alarm every hour to sync threat signature regexes from the server. |
| `host_permissions: <all_urls>` | host_permissions | Clipboard hijacking scripts are dynamically loaded on compromised pages across any domain. Universal access is required for real-time interception and content script injection. |

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
https://marontis.github.io/clickfixed/PRIVACY.md

## Distribution

**Visibility**: Public
**Regions**: All regions

## Developer Info

**Publisher Name**
Click Fixed Security Project

**Contact Email**
https://github.com/Marontis/clickfixed/issues

## Version History

| Version | Date | Changes | Status |
|---------|------|---------|--------|
| 1.0.0 | 2026-06-19 | Initial Release (Gemini Nano Edge AI + Cloud Fallback + A2A Sync) | Released |
| 1.1.0 | 2026-06-21 | Added Proactive Lure Detection and physical DOM removal for fake verification modals | Draft |

## Developer Console Copy-Paste Guide

This section contains the exact text fields to copy-paste into the **Chrome Web Store Developer Console** under the **Store Listing** and **Privacy Practices** tabs to resolve validation errors.

### 1. Privacy Practices Tab -> Single Purpose
**Field:** *Single purpose description*
```text
Click Fixed intercepts and blocks malicious clipboard-hijacking command injection attacks on websites using on-device and cloud-fallback AI analysis.
```

### 2. Privacy Practices Tab -> Permissions Justifications
**Field:** *Justification for storage*
```text
The 'storage' permission is required to save and retrieve the user's configuration settings (such as toggle states for Cloud Fallback, telemetry reporting, and aggressive signature checks) and to keep track of the local count of blocked clipboard-hijacking attacks on the device. All configuration and statistics are stored locally on the user's device.
```

**Field:** *Justification for alarms*
```text
The 'alarms' permission is used to schedule periodic background check-ins (once every hour) to fetch the latest threat signature updates (regex patterns matching known ClickFix / ClearFake scripts) from the secure backend database. This keeps the extension's local shield updated without requiring a manual update of the entire extension.
```

### 3. Privacy Practices Tab -> Host Permissions Justifications
**Field:** *Justification for <all_urls>*
```text
The '<all_urls>' host permission is required because clipboard-hijacking scripts (such as ClickFix, ClearFake, and FakeUpdates) are loaded dynamically on arbitrary, compromised legitimate websites across any top-level domain. To proactively block malicious clipboard writes and remove fake CAPTCHA or update dialogs at point zero, the content scripts must run and intercept clipboard events at document startup on all webpages.
```

### 4. Privacy Practices Tab -> Remote Code Use
**Question:** *Does your extension use remote code?*
- Select **No, my extension does not use remote code** (or equivalent **No** option).
- **Justification / Explanation (if requested):**
```text
Click Fixed does not execute or load any external JavaScript, scripts, or remote executable code. All content scripts, options pages, and warning dialogs are bundled locally inside the extension. Threat signatures are loaded as raw JSON/regex matching patterns, not executable code.
```

### 5. Privacy Practices Tab -> Data Usage Compliance
Scroll to the bottom of the Privacy practices tab and check/certify the following:
- [x] **I certify that my data usage complies with the developer program policies.**
- [x] **Data is not sold to third parties.**
- [x] **Data is not used for purposes unrelated to the extension's core functionality.**
- [x] **Data is not used for creditworthiness or lending purposes.**

### 6. Settings Page -> Publisher Contact Email
- Go to the **Settings** page (in the left-hand navigation menu of the Developer Dashboard).
- Locate the **Publisher contact email** field.
- **Enter a valid, monitored email address** (e.g., your personal or project email). *Note: Google Web Store listing requires an actual email address here, whereas the support URL can point to a GitHub issues page.*
- Click **Save**.
- Google will automatically send a verification link to that email. You **must** open your inbox, find the verification email from Chrome Web Store Developer Support, and click the link to verify it.

