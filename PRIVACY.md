# Privacy Policy for Click Fixed

**Last Updated:** June 21, 2026

Click Fixed ("we," "us," or "our") is committed to protecting your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use the **Click Fixed** browser extension (the "Extension").

---

## 1. Single Purpose and Core Functionality
The Extension's single purpose is to intercept and block malicious clipboard-hijacking command injection attacks (often referred to as "ClickFix," "ClearFake," or "FakeUpdates" campaigns) using a combination of on-device local AI (Gemini Nano) and a secure cloud fallback.

To achieve this, the Extension monitors clipboard API writes and analyzes DOM mutations for captchas and software-update lures.

---

## 2. Data We Do NOT Collect
We design our tools around the principle of **data minimization**.
- **No Personally Identifiable Information (PII):** We do not collect names, email addresses, usernames, passwords, IP addresses, physical locations, or device identifiers.
- **No Browsing History:** We do not track, log, or store your browsing history or list of visited pages.

---

## 3. Data We Collect and Transmit
When a malicious clipboard write or a fake modal captcha lure is detected and blocked, the Extension transmits a secure threat telemetry record to the user's configured backend database (Google Cloud Firestore) and the Google Web Risk Submission API. 

The transmitted record contains only:
1. **Sanitized Victim Origin:** The scheme and host of the compromised webpage (e.g. `https://example.com`), completely stripping paths, search query parameters, and URL fragments to protect your privacy.
2. **Culprit Script URL:** The URL of the malicious JavaScript file attempting the hijack.
3. **Payload Signature:** The command payload (e.g., PowerShell or terminal snippet) that was blocked.
4. **Timestamp:** The date and time of the event.
5. **AI Detection Metadata:** The type of engine that identified the threat (e.g., Gemini Nano Edge AI or Cloud Fallback).

---

## 4. Third-Party Sharing and Data Use
We certify that:
- **No Sale of Data:** We never sell, lease, rent, or trade your collected telemetry data to third parties.
- **No Advertising/Targeting:** Your data is never used for advertising, marketing, analytics, profiling, or creditworthiness evaluation.
- **Strictly Security Operations:** Data is collected solely to report compromised websites, identify emerging attacker infrastructure, and alert site administrators or submit threat indicators to Google Web Risk to burn malicious URLs.

---

## 5. Security of Your Data
All communications between the Extension and the cloud backend are encrypted in transit via standard HTTPS (TLS 1.2+). Access to the threat database is strictly authenticated and restricted.

---

## 6. Your Choices and Controls
You can configure the Extension settings via the Options page dashboard. Detections and total block counts are saved locally on your device via Chrome's storage API and can be cleared at any time by clearing the extension storage.

---

## 7. Contact & Support
For support, feedback, bug reports, or security disclosures, please open an issue in the official project repository:
[Click Fixed GitHub Issues](https://github.com/Marontis/clickfixed/issues)
