# Firestore Data Model — Click Fixed Threat Intelligence
# =========================================================
# 
# Privacy Principle:
#   We store the MINIMUM data needed to act on threats.
#   • Culprit JS URL → the attack asset (NOT user data — store in full)
#   • Victim site   → origin only (scheme + host), NEVER path/query/fragment
#   • No user IPs, no user agents, no session data, no browsing history
#
# Collections
# -----------
#
# clickfix_threats/{culprit_url_hash}
#   Primary record keyed by SHA-256 of the culprit JS URL.
#   Enables deduplication: same script = same document.
#
#   Fields:
#     culprit_js_url     : string   — The malicious script URL (attack asset)
#     culprit_url_hash   : string   — SHA-256 of culprit_js_url (= document ID)
#     victim_origins     : array    — Origins of victim sites (no paths/queries)
#     first_seen         : timestamp
#     last_seen          : timestamp
#     report_count       : number   — How many times this script was detected
#     ai_analysis        : string   — Latest Gemini analysis of the payload
#     payload_hashes     : array    — Unique SHA-256 hashes of payloads seen
#     web_risk_submitted : boolean  — Was this URL sent to Web Risk API?
#     abuse_contact      : string   — Abuse email if found via security.txt
#
# Example document:
# {
#   "culprit_js_url":     "https://evil-cdn.example.com/update.min.js",
#   "culprit_url_hash":   "a3f8b2c1...",
#   "victim_origins":     ["https://news-site.example.com"],
#   "first_seen":         "2026-06-19T01:23:45Z",
#   "last_seen":          "2026-06-19T02:10:00Z",
#   "report_count":       3,
#   "ai_analysis":        "PowerShell payload downloads and executes remote script",
#   "payload_hashes":     ["sha256:deadbeef..."],
#   "web_risk_submitted": true,
#   "abuse_contact":      "security@news-site.example.com"
# }
#
# Firestore Security Rules (deploy via Firebase Console or CLI):
#
# rules_version = '2';
# service cloud.firestore {
#   match /databases/{database}/documents {
#     // Only Cloud Run service account can read/write
#     match /clickfix_threats/{docId} {
#       allow read, write: if false;  // All access via backend only (Admin SDK / MCP)
#     }
#   }
# }
