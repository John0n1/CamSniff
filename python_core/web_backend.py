import asyncio
import json
from pathlib import Path
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="CamSniff Backend")
LOG_FILE = Path("output/logs/scan.jsonl")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

@app.get("/")
def index():
    return HTMLResponse(
        """
        <html>
        <body>
          <h3>CamSniff Live Events</h3>
          <pre id="out"></pre>
          <script>
            const out = document.getElementById('out');
            const ws = new WebSocket(`ws://${location.host}/ws`);
            ws.onmessage = (e) => { out.textContent += e.data + "\n"; };
          </script>
        </body>
        </html>
        """
    )

@app.websocket("/ws")
async def ws_stream(ws: WebSocket):
    await ws.accept()
    # Tail the log file and stream lines
    try:
        last_size = 0
        while True:
            await asyncio.sleep(0.5)
            if not LOG_FILE.exists():
                continue
            data = LOG_FILE.read_text(encoding="utf-8")
            chunk = data[last_size:]
            last_size = len(data)
            for line in chunk.splitlines():
                try:
                    json.loads(line)  # basic sanity
                    await ws.send_text(line)
                except Exception:
                    continue
    except Exception:
        await ws.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8089)

def main():
    uvicorn.run(app, host="0.0.0.0", port=8089)
