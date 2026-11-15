"""ThreatLens'i başlatır:  python run.py   ->  http://127.0.0.1:8000
Geliştirme için otomatik yeniden yükleme:  python run.py --reload"""
import sys

import uvicorn

if __name__ == "__main__":
    port = int(next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--port=")), 8000))
    uvicorn.run("app.main:app", host="127.0.0.1", port=port, reload="--reload" in sys.argv)
