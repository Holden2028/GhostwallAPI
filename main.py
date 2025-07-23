from fastapi import FastAPI, Request
from pydantic import BaseModel
from detection import detect_bot
import datetime
from fastapi.middleware.cors import CORSMiddleware
import os

def log_request(ip, user_agent, api_key, visitor_type, details):
    with open("log.txt", "a") as f:
        f.write(
            f"{datetime.datetime.utcnow().isoformat()} "
            f"IP:{ip} "
            f"KEY:{api_key} "
            f"UA:'{user_agent}' "
            f"TYPE:{visitor_type} "
            f"DETAILS:{details}\n"
        )

# List or set of valid API keys (replace with your real keys!)
VALID_API_KEYS = {"test123", "ghostwall2024", "anotherkey"}

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or specify ["http://127.0.0.1:5050"]
    allow_methods=["*"],
    allow_headers=["*"],
)

class CheckRequest(BaseModel):
    api_key: str
    user_agent: str

@app.post("/check")
async def check(req: CheckRequest, request: Request):
    if req.api_key not in VALID_API_KEYS:
        log_request(request.client.host, req.user_agent, req.api_key, "error", "Invalid API key.")
        return {"result": "error", "details": "Invalid API key."}
    ip = request.client.host
    headers = dict(request.headers)
    visitor_type, details = detect_bot(req.user_agent, headers, ip)
    log_request(ip, req.user_agent, req.api_key, visitor_type, details)
    return {"result": visitor_type, "details": details}

@app.get("/logs")
def get_logs():
    logs = []
    try:
        with open("log.txt") as f:
            logs = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        logs = ["No logs found."]
    return {"logs": logs}

@app.get("/")
def root():
    return {"status": "ok"}

@app.delete("/logs")
def clear_logs():
    try:
        open("log.txt", "w").close()
        return {"status": "ok", "message": "Logs cleared."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
