from fastapi import FastAPI, Request
from pydantic import BaseModel
from detection import detect_bot
import datetime
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

LOG_FILE = "/opt/render/project/src/log.txt"

def log_request(ip, user_agent, api_key, visitor_type, details):
    print(f"LOGGING: ip={ip}, api_key={api_key}, visitor_type={visitor_type}, details={details}")
    with open(LOG_FILE, "a") as f:
        f.write(
            f"{datetime.datetime.utcnow().isoformat()}\t"
            f"{ip}\t"
            f"{api_key}\t"
            f"{user_agent}\t"
            f"{visitor_type}\t"
            f"{details}\n"
        )

VALID_API_KEYS = {"test123", "ghostwall2024", "anotherkey"}

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class CheckRequest(BaseModel):
    api_key: str
    user_agent: str
    ip: str = None
    accept: str = None
    accept_encoding: str = None
    accept_language: str = None
    connection: str = None
    referer: str = None
    cookies: dict = {}
    headers: dict = {}

@app.get("/logfile")
def read_log_file():
    try:
        with open(LOG_FILE, "r") as f:
            content = f.read()
        return PlainTextResponse(content)
    except FileNotFoundError:
        return PlainTextResponse("Log file not found.", status_code=404)
    except Exception as e:
        return PlainTextResponse(f"Error reading log file: {e}", status_code=500)

@app.post("/check")
async def check(req: CheckRequest, request: Request):
    if req.api_key not in VALID_API_KEYS:
        log_request(request.client.host, req.user_agent, req.api_key, "error", "Invalid API key.")
        return {"result": "error", "details": "Invalid API key."}

    ip = req.ip or request.client.host
    headers = req.headers or dict(request.headers)

    fingerprint = {
        "user_agent": req.user_agent,
        "accept": req.accept,
        "accept_encoding": req.accept_encoding,
        "accept_language": req.accept_language,
        "connection": req.connection,
        "referer": req.referer,
        "cookies": req.cookies,
        "headers": headers,
    }

    visitor_type, details = detect_bot(req.user_agent, fingerprint, ip)
    log_request(ip, req.user_agent, req.api_key, visitor_type, details)
    return {"result": visitor_type, "details": details}

@app.get("/logs")
def get_logs():
    logs = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 5:
                    logs.append({
                        "timestamp": parts[0],
                        "ip": parts[1],
                        "api_key": parts[2],
                        "user_agent": parts[3],
                        "visitor_type": parts[4],
                        "details": parts[5] if len(parts) > 5 else ""
                    })
    except FileNotFoundError:
        logs = []
    return {"logs": logs}

@app.get("/")
def root():
    return {"status": "ok"}

@app.delete("/logs")
def clear_logs():
    try:
        open(LOG_FILE, "w").close()
        return {"status": "ok", "message": "Logs cleared."}
    except Exception as e:
        return {"status": "error", "message": str(e)}