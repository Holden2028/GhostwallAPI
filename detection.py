import time

# --- Config ---
BOT_KEYWORDS = [
    'bot', 'crawler', 'spider', 'crawl', 'slurp',
    'google', 'bing', 'scrape', 'yandex', 'duckduckgo', 'gpt', 'ai',
    'requests', 'httpx', 'go-http-client', 'claude', 'curl',
    'fetch', 'wget', 'python', 'anthropic',
    'assistant', 'automation', 'headless', 'selenium', 'puppeteer', 'phantom'
]
COMMON_BROWSER_HEADERS = [
    'accept', 'accept-encoding', 'accept-language', 'cache-control', 'cookie', 'dnt',
    'referer', 'user-agent', 'sec-ch-ua'
]
IMPORTANT_HEADERS = {'user-agent', 'accept', 'accept-language'}

# --- Rate limiting state (in-memory, per-process) ---
RATE_LIMIT = 20          # requests
RATE_WINDOW = 60         # seconds
ip_activity = {}

def _rate_limit(ip: str) -> bool:
    """Return True if this IP should be blocked."""
    now = time.time()
    ip_activity.setdefault(ip, [])
    # Remove requests outside window
    ip_activity[ip] = [t for t in ip_activity[ip] if now - t < RATE_WINDOW]
    ip_activity[ip].append(now)
    return len(ip_activity[ip]) > RATE_LIMIT

def suspicious_headers(headers: dict) -> (bool, str):
    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing = [h for h in COMMON_BROWSER_HEADERS if h not in lower_headers]
    if any(h not in lower_headers for h in IMPORTANT_HEADERS):
        return True, f"Missing critical browser headers: {IMPORTANT_HEADERS - set(lower_headers.keys())}"
    return False, ''

def detect_bot(user_agent: str, headers: dict, ip: str) -> (str, str):
    """
    Returns (visitor_type, details)
    visitor_type: 'bot' or 'human'
    details: Reason
    """
    # --- Rate limiting ---
    if _rate_limit(ip):
        return 'bot', 'Rate limit exceeded'

    # --- Keyword in User-Agent ---
    ua = (user_agent or '').lower()
    for kw in BOT_KEYWORDS:
        if kw in ua:
            return 'bot', f"Keyword '{kw}' in User-Agent"

    # --- Suspicious headers ---
    suspicious, details = suspicious_headers(headers)
    if suspicious:
        return 'bot', details

    # --- If passed all checks, human ---
    return 'human', ''