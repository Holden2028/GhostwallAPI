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
RATE_LIMIT = 20
RATE_WINDOW = 60
ip_activity = {}

def _rate_limit(ip: str) -> bool:
    now = time.time()
    ip_activity.setdefault(ip, [])
    ip_activity[ip] = [t for t in ip_activity[ip] if now - t < RATE_WINDOW]
    ip_activity[ip].append(now)
    return len(ip_activity[ip]) > RATE_LIMIT

def suspicious_headers(headers: dict) -> (bool, str):
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if any(h not in lower_headers for h in IMPORTANT_HEADERS):
        return True, f"Missing critical browser headers: {IMPORTANT_HEADERS - set(lower_headers.keys())}"
    return False, ''

def detect_bot(user_agent: str, headers: dict, ip: str) -> (str, str):
    if _rate_limit(ip):
        return 'bot', 'Rate limit exceeded'

    ua = (user_agent or '').lower()
    for kw in BOT_KEYWORDS:
        if kw in ua:
            return 'bot', f"Keyword '{kw}' in User-Agent"

    suspicious, details = suspicious_headers(headers)
    if suspicious:
        return 'bot', details

    return 'human', ''