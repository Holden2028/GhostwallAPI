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
    'accept', 'accept-encoding', 'accept-language', 'cache-control',
    'cookie', 'dnt', 'referer', 'user-agent', 'sec-ch-ua',
    'sec-fetch-mode', 'sec-fetch-site', 'upgrade-insecure-requests'
]

IMPORTANT_HEADERS = {'user-agent', 'accept', 'accept-language'}

# --- Rate limiting state (in-memory) ---
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

def fingerprint_score(fingerprint: dict) -> int:
    score = 0

    # Header quality
    headers = fingerprint.get("headers", {})
    header_keys = [k.lower() for k in headers.keys()]
    score += sum(1 for h in COMMON_BROWSER_HEADERS if h in header_keys)

    # Penalize missing important headers
    for h in IMPORTANT_HEADERS:
        if h not in header_keys:
            score -= 5

    # Cookie presence
    cookies = fingerprint.get("cookies", {})
    if cookies:
        score += 3
    else:
        score -= 3

    # Presence of known fields
    if fingerprint.get("referer"):
        score += 2
    if fingerprint.get("accept_language"):
        score += 1
    if fingerprint.get("accept_encoding"):
        score += 1

    return score

def detect_bot(user_agent: str, fingerprint: dict, ip: str, path: str = "") -> (str, str):
    # Skip detection for trivial paths
    ignored_paths = {"/favicon.ico", "/robots.txt", "/apple-touch-icon.png"}
    if path in ignored_paths:
        return 'human', f"Ignored path {path}"

    if _rate_limit(ip):
        return 'bot', 'Rate limit exceeded'

    ua = (user_agent or '').lower()
    for kw in BOT_KEYWORDS:
        if kw in ua:
            return 'bot', f"Keyword '{kw}' in User-Agent"

    headers = fingerprint.get("headers", {})
    suspicious, header_reason = suspicious_headers(headers)
    if suspicious:
        return 'bot', header_reason

    score = fingerprint_score(fingerprint)
    if score < 11:
        return 'bot', f"Low fingerprint score: {score}"

    return 'human', f"Fingerprint score OK: {score}"