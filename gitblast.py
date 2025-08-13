#!/usr/bin/env python3
"""
GitBlast: A powerful GitHub secret scanner that blasts through repositories to find exposed sensitive data.
Author: Vahe Demirkhanyan
"""

import sys
import re
import math
import time
import argparse
import threading
import os
import base64
import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter, Retry

# -----------------------
# Config / Defaults
# -----------------------
GITHUB_SEARCH_URL = "https://api.github.com/search/code"
MAX_PAGES = 3
RESULTS_PER_PAGE = 30
MAX_FILE_SIZE = 1024 * 1024
ENTROPY_THRESHOLD = 4.3  # raised a bit
RATE_LIMIT_PAUSE = 6
OUTPUT_FILE = None

# concurrency / rate
DEFAULT_THREADS = 6
DEFAULT_RAW_RPS = 4  # token bucket target

# Will be set by argparse
USE_ENTROPY_DETECTION = False

PRINT_LOCK = threading.Lock()
RAW_TOKEN_BUCKET = None  # set in main()
SESSION: requests.Session = None  # set in main()

DORK_QUERIES = [
    "{keyword}",
    "{keyword} filename:.env password",
    "{keyword} AWS_SECRET_ACCESS_KEY",
    '{keyword} "BEGIN RSA PRIVATE KEY"',
    '{keyword} "api_key"',
    '{keyword} "db_password"',
    "{keyword} filename:config password",
    "{keyword} filename:settings password",
    "{keyword} filename:credentials",
    "{keyword} filename:id_rsa",
    "{keyword} filename:htpasswd",
    "{keyword} filename:npmrc _auth",
    "{keyword} filename:dockercfg auth",
    "{keyword} filename:properties password",
    "{keyword} filename:key.pem",
    "{keyword} extension:yaml password",
    "{keyword} extension:json password",
    "{keyword} extension:xml password",
    "{keyword} TOKEN",
    "{keyword} SECRET",
    '{keyword} "db_username"',
    '{keyword} "database_url"',
    '{keyword} "connectionstring"',
]

# Tighten dorks (noise drop, low risk)
QUALIFIERS = (
    " in:file size:<20000"
    " -extension:md -filename:README -filename:CHANGELOG -filename:LICENSE"
    " -path:tests -path:test -path:examples -path:example -path:samples -path:sample"
    " -path:docs -path:.github -path:.git"
)

TEXT_EXTS = {
    '.env','.json','.yaml','.yml','.py','.js','.ts','.tsx','.php','.rb','.go',
    '.java','.cs','.ini','.cfg','.conf','.properties','.toml','.sh','.ps1','.xml','.txt'
}
SKIP_PATH_PARTS = (
    "node_modules/", "vendor/", "dist/", "build/", "target/",
    "coverage/", "__pycache__/", "bin/", "obj/", ".git/", ".svn/",
    "third_party/", "submodules/"
)

KNOWN_PREFIXES = (
    "ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_",
    "sk_live_", "sk_test_", "AKIA", "ASIA", "AIza", "sq0csp-"
)

def should_fetch(path):
    p = (path or "").lower()
    if any(part in p for part in SKIP_PATH_PARTS):
        return False
    _, ext = os.path.splitext(p)
    return (ext in TEXT_EXTS) or ext == ''

# -----------------------
# Utilities
# -----------------------
def write_to_output(message, file_handle=None):
    with PRINT_LOCK:
        print(message)
        if file_handle:
            file_handle.write(message + "\n")

def shannon_entropy(string):
    if not string:
        return 0
    if not isinstance(string, str):
        string = str(string)
    entropy = 0
    string_len = len(string)
    char_counts = defaultdict(int)
    for char in string:
        char_counts[char] += 1
    for count in char_counts.values():
        p_x = float(count) / string_len
        entropy += -p_x * math.log(p_x, 2)
    return entropy

def is_likely_secret_basic(s, entropy_threshold=ENTROPY_THRESHOLD):
    ent = shannon_entropy(s)
    return ent > entropy_threshold

def is_likely_secret_advanced(s):
    if not isinstance(s, str):
        s = str(s)
    s = s.strip()
    # If matches a known key/token prefix, allow shorter
    if any(s.startswith(p) for p in KNOWN_PREFIXES):
        return is_likely_secret_basic(s)
    # Otherwise require length and entropy
    if len(s) < 20:
        return False
    return is_likely_secret_basic(s)

def classify_as_secret(text):
    if not isinstance(text, str):
        return False
    text = text.strip('\'"` \t\r\n')
    if not (8 <= len(text) <= 200):
        return False
    has_upper = any(c.isupper() for c in text)
    has_lower = any(c.islower() for c in text)
    has_digit = any(c.isdigit() for c in text)
    has_special = any(not c.isalnum() for c in text)
    char_variety = sum([has_upper, has_lower, has_digit, has_special])
    common_words = ["test", "password", "secret", "key", "example", "demo"]
    has_common_words = any(word in text.lower() for word in common_words)
    return (char_variety >= 2 and not has_common_words)

def luhn_ok(number_str):
    digits = [int(c) for c in re.sub(r'\D', '', str(number_str))]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, n in enumerate(digits[:-1]):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return (checksum + digits[-1]) % 10 == 0

def b64url_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    pad = '=' * (-len(s) % 4)
    return base64.b64decode(s + pad)

def jwt_header_json_ok(token):
    parts = token.split('.')
    if len(parts) != 3:
        return False
    try:
        hdr = b64url_decode(parts[0])
        data = json.loads(hdr.decode('utf-8', errors='ignore'))
        return isinstance(data, dict) and "alg" in data
    except Exception:
        return False

def is_false_positive(match_text, content, filename=""):
    """Safer FP filter: placeholders, file context, and simple block-comment tracking."""
    m = str(match_text)
    low = m.lower()
    if any(t in low for t in ("example","test","sample","your_","xxxx","demo")):
        return True
    if filename and any(x in filename.lower() for x in ("readme.md","docs","example","tutorial")):
        return True

    in_block = False
    for line in content.splitlines():
        if "/*" in line:
            in_block = True
        if "*/" in line:
            in_block = False
            continue
        idx = line.find(m)
        if idx != -1:
            before = line[:idx].lstrip()
            if in_block or before.startswith(("#","//")):
                return True
    return False

def make_snippet(line, start, end, max_len=120):
    line = line.rstrip('\n')
    L = len(line)
    if L <= max_len:
        return line
    context = max_len // 2
    s = max(0, (start + end)//2 - context)
    e = min(L, s + max_len)
    prefix = "…" if s > 0 else ""
    suffix = "…" if e < L else ""
    return prefix + line[s:e] + suffix

def mask_for_json(v):
    v = str(v)
    return v if len(v) <= 12 else f"{v[:6]}…{v[-6:]}"

# -----------------------
# Patterns
# -----------------------
CREDIT_CARD_REGEX = re.compile(
    r'(?:^|[^0-9])([0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})(?:$|[^0-9])'
)

SECRET_PATTERNS = [
    ("AWS_SECRET_ACCESS_KEY", re.compile(r'(?i)aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})')),
    ("AWS_ACCESS_KEY_ID",     re.compile(r'(?i)\bAKIA[0-9A-Z]{16}\b')),
    ("AWS_STS_KEY_ID",        re.compile(r'(?i)\bASIA[0-9A-Z]{16}\b')),

    ("GH_TOKEN_GHP",          re.compile(r'\bghp_[A-Za-z0-9]{36}\b')),
    ("GH_TOKEN_PATS",         re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}\b')),
    ("GH_TOKEN_VARIANTS",     re.compile(r'\bgh(?:o|u|s|r)_[A-Za-z0-9]{36}\b')),

    ("STRIPE_SECRET",         re.compile(r'\bsk_(?:live|test)_[A-Za-z0-9]{24}\b')),
    ("SQUARE_SECRET",         re.compile(r'\bsq0csp-[0-9A-Za-z\-_]{43}\b')),

    ("TWILIO_SECRET_SID",     re.compile(r'\bSK[0-9a-f]{32}\b')),
    ("TWILIO_ACCOUNT_SID",    re.compile(r'\bAC[0-9a-f]{32}\b')),
    ("TWILIO_AUTH_TOKEN",     re.compile(r'(?i)\bTWILIO_AUTH_TOKEN\b[^\S\r\n]*[:=][^\S\r\n]*([0-9a-f]{32})')),

    ("GOOGLE_API_KEY",        re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),

    ("SLACK_TOKEN",           re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b')),
    ("SLACK_WEBHOOK",         re.compile(r'https?://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}')),
    ("DISCORD_WEBHOOK",       re.compile(r'https?://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[A-Za-z0-9/_-]{20,}')),
    ("SENDGRID_KEY",          re.compile(r'\bSG\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{40,}\b')),

    ("JWT",                   re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b')),

    ("GENERIC_PRIVATE_KEY",   re.compile(r'(?i)-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE|CERTIFICATE)\s+KEY-----')),
    ("GENERIC_PASSWORD_KV",   re.compile(r'(?i)\bpassword\s*[:=]\s*([^\s]+)')),
    ("GENERIC_SECRET_KV",     re.compile(r'(?i)\b(secret|secret_key|client_secret|api_key|apikey|auth_token)\s*[:=]\s*([^\s]+)')),
    ("GENERIC_CONN_STR",      re.compile(r'(?i)\b(connection|string|dsn)\b\s*[:=]\s*([^\s]+)')),

    ("MONGODB_URI",           re.compile(r'(?i)\bmongodb(?:\+srv)?:\/\/[^\s]+')),
    ("REDIS_URI",             re.compile(r'(?i)\bredis:\/\/[^\s]+')),
    ("SENDGRID_SMTP",         re.compile(r'(?i)smtp\.sendgrid\.net')),
    ("GITHUB_TOKEN_KV",       re.compile(r'(?i)github_token\s*=\s*(\S+)')),

    ("CREDIT_CARD",           CREDIT_CARD_REGEX),
]

# Provider-aware validators (precision boost, low risk)
PROVIDERS = {
    "STRIPE_SECRET":   lambda v: v.startswith(("sk_live_","sk_test_")) and len(v) >= 32,
    "GOOGLE_API_KEY":  lambda v: v.startswith("AIza") and len(v) == 39,  # "AIza" + 35
    "GH_TOKEN_GHP":    lambda v: v.startswith("ghp_") and len(v) >= 40,
    "GH_TOKEN_PATS":   lambda v: v.startswith("github_pat_") and len(v) >= 80,
    "SLACK_WEBHOOK":   lambda v: v.startswith("https://hooks.slack.com/services/"),
}

# -----------------------
# Token Bucket
# -----------------------
class TokenBucket:
    def __init__(self, rate_per_sec, capacity=None):
        self.rate = float(rate_per_sec)
        self.capacity = capacity if capacity is not None else max(1.0, rate_per_sec)
        self._tokens = self.capacity
        self._last = time.time()
        self._lock = threading.Lock()

    def consume(self, tokens=1.0):
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            if self._tokens < tokens:
                needed = tokens - self._tokens
                wait_time = needed / self.rate if self.rate > 0 else 1.0
        if 'wait_time' in locals() and wait_time > 0:
            time.sleep(wait_time)
            return self.consume(tokens)
        with self._lock:
            self._tokens -= tokens
            return True

# -----------------------
# HTTP Session (reuse + retries + pooling)
# -----------------------
def make_session(github_token: str, pool_size: int) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "GitBlast/1.2",
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {github_token}",
    })
    retry = Retry(
        total=5, connect=3, read=3,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_size, pool_maxsize=pool_size)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

# -----------------------
# GitHub Search
# -----------------------
def search_github_code(query, max_pages=MAX_PAGES, per_page=RESULTS_PER_PAGE):
    all_items = []
    for page in range(1, max_pages + 1):
        params = {
            "q": query,
            "per_page": per_page,
            "page": page,
            "sort": "indexed",
            "order": "desc",
        }
        max_retries = 3
        attempt = 0
        while attempt < max_retries:
            attempt += 1
            try:
                resp = SESSION.get(GITHUB_SEARCH_URL, params=params, timeout=20)
            except requests.RequestException as e:
                write_to_output(f"[!] Request exception: {e}")
                if attempt < max_retries:
                    write_to_output(f"    Retrying in {RATE_LIMIT_PAUSE} seconds...")
                    time.sleep(RATE_LIMIT_PAUSE)
                    continue
                else:
                    write_to_output(f"    Max retries reached. Skipping query: {query}")
                    break

            status = resp.status_code
            try:
                body_lower = resp.text.lower()
            except Exception:
                body_lower = ""

            retry_after = resp.headers.get("Retry-After")
            rl_remaining = resp.headers.get("X-RateLimit-Remaining")
            rl_reset = resp.headers.get("X-RateLimit-Reset")

            def sleep_until_reset(default_wait=60):
                wait_time = default_wait
                if retry_after:
                    try:
                        wait_time = max(int(float(retry_after)), 5)
                    except Exception:
                        pass
                elif rl_remaining == "0" and rl_reset:
                    try:
                        reset_time = int(rl_reset)
                        current_time = int(time.time())
                        wait_time = max(reset_time - current_time, 5)
                    except Exception:
                        pass
                write_to_output(f"[!] Backing off for {wait_time} seconds due to rate limiting/abuse detection...")
                time.sleep(wait_time)

            if status in (403, 429):
                # Session retry already handles 429; still handle 403 abuse/rate-limit here.
                if ("rate limit" in body_lower) or ("abuse detection" in body_lower) or retry_after or (rl_remaining == "0"):
                    sleep_until_reset()
                    continue
                else:
                    write_to_output(f"[!] Error: HTTP {status} - {resp.text[:200]}")
                    if attempt < max_retries:
                        write_to_output(f"    Retrying in {RATE_LIMIT_PAUSE} seconds...")
                        time.sleep(RATE_LIMIT_PAUSE)
                        continue
                    else:
                        write_to_output(f"    Max retries reached. Skipping query: {query}")
                        break

            if status != 200:
                write_to_output(f"[!] Error: HTTP {status} - {resp.text[:200]}")
                if attempt < max_retries:
                    write_to_output(f"    Retrying in {RATE_LIMIT_PAUSE} seconds...")
                    time.sleep(RATE_LIMIT_PAUSE)
                    continue
                else:
                    write_to_output(f"    Max retries reached. Skipping query: {query}")
                    break

            try:
                data = resp.json()
            except ValueError:
                write_to_output("    [!] Could not decode JSON response.")
                break

            items = data.get("items", [])
            all_items.extend(items)
            if len(items) < per_page:
                attempt = max_retries
                break

            time.sleep(RATE_LIMIT_PAUSE)
            break

    return all_items

# -----------------------
# Content Fetch & Scan
# -----------------------
def get_raw_content(item, max_size=MAX_FILE_SIZE, max_retries=3):
    """Fetch raw file content from a code search 'item'. Uses Session + token bucket."""
    path = item.get("path", "")
    if not should_fetch(path):
        return None

    html_url = item.get("html_url")
    if not html_url:
        return None
    raw_url = html_url.replace("github.com/", "raw.githubusercontent.com/").replace("/blob/", "/")

    tries = 0
    while tries < max_retries:
        tries += 1
        if RAW_TOKEN_BUCKET:
            RAW_TOKEN_BUCKET.consume(1)

        r = None
        try:
            r = SESSION.get(raw_url, stream=True, timeout=20)
            if r.status_code == 429:
                ra = r.headers.get("Retry-After")
                wait_time = int(float(ra)) if ra else 5
                write_to_output(f"      [!] 429 on raw fetch. Sleeping {wait_time}s then retrying...")
                time.sleep(wait_time)
                continue
            r.raise_for_status()

            content_length = r.headers.get('Content-Length')
            if content_length and int(content_length) > max_size:
                write_to_output(f"      [!] File too large: {int(content_length)/1024:.1f}KB")
                return None

            chunks = []
            total_bytes = 0
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total_bytes += len(chunk)
                if total_bytes > max_size:
                    write_to_output(f"      [!] Stopped reading: exceeded {max_size/1024:.1f}KB limit")
                    break
                chunks.append(chunk)

            blob = b''.join(chunks)
            for enc in ('utf-8', 'latin-1'):
                try:
                    return blob.decode(enc)
                except UnicodeDecodeError:
                    continue
            write_to_output(f"      [!] Could not decode file content")
            return None
        except requests.RequestException as e:
            write_to_output(f"      [!] Error fetching raw content: {e}")
            if tries < max_retries:
                time.sleep(2 * tries)
                continue
            return None
        finally:
            if r is not None:
                r.close()
    return None

def scan_for_secrets(content, filename=""):
    if not content:
        return []
    findings = []
    seen_line_offsets = set()

    lines = content.splitlines()
    for line_no, line in enumerate(lines, 1):
        raw_line = line
        line = line.strip()
        if not line:
            continue

        if line.startswith('#') or line.startswith('//'):
            continue

        for name, pat in SECRET_PATTERNS:
            for m in pat.finditer(raw_line):
                if m.groups():
                    val = next((g for g in m.groups() if g), m.group(0))
                else:
                    val = m.group(0)

                # Quick provider validators
                if not PROVIDERS.get(name, lambda _: True)(val):
                    continue

                # Special validations
                if name == "CREDIT_CARD" and not luhn_ok(val):
                    continue
                if name == "JWT" and not jwt_header_json_ok(val):
                    continue

                if is_false_positive(val, content, filename):
                    continue

                start, end = m.start(), m.end()
                key = (name, line_no, start, end)
                if key in seen_line_offsets:
                    continue
                seen_line_offsets.add(key)

                snippet = make_snippet(raw_line, start, end)
                findings.append(("PATTERN", name, val, line_no, snippet))

        if USE_ENTROPY_DETECTION:
            if '=' in raw_line:
                k, v = raw_line.split('=', 1)
                key_name = k.strip().lower()
                value = v.strip().strip('"\'')
                ctx_keys = ('secret', 'token', 'passwd', 'password', 'apikey', 'client_secret',
                            'private_key', 'connection', 'string', 'dsn', 'auth')
                if any(ck in key_name for ck in ctx_keys) and len(value) > 6:
                    if is_likely_secret_advanced(value) or classify_as_secret(value):
                        start = max(0, raw_line.find(value))
                        snippet = make_snippet(raw_line, start, start+len(value))
                        findings.append(("ENTROPY", "KV", value, line_no, snippet))
            else:
                for word in re.findall(r'[\w\-\._~:/?#\[\]@!$&\'()*+,;=]{16,}', raw_line):
                    if is_likely_secret_advanced(word) or classify_as_secret(word):
                        start = raw_line.find(word)
                        snippet = make_snippet(raw_line, start, start+len(word))
                        findings.append(("ENTROPY", "WORD", word, line_no, snippet))

    return findings

# -----------------------
# CLI / Main
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="GitBlast: GitHub secret scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument("keyword", help="Search keyword (e.g., org/repo/company name)")
    p.add_argument("github_token", help="GitHub Personal Access Token")
    p.add_argument("output_file", nargs="?", default=OUTPUT_FILE, help="Optional output file path")
    p.add_argument("--entropy", action="store_true", help="Enable entropy-based detection (more noisy)")
    p.add_argument("--max-pages", type=int, default=MAX_PAGES, help="Max search pages per dork")
    p.add_argument("--per-page", type=int, default=RESULTS_PER_PAGE, help="Results per page (GitHub max 100)")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Concurrent raw fetch workers")
    p.add_argument("--raw-rps", type=float, default=DEFAULT_RAW_RPS, help="Throttle for raw.githubusercontent.com requests (per second)")
    p.add_argument("--json", action="store_true", help="Output findings as JSON")
    p.add_argument("--fail-on-findings", action="store_true", help="Exit with code 2 if findings exist (CI-friendly)")
    return p.parse_args()

def worker_process_item(item, output_handle):
    repo_name = item["repository"]["full_name"]
    path = item.get("path", "")
    html_url = item.get("html_url", "")

    write_to_output(f"   -> Checking {repo_name} / {path}", output_handle)
    write_to_output(f"      {html_url}", output_handle)

    raw_code = get_raw_content(item)
    if not raw_code:
        write_to_output("      [!] No content fetched or file is empty.\n", output_handle)
        return None

    matches = scan_for_secrets(raw_code, path)
    if matches:
        write_to_output(f"      [SECRET FOUND]", output_handle)
        for mtype, name, val, line_no, snippet in matches:
            preview = val if len(val) <= 80 else (val[:40] + "…" + val[-8:])
            write_to_output(f"         => [{mtype}:{name}] {path}:{line_no}  {preview}", output_handle)
            write_to_output(f"            {snippet}", output_handle)
        write_to_output("", output_handle)
        return (repo_name, path, html_url, matches)
    else:
        write_to_output("      No secrets detected in file.\n", output_handle)
        return None

def main():
    global USE_ENTROPY_DETECTION, MAX_PAGES, RESULTS_PER_PAGE, RAW_TOKEN_BUCKET, SESSION

    args = parse_args()
    keyword = args.keyword.strip()
    github_token = args.github_token.strip()
    USE_ENTROPY_DETECTION = bool(args.entropy)
    MAX_PAGES = int(args.max_pages)
    RESULTS_PER_PAGE = int(args.per_page)

    # Build Session with pooling/retries and auth (used for API + raw)
    pool_size = max(10, args.threads * 2)
    SESSION = make_session(github_token, pool_size)

    output_handle = None
    if args.output_file:
        try:
            output_handle = open(args.output_file, 'w', encoding='utf-8')
            write_to_output(f"[*] Output will be saved to: {args.output_file}", output_handle)
        except Exception as e:
            write_to_output(f"[!] Error opening output file: {e}")
            output_handle = None

    write_to_output(f"[*] Searching GitHub for secrets related to: {keyword}", output_handle)
    write_to_output(f"[*] Entropy-based detection is {'ENABLED' if USE_ENTROPY_DETECTION else 'DISABLED'}", output_handle)
    write_to_output(f"[*] Concurrency: threads={args.threads}, raw_rps={args.raw_rps}", output_handle)

    RAW_TOKEN_BUCKET = TokenBucket(rate_per_sec=args.raw_rps, capacity=max(1.0, args.raw_rps*2))

    # Collect and deduplicate items across all dorks
    dedup = set()
    work_items = []

    for dork_template in DORK_QUERIES:
        base = dork_template.format(keyword=keyword)
        dork_query = (base + QUALIFIERS).strip()
        write_to_output(f"\n[+] Dork Query: '{dork_query}'", output_handle)
        search_items = search_github_code(dork_query, max_pages=MAX_PAGES, per_page=RESULTS_PER_PAGE)
        write_to_output(f"    Found {len(search_items)} results.", output_handle)

        added = 0
        for item in search_items:
            repo = item.get("repository", {})
            repo_id = repo.get("id", repo.get("full_name", ""))
            path = item.get("path", "")
            sha = item.get("sha") or item.get("html_url")
            key = (repo_id, path, sha)
            if key in dedup:
                continue
            dedup.add(key)
            work_items.append(item)
            added += 1
        write_to_output(f"    Added {added} new files after de-dup.", output_handle)

    write_to_output(f"\n[*] Total unique files to scan: {len(work_items)}", output_handle)

    suspicious_results = []
    if work_items:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(worker_process_item, item, output_handle) for item in work_items]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    suspicious_results.append(res)

    write_to_output("\n=== Summary of Potential Secrets Found ===", output_handle)
    if not suspicious_results:
        write_to_output("No secrets detected across all dorks.", output_handle)
    else:
        write_to_output(f"Found potential secrets in {len(suspicious_results)} files:", output_handle)
        for repo_name, path, url, matches in suspicious_results:
            write_to_output(f"* {repo_name} / {path}", output_handle)
            write_to_output(f"  URL: {url}", output_handle)
            write_to_output(f"  Found {len(matches)} match(es).", output_handle)

    # Optional JSON for pipelines
    if args.json:
        out = []
        for repo_name, path, url, matches in suspicious_results:
            out.append({
                "repo": repo_name,
                "path": path,
                "url": url,
                "matches": [{"type": t, "rule": n, "line": ln, "preview": mask_for_json(v)} for t, n, v, ln, _ in matches]
            })
        print(json.dumps(out, ensure_ascii=False))

    # CI-friendly exit
    if args.fail_on_findings and suspicious_results:
        sys.exit(2)

    write_to_output("\nDone.\n", output_handle)
    if output_handle:
        output_handle.close()
        print(f"[*] Results saved to {args.output_file}")

if __name__ == "__main__":
    main()
