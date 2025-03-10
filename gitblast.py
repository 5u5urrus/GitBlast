#!/usr/bin/env python3
"""
GitBlast: A powerful GitHub secret scanner that blasts through repositories to find exposed sensitive data.
Author: Vahe Demirkhanyan
"""
import sys
import re
import requests
import math
import time
from collections import defaultdict

DORK_QUERIES = [
    "{keyword}",
    "{keyword} filename:.env password",
    "{keyword} AWS_SECRET_ACCESS_KEY",
    "{keyword} \"BEGIN RSA PRIVATE KEY\"",
    "{keyword} \"api_key\"",
    "{keyword} \"db_password\"",
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
    "{keyword} \"db_username\"",
    "{keyword} \"database_url\"",
    "{keyword} \"connectionstring\"",
]

SECRET_PATTERNS = [
    re.compile(r'(?i)(aws_secret_access_key\s*=\s*\S+)'),
    re.compile(r'(?i)(api_key\s*=\s*\S+)'),
    re.compile(r'(?i)(secret_key\s*=\s*\S+)'),
    re.compile(r'(?i)(password\s*=\s*\S+)'),
    re.compile(r'(?i)(BEGIN\s+RSA\s+PRIVATE\s+KEY)'),
    re.compile(r'(?i)(access_key\s*=\s*\S+)'),
    re.compile(r'(?i)(auth_token\s*=\s*\S+)'),
    re.compile(r'(?i)(jwt_secret\s*=\s*\S+)'),
    re.compile(r'(?i)(client_secret\s*=\s*\S+)'),
    re.compile(r'(?i)(db_connection\s*=\s*\S+)'),
    re.compile(r'(?i)(private_key\s*=\s*\S+)'),
    re.compile(r'(?i)(mongodb(?:\+srv)?:\/\/[^\s]+)'),
    re.compile(r'(?i)(redis:\/\/[^\s]+)'),
    re.compile(r'(?i)(smtp\.sendgrid\.net)'),
    re.compile(r'(?i)(hooks\.slack\.com)'),
    re.compile(r'(?i)((xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}))'),
    re.compile(r'(?i)(-----BEGIN\s+(?:CERTIFICATE|OPENSSH|PGP|DSA|EC|PRIVATE)\s+KEY)'),
    re.compile(r'(?:^|[^0-9])([0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})(?:$|[^0-9])'),
    re.compile(r'(?i)(github_token\s*=\s*\S+)'),
    re.compile(r'(?i)(AKIA[0-9A-Z]{16})'),
    re.compile(r'(?i)(sk_live_[0-9a-zA-Z]{24})'),
    re.compile(r'(?i)(sq0csp-[0-9A-Za-z\-_]{43})'),
    re.compile(r'(?:^|[^0-9A-Za-z])([0-9a-fA-F]{32})(?:$|[^0-9A-Za-z])'),
    re.compile(r'(?i)(AIza[0-9A-Za-z\-_]{35})'),
]

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
MAX_PAGES = 3
RESULTS_PER_PAGE = 30
MAX_FILE_SIZE = 1024 * 1024
ENTROPY_THRESHOLD = 4.0
RATE_LIMIT_PAUSE = 6
OUTPUT_FILE = None
USE_ENTROPY_DETECTION = False

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

def is_likely_secret(s, entropy_threshold=ENTROPY_THRESHOLD):
    if len(s) < 8:
        return False
    entropy = shannon_entropy(s)
    return entropy > entropy_threshold

def classify_as_secret(text):
    if not isinstance(text, str):
        return False
    text = text.strip('\'"` \t\r\n')
    if not (8 <= len(text) <= 100):
        return False
    has_upper = any(c.isupper() for c in text)
    has_lower = any(c.islower() for c in text)
    has_digit = any(c.isdigit() for c in text)
    has_special = any(not c.isalnum() for c in text)
    char_variety = sum([has_upper, has_lower, has_digit, has_special])
    common_words = ["test", "password", "secret", "key", "example", "demo"]
    has_common_words = any(word in text.lower() for word in common_words)
    return (char_variety >= 2 and not has_common_words)

def is_false_positive(match, content):
    if not isinstance(match, str):
        match = str(match)
    test_values = ["example", "test", "sample", "your_", "xxxx", "demo"]
    if any(tv in match.lower() for tv in test_values):
        return True
    lines = content.splitlines()
    for line in lines:
        if match in line:
            line = line.strip()
            if line.startswith('#') or line.startswith('//') or line.startswith('/*'):
                return True
    doc_patterns = ["readme.md", "documentation", "example", "tutorial"]
    lower_path = match.lower()
    if any(dp in lower_path for dp in doc_patterns):
        return True
    return False

def search_github_code(token, query, max_pages=MAX_PAGES):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    all_items = []
    for page in range(1, max_pages + 1):
        params = {
            "q": query,
            "per_page": RESULTS_PER_PAGE,
            "page": page
        }
        max_retries = 3
        for retry in range(max_retries):
            try:
                resp = requests.get(GITHUB_SEARCH_URL, headers=headers, params=params, timeout=15)
                if resp.status_code == 403 and 'rate limit exceeded' in resp.text.lower():
                    wait_time = 60
                    if 'X-RateLimit-Reset' in resp.headers:
                        reset_time = int(resp.headers['X-RateLimit-Reset'])
                        current_time = int(time.time())
                        wait_time = max(reset_time - current_time, 10)
                    print(f"[!] Rate limit exceeded. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                if resp.status_code == 200:
                    break
                print(f"[!] Error: HTTP {resp.status_code} - {resp.text}")
                if retry < max_retries - 1:
                    print(f"    Retrying in {RATE_LIMIT_PAUSE} seconds...")
                    time.sleep(RATE_LIMIT_PAUSE)
                else:
                    print(f"    Max retries reached. Skipping query: {query}")
                    return all_items
            except requests.RequestException as e:
                print(f"[!] Request exception: {e}")
                if retry < max_retries - 1:
                    print(f"    Retrying in {RATE_LIMIT_PAUSE} seconds...")
                    time.sleep(RATE_LIMIT_PAUSE)
                else:
                    print(f"    Max retries reached. Skipping query: {query}")
                    return all_items
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            all_items.extend(items)
            if len(items) < RESULTS_PER_PAGE:
                break
            if page < max_pages:
                time.sleep(RATE_LIMIT_PAUSE)
    return all_items

def get_raw_content(item, max_size=MAX_FILE_SIZE):
    html_url = item.get("html_url")
    if not html_url:
        return None
    raw_url = html_url.replace("github.com/", "raw.githubusercontent.com/")
    raw_url = raw_url.replace("/blob/", "/")
    try:
        with requests.get(raw_url, stream=True, timeout=15) as r:
            r.raise_for_status()
            content_length = r.headers.get('Content-Length')
            if content_length and int(content_length) > max_size:
                print(f"      [!] File too large: {int(content_length)/1024:.1f}KB")
                return None
            content = ""
            total_bytes = 0
            for chunk in r.iter_content(chunk_size=8192):
                total_bytes += len(chunk)
                if total_bytes > max_size:
                    print(f"      [!] Stopped reading: exceeded {max_size/1024:.1f}KB limit")
                    break
                try:
                    content += chunk.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        content += chunk.decode('latin-1')
                    except UnicodeDecodeError:
                        print(f"      [!] Could not decode file content")
                        return None
            return content
    except requests.RequestException as e:
        print(f"      [!] Error fetching raw content: {e}")
        return None

def scan_for_secrets(content, filename=""):
    if not content:
        return []
    findings = []
    for pat in SECRET_PATTERNS:
        matches = pat.findall(content)
        if matches:
            for match in matches:
                if not is_false_positive(match, content):
                    findings.append(("PATTERN", match))
    if USE_ENTROPY_DETECTION:
        try:
            deep_findings = deep_scan_content(content, filename)
            findings.extend([("ENTROPY", f) for f in deep_findings])
        except Exception as e:
            print(f"      [!] Error in deep scan: {e}")
    return findings

def deep_scan_content(content, filename=""):
    findings = []
    skip_extensions = ['.jpg', '.png', '.gif', '.jpeg', '.bmp', '.svg', 
                       '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.ico']
    if any(filename.lower().endswith(ext) for ext in skip_extensions):
        return findings
    lines = content.splitlines()
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        if '=' in line:
            parts = line.split('=', 1)
            key = parts[0].strip().lower()
            value = parts[1].strip().strip('"\'')
            secret_keys = ['key', 'secret', 'password', 'token', 'auth', 
                          'cred', 'pw', 'pass', 'login', 'access']
            if any(sk in key for sk in secret_keys) and len(value) > 6:
                if is_likely_secret(value) or classify_as_secret(value):
                    value_clean = value.split('#')[0].split('//')[0].strip()
                    findings.append(f"High entropy value in line {i+1}: {key}={value_clean}")
        else:
            words = re.findall(r'[\w\-\._~:/?#\[\]@!$&\'()*+,;=]{8,}', line)
            for word in words:
                if len(word) >= 16 and (is_likely_secret(word) or classify_as_secret(word)):
                    findings.append(f"Suspicious string in line {i+1}: {word}")
    return findings

def write_to_output(message, file_handle=None):
    print(message)
    if file_handle:
        file_handle.write(message + "\n")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <keyword> <github_token> [output_file] [--entropy]")
        print(f"  --entropy: Enable entropy-based detection (can generate more false positives)")
        sys.exit(1)
    keyword = sys.argv[1].strip()
    github_token = sys.argv[2].strip()
    global USE_ENTROPY_DETECTION
    if "--entropy" in sys.argv:
        USE_ENTROPY_DETECTION = True
        sys.argv.remove("--entropy")
    output_file = sys.argv[3].strip() if len(sys.argv) > 3 else OUTPUT_FILE
    output_handle = None
    if output_file:
        try:
            output_handle = open(output_file, 'w', encoding='utf-8')
            write_to_output(f"[*] Output will be saved to: {output_file}", output_handle)
        except Exception as e:
            print(f"[!] Error opening output file: {e}")
            output_handle = None
    write_to_output(f"[*] Searching GitHub for secrets related to: {keyword}", output_handle)
    if USE_ENTROPY_DETECTION:
        write_to_output(f"[*] Entropy-based detection is ENABLED", output_handle)
    else:
        write_to_output(f"[*] Entropy-based detection is DISABLED (use --entropy flag to enable)", output_handle)
    suspicious_results = []
    for dork_template in DORK_QUERIES:
        dork_query = dork_template.format(keyword=keyword)
        write_to_output(f"\n[+] Dork Query: '{dork_query}'", output_handle)
        search_items = search_github_code(github_token, dork_query, max_pages=MAX_PAGES)
        write_to_output(f"    Found {len(search_items)} results.", output_handle)
        for item in search_items:
            repo_name = item["repository"]["full_name"]
            path = item.get("path", "")
            html_url = item.get("html_url", "")
            write_to_output(f"   -> Checking {repo_name} / {path}", output_handle)
            write_to_output(f"      {html_url}", output_handle)
            raw_code = get_raw_content(item)
            if not raw_code:
                write_to_output("      [!] No content fetched or file is empty.\n", output_handle)
                continue
            matches = scan_for_secrets(raw_code, path)
            if matches:
                suspicious_results.append((repo_name, path, html_url, matches))
                write_to_output(f"      [SECRET FOUND]", output_handle)
                for match_type, m in matches:
                    snippet = (m[:80] + "...") if isinstance(m, str) and len(m) > 80 else m
                    write_to_output(f"         => [{match_type}] {snippet}", output_handle)
                write_to_output("", output_handle)
            else:
                write_to_output("      No secrets detected in file.\n", output_handle)
    write_to_output("\n=== Summary of Potential Secrets Found ===", output_handle)
    if not suspicious_results:
        write_to_output("No secrets detected across all dorks.", output_handle)
    else:
        write_to_output(f"Found potential secrets in {len(suspicious_results)} files:", output_handle)
        for repo_name, path, url, secrets_list in suspicious_results:
            write_to_output(f"* {repo_name} / {path}", output_handle)
            write_to_output(f"  URL: {url}", output_handle)
            write_to_output(f"  Found {len(secrets_list)} match(es).", output_handle)
    write_to_output("\nDone.\n", output_handle)
    if output_handle:
        output_handle.close()
        print(f"[*] Results saved to {output_file}")

if __name__ == "__main__":
    main()
