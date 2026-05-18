import re
import json
import os
from fastapi import Request
from fastapi.responses import Response

RULES_FILE = "parsed_rules.json"
_compiled_rules: dict[str, list[re.Pattern]] = {}

SCANNER_SIGNATURES = re.compile(
    r"sqlmap|nikto|nmap|nessus|masscan|dirbuster|gobuster|wfuzz|"
    r"burpsuite|acunetix|openvas|zap|hydra|metasploit|nuclei|"
    r"zgrab|shodan|censys|python-requests|curl/|wget/",
    re.IGNORECASE
)

def check_scanner(user_agent: str) -> bool:
    return bool(SCANNER_SIGNATURES.search(user_agent))

def load_rules():
    global _compiled_rules
    if not os.path.exists(RULES_FILE):
        print(f"[WARN] '{RULES_FILE}' introuvable. Lance parse_rules.py d'abord.")
        return
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        raw_rules = json.load(f)
    total = 0
    for category, patterns in raw_rules.items():
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
                total += 1
            except re.error:
                pass
        _compiled_rules[category] = compiled
    print(f"[WAF] ça marche bien, {total} règles OWASP chargées ({len(_compiled_rules)} catégories)")

_CATEGORY_LABELS: dict[str, str] = {
    "sql_injection": "SQL Injection",
    "xss":           "XSS",
    "rce":           "Remote Code Execution",
    "lfi":           "Path Traversal",
    "rfi":           "Remote File Inclusion",
    "php_injection": "Code Injection",
    "java_attack":   "Code Injection",
    "SQLi":          "SQL Injection",
    "XSS":           "XSS",
    "General":       "",
}

def _check_value(value: str) -> tuple[bool, str, str]:
    for category, patterns in _compiled_rules.items():
        for pattern in patterns:
            if pattern.search(value):
                return True, category, value[:100]
    return False, "", ""

FORBIDDEN_METHODS = {"TRACE", "CONNECT"}

RATE_LIMIT = 100
RATE_WINDOW = 60
_request_counts: dict[str, list] = {}

def check_rate_limit(ip: str) -> bool:
    import time
    now = time.time()
    if ip not in _request_counts:
        _request_counts[ip] = []
    _request_counts[ip] = [t for t in _request_counts[ip] if now - t < RATE_WINDOW]
    _request_counts[ip].append(now)
    return len(_request_counts[ip]) > RATE_LIMIT

async def analyze_request(request: Request) -> tuple[bool, str, str, str]:
    client_ip = request.client.host if request.client else "unknown"
    if check_rate_limit(client_ip):
        return True, "Rate limit dépassé", f"IP: {client_ip} | Plus de {RATE_LIMIT} requêtes/{RATE_WINDOW}s", ""

    if request.method in FORBIDDEN_METHODS:
        return True, "Méthode HTTP interdite", f"Méthode: {request.method}", ""

    user_agent = request.headers.get("user-agent", "")
    if user_agent and check_scanner(user_agent):
        return True, "Scanner détecté", f"User-Agent: {user_agent[:80]}", ""

    for param_name, param_value in request.query_params.items():
        is_malicious, category, matched_payload = _check_value(param_value)
        if is_malicious:
            return True, f"Attaque dans le paramètre GET '{param_name}'", \
                f"Catégorie={category} | Payload={matched_payload}", category
    try:
        body_bytes = await request.body()
        if body_bytes:
            body_text = body_bytes.decode("utf-8", errors="ignore")
            is_malicious, category, matched_payload = _check_value(body_text)
            if is_malicious:
                return True, "Attaque dans le body", \
                    f"Catégorie={category} | Payload={matched_payload}", category
    except Exception:
        pass
    for header_name in ["user-agent", "x-forwarded-for", "cookie"]:
        header_value = request.headers.get(header_name, "")
        if header_value:
            is_malicious, category, pattern = _check_value(header_value)
            if is_malicious:
                return True, f"Attaque dans le header '{header_name}'", \
                    f"Catégorie: {category} | Pattern: {pattern}", category

    return False, "", "", ""

def block_response(reason: str, detail: str, attack_type: str = "") -> Response:
    status_code = 429 if "Rate limit" in reason else 403
    label = _CATEGORY_LABELS.get(attack_type, "")
    body = f"{label} detected." if label else "Access Denied."
    return Response(
        content=f"{status_code} {'Too Many Requests' if status_code == 429 else 'Forbidden'}\n\n{body}",
        status_code=status_code,
        media_type="text/plain"
    )

load_rules()