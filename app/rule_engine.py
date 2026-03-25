import re
import json
import os
from fastapi import Request
from fastapi.responses import Response

RULES_FILE = "parsed_rules.json"
_compiled_rules: dict[str, list[re.Pattern]] = {}

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

def _check_value(value: str) -> tuple[bool, str, str]:
    for category, patterns in _compiled_rules.items():
        for pattern in patterns:
            if pattern.search(value):
                return True, category, pattern.pattern[:80]
    return False, "", ""

async def analyze_request(request: Request) -> tuple[bool, str, str]:
    for param_name, param_value in request.query_params.items():
        is_malicious, category, pattern = _check_value(param_value)
        if is_malicious:
            return True, f"Attaque dans le paramètre GET '{param_name}'", f"Catégorie: {category} | Pattern: {pattern}"

    try:
        body_bytes = await request.body()
        if body_bytes:
            body_text = body_bytes.decode("utf-8", errors="ignore")
            is_malicious, category, pattern = _check_value(body_text)
            if is_malicious:
                return True, "Attaque dans le body", f"Catégorie: {category} | Pattern: {pattern}"
    except Exception:
        pass
#    for header_name in ["user-agent", "referer", "x-forwarded-for", "cookie"]:
    for header_name in ["user-agent", "x-forwarded-for", "cookie"]:
        header_value = request.headers.get(header_name, "")
        if header_value:
            is_malicious, category, pattern = _check_value(header_value)
            if is_malicious:
                return True, f"Attaque dans le header '{header_name}'", f"Catégorie: {category} | Pattern: {pattern}"

    return False, "", ""

def block_response(reason: str, detail: str) -> Response:
    return Response(
        content=f"403 Forbidden\n\nRaison: {reason}\n{detail}",
        status_code=403,
        media_type="text/plain"
    )

load_rules()