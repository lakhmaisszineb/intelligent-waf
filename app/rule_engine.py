import re
from fastapi import Request

# ──────────────────────────────────────────────────────────────────────────────
# RÈGLES SQLi — inspirées de l'OWASP CRS (règles 942xxx)
# Source : https://github.com/coreruleset/coreruleset
# ──────────────────────────────────────────────────────────────────────────────
SQLI_PATTERNS = [
    re.compile(r"(?i)(\bselect\b.+\bfrom\b)"),        # SELECT ... FROM
    re.compile(r"(?i)(\bunion\b.+\bselect\b)"),        # UNION SELECT
    re.compile(r"(?i)(\bor\b\s+\d+\s*=\s*\d+)"),          # OR 1=1
    re.compile(r"(?i)(\bor\b\s*'[^']*'\s*=)"),             # OR '1'=
    re.compile(r"(?i)(\band\b\s+\d+\s*=\s*\d+)"),         # AND 1=1
    re.compile(r"(?i)(\band\b\s*'[^']*'\s*=)"),           # AND '1'=
    re.compile(r"(?i)(\bdrop\s+table\b)"),             # DROP TABLE
    re.compile(r"(?i)(\binsert\s+into\b)"),            # INSERT INTO
    re.compile(r"(?i)(\bdelete\s+from\b)"),            # DELETE FROM
    re.compile(r"(?i)(--|;|\/\*|\*\/)"),               # Commentaires SQL
    re.compile(r"(?i)(\bsleep\s*\()"),                 # SLEEP() - blind SQLi
    re.compile(r"(?i)(\bbenchmark\s*\()"),             # BENCHMARK() - blind SQLi
]

# ──────────────────────────────────────────────────────────────────────────────
# RÈGLES XSS — inspirées de l'OWASP CRS (règles 941xxx)
# Source : https://github.com/coreruleset/coreruleset
# ──────────────────────────────────────────────────────────────────────────────
XSS_PATTERNS = [
    re.compile(r"(?i)<script[^>]*>"),                  # <script>
    re.compile(r"(?i)<\/script>"),                     # </script>
    re.compile(r"(?i)(javascript\s*:)"),               # javascript:
    re.compile(r"(?i)(onerror\s*=)"),                  # onerror=
    re.compile(r"(?i)(onload\s*=)"),                   # onload=
    re.compile(r"(?i)(onclick\s*=)"),                  # onclick=
    re.compile(r"(?i)(onmouseover\s*=)"),              # onmouseover=
    re.compile(r"(?i)<iframe[^>]*>"),                  # <iframe>
    re.compile(r"(?i)(alert\s*\()"),                   # alert()
    re.compile(r"(?i)(document\.cookie)"),             # document.cookie
]


def _match_patterns(value: str, patterns: list) -> str | None:
    """
    Vérifie si une valeur correspond à l'un des patterns.
    Retourne la description du pattern trouvé, ou None si aucun match.
    """
    for pattern in patterns:
        if pattern.search(value):
            return pattern.pattern
    return None


async def check_request(request: Request) -> dict:
    """
    Inspecte la requête entrante contre les règles SQLi et XSS.
    Retourne un dictionnaire :
      - {"blocked": False}                        si la requête est saine
      - {"blocked": True, "type": "...", "reason": "...", "location": "..."}  si attaque détectée
    """
    # ── 1. Collecter toutes les valeurs à inspecter ──────────────────────────

    inputs = {}

    # Paramètres GET (query string) ex: ?id=1 OR 1=1
    for key, value in request.query_params.items():
        inputs[f"query_param:{key}"] = value

    # Corps de la requête (POST/PUT) ex: formulaire ou JSON
    try:
        body = await request.body()
        if body:
            inputs["body"] = body.decode("utf-8", errors="ignore")
    except Exception:
        pass

    # ── 2. Vérifier chaque valeur contre les règles ──────────────────────────

    for location, value in inputs.items():

        # Vérification SQLi
        match = _match_patterns(value, SQLI_PATTERNS)
        if match:
            return {
                "blocked": True,
                "type": "SQLi",
                "reason": f"Patron détecté : {match}",
                "location": location,
            }

        # Vérification XSS
        match = _match_patterns(value, XSS_PATTERNS)
        if match:
            return {
                "blocked": True,
                "type": "XSS",
                "reason": f"Patron détecté : {match}",
                "location": location,
            }

    # ── 3. Aucune attaque détectée ───────────────────────────────────────────
    return {"blocked": False}
