import requests
import time

WAF = "http://localhost:8000"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# Récupère ton PHPSESSID depuis le navigateur (F12 → Application → Cookies)
COOKIE = "PHPSESSID=3l4pe8i1i3bgpmnhhkupf0hq61; security=low"
HEADERS["Cookie"] = COOKIE

tests = [
    # ================================================================
    # MODELE EXPERT SQLi — doit être détecté avec score élevé
    # ================================================================
    ("SQLi classique",          "GET", "/vulnerabilities/sqli/",
     {"id": "1' OR '1'='1", "Submit": "Submit"}, 403),

    ("SQLi UNION",              "GET", "/vulnerabilities/sqli/",
     {"id": "1 UNION SELECT 1,database()--", "Submit": "Submit"}, 403),

    ("SQLi time-based",         "GET", "/vulnerabilities/sqli/",
     {"id": "1' AND SLEEP(5)--", "Submit": "Submit"}, 403),

    ("SQLi obfusqué casse",     "GET", "/vulnerabilities/sqli/",
     {"id": "1' oR '1'='1", "Submit": "Submit"}, 403),

    ("SQLi commentaires",       "GET", "/vulnerabilities/sqli/",
     {"id": "1'/**/OR/**/1=1--", "Submit": "Submit"}, 403),

    # ================================================================
    # MODELE EXPERT XSS — doit être détecté avec score élevé
    # ================================================================
    ("XSS script classique",    "GET", "/vulnerabilities/xss_r/",
     {"name": "<script>alert(1)</script>"}, 403),

    ("XSS img onerror",         "GET", "/vulnerabilities/xss_r/",
     {"name": "<img src=x onerror=alert(1)>"}, 403),

    ("XSS javascript",          "GET", "/vulnerabilities/xss_r/",
     {"name": "javascript:alert(document.cookie)"}, 403),

    ("XSS obfusqué casse",      "GET", "/vulnerabilities/xss_r/",
     {"name": "<ScRiPt>alert(1)</ScRiPt>"}, 403),

    ("XSS svg",                 "GET", "/vulnerabilities/xss_r/",
     {"name": "<svg/onload=alert(1)>"}, 403),

    # ================================================================
    # MODELE GENERAL (LFI, CMDi, SSTI, XXE) — Master Model
    # ================================================================
    ("LFI traversal",           "GET", "/vulnerabilities/fi/",
     {"page": "../../../etc/passwd"}, 403),

    ("LFI double encoding",     "GET", "/vulnerabilities/fi/",
     {"page": "..%252f..%252fetc%252fpasswd"}, 403),

    ("LFI obfusqué",            "GET", "/vulnerabilities/fi/",
     {"page": "....//....//etc/passwd"}, 403),

    ("CMDi pipe",               "POST", "/vulnerabilities/exec/",
     {"ip": "127.0.0.1|whoami", "Submit": "Submit"}, 403),

    ("CMDi semicolon",          "POST", "/vulnerabilities/exec/",
     {"ip": "127.0.0.1;cat /etc/passwd", "Submit": "Submit"}, 403),

    ("CMDi obfusqué",           "POST", "/vulnerabilities/exec/",
     {"ip": "127.0.0.1|w'h'oami", "Submit": "Submit"}, 403),

    ("SSTI Jinja2",             "GET", "/vulnerabilities/xss_r/",
     {"name": "{{7*7}}"}, 403),

    ("SSTI dollar",             "GET", "/vulnerabilities/xss_r/",
     {"name": "${7*7}"}, 403),

    # ================================================================
    # ISOLATION FOREST (LOF) — Anomalies / Zero-day
    # ================================================================
    ("Anomalie entropie haute",  "GET", "/vulnerabilities/sqli/",
     {"id": "%53%45%4C%45%43%54%20%2A%20%46%52%4F%4D%20users"}, 403),

    ("Anomalie double encoding", "GET", "/vulnerabilities/fi/",
     {"page": "%25%32%65%25%32%65%25%32%66etc%25%32%66passwd"}, 403),


    # ================================================================
    # VRAIS NOUVEAUX PAYLOADS — jamais vus pendant l'entraînement
    # ================================================================
    ("SQLi unicode",        "GET", "/vulnerabilities/sqli/",
     {"id": "1\u0027 OR \u00271\u0027=\u00271", "Submit": "Submit"}, 403),

    ("SQLi hex encoding",   "GET", "/vulnerabilities/sqli/",
     {"id": "1' OR 0x313d31--", "Submit": "Submit"}, 403),

    ("SQLi concat MySQL",   "GET", "/vulnerabilities/sqli/",
     {"id": "1' OR 'una'='un'+'a", "Submit": "Submit"}, 403),

    ("SQLi information",    "GET", "/vulnerabilities/sqli/",
     {"id": "1;SELECT/**/SLEEP(0)/**/FROM/**/information_schema.tables--",
      "Submit": "Submit"}, 403),

    ("XSS entities",        "GET", "/vulnerabilities/xss_r/",
     {"name": "<img src=`x` onerror=`alert(1)`>"}, 403),

    ("XSS data URI",        "GET", "/vulnerabilities/xss_r/",
     {"name": "<a href=data:text/html,<script>alert(1)</script>>click</a>"}, 403),

    ("XSS fromCharCode",    "GET", "/vulnerabilities/xss_r/",
     {"name": "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>"}, 403),

    ("LFI null byte",       "GET", "/vulnerabilities/fi/",
     {"page": "../../../etc/passwd%00"}, 403),

    ("LFI windows",         "GET", "/vulnerabilities/fi/",
     {"page": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"}, 403),

    ("CMDi backtick",       "POST", "/vulnerabilities/exec/",
     {"ip": "127.0.0.1`id`", "Submit": "Submit"}, 403),

    ("CMDi substitution",   "POST", "/vulnerabilities/exec/",
     {"ip": "127.0.0.1$(cat /etc/passwd)", "Submit": "Submit"}, 403),

    ("SSTI Twig avancé",    "GET", "/vulnerabilities/xss_r/",
     {"name": "{{_self.env.registerUndefinedFilterCallback('id')}}{{_self.env.getFilter('x')}}"}, 403),

    ("SSTI Freemarker",     "GET", "/vulnerabilities/xss_r/",
     {"name": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"}, 403),

    ("Zero-day simulé 1",   "GET", "/vulnerabilities/sqli/",
     {"id": "' AND extractvalue(1,concat(0x7e,version()))--", "Submit": "Submit"}, 403),

    ("Zero-day simulé 2",   "GET", "/vulnerabilities/xss_r/",
     {"name": "<details/open/ontoggle=alert(1)>"}, 403),
     
    # ================================================================
    # REQUETES NORMALES — NE DOIVENT PAS ETRE BLOQUEES
    # ================================================================
    ("Normal id=1",             "GET", "/vulnerabilities/sqli/",
     {"id": "1", "Submit": "Submit"}, 200),

    ("Normal name=John",        "GET", "/vulnerabilities/xss_r/",
     {"name": "John"}, 200),

    ("Normal page",             "GET", "/vulnerabilities/fi/",
     {"page": "include.php"}, 200),

    ("Normal index",            "GET", "/index.php",
     {}, 200),

    ("Normal login page",       "GET", "/login.php",
     {}, 200),
]

# ================================================================
# EXECUTION
# ================================================================
print("=" * 65)
print("  WAF ML Engine — Test Report")
print("=" * 65)

passed = failed = 0
results = []

for name, method, path, params, expected in tests:
    try:
        if method == "GET":
            r = requests.get(
                f"{WAF}{path}",
                params=params,
                headers=HEADERS,
                timeout=5,
                allow_redirects=False
            )
        else:
            r = requests.post(
                f"{WAF}{path}",
                data=params,
                headers=HEADERS,
                timeout=5,
                allow_redirects=False
            )

        got = r.status_code
        ok  = (got == expected) or \
              (expected == 403 and got in [403, 429]) or \
              (expected == 200 and got in [200, 302])

        status = "✅ PASS" if ok else "❌ FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        results.append((status, name, expected, got))
        print(f"{status} | {name:30s} | expected={expected} got={got}")
        time.sleep(0.3)

    except Exception as e:
        failed += 1
        print(f"❌ ERR  | {name:30s} | {e}")

print("=" * 65)
print(f"\n  Résultat global : {passed}/{passed+failed} tests passés")
print(f"  Attaques bloquées  : {sum(1 for r in results if r[0]=='✅ PASS' and r[2]==403)}/{sum(1 for r in results if r[2]==403)}")
print(f"  Normales autorisées: {sum(1 for r in results if r[0]=='✅ PASS' and r[2]==200)}/{sum(1 for r in results if r[2]==200)}")
print("=" * 65)