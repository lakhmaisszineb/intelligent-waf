import argparse
import random
import string
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

import requests

try:
    from app.dashboard.log_parser import iter_entries
except Exception:
    iter_entries = None


WAF_DEFAULT = "http://localhost:8000"
LOG_DEFAULT = "logs/waf.log"

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
]


@dataclass
class Scenario:
    kind: str
    name: str
    method: str
    path: str
    params: Dict[str, str]


def _rand_token(rng: random.Random, n: int = 8) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(rng.choice(chars) for _ in range(n))


def _payload_sets() -> Dict[str, List[str]]:
    return {
        "sqli": [
            "1' OR '1'='1",
            "1 UNION SELECT 1,database()--",
            "1' AND SLEEP(2)--",
            "1') OR ('1'='1",
            "1'/**/OR/**/1=1--",
            "1' OR 0x313d31--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "1' OR 'una'='un'+'a",
            "1;SELECT/**/SLEEP(0)/**/FROM/**/information_schema.tables--",
            "1' OR IF(1=1,SLEEP(1),0)--",
            "1' OR JSON_EXTRACT('{\"a\":1}','$.a')=1--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)",
            "<svg/onload=alert(1)>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<details open ontoggle=alert(1)>",
            "<a href=data:text/html,<script>alert(1)</script>>click</a>",
            "<img src=`x` onerror=`alert(1)`>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        ],
        "lfi": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..%252f..%252fetc%252fpasswd",
            "....//....//etc/passwd",
            "../../../etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
            "zip://../../../../var/www/html/shell.zip%23shell.php",
        ],
        "cmdi": [
            "127.0.0.1|whoami",
            "127.0.0.1;cat /etc/passwd",
            "127.0.0.1`id`",
            "127.0.0.1$(cat /etc/passwd)",
            "127.0.0.1 && uname -a",
            "127.0.0.1 || ping -c 1 8.8.8.8",
            "127.0.0.1; sleep 1",
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "{{config.items()}}",
            "{{_self.env.registerUndefinedFilterCallback('id')}}{{_self.env.getFilter('x')}}",
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
        "anomaly": [
            "%53%45%4C%45%43%54%20%2A%20%46%52%4F%4D%20users",
            "%25%32%65%25%32%65%25%32%66etc%25%32%66passwd",
            "Q2F0IC9ldGMvcGFzc3dkIC0tLS0tLS0=",
            "//////.....//////.....%%%%%%",
            "0x4141414141414141414141414141",
            "<><><>{}{}[];';';""``~~",
        ],
        "mixed": [
            "1' OR '1'='1 <script>alert(1)</script>",
            "../../../etc/passwd;cat /etc/passwd",
            "{{7*7}} UNION SELECT 1,2,3--",
            "<img src=x onerror=alert(1)> AND SLEEP(1)--",
            "php://filter/convert.base64-encode/resource=index.php | whoami",
            "${7*7} ../../../../etc/passwd",
        ],
        "benign": [
            "John",
            "Alice",
            "normal_user",
            "product-123",
            "hello world",
            "invoice 2026 05",
            "status active",
            "view profile",
            "profile",
            "welcome page",
            "contact us",
            "search shoes",
        ],
    }


def _build_pools() -> Dict[str, List[Scenario]]:
    ps = _payload_sets()
    pools: Dict[str, List[Scenario]] = defaultdict(list)

    for p in ps["sqli"]:
        pools["sqli"].append(Scenario("sqli", "SQLi", "GET", "/vulnerabilities/sqli/", {"id": p, "Submit": "Submit"}))

    for p in ps["xss"]:
        pools["xss"].append(Scenario("xss", "XSS", "GET", "/vulnerabilities/xss_r/", {"name": p}))

    for p in ps["lfi"]:
        pools["lfi"].append(Scenario("lfi", "LFI", "GET", "/vulnerabilities/fi/", {"page": p}))

    for p in ps["cmdi"]:
        pools["cmdi"].append(Scenario("cmdi", "CMDi", "POST", "/vulnerabilities/exec/", {"ip": p, "Submit": "Submit"}))

    for p in ps["ssti"]:
        pools["ssti"].append(Scenario("ssti", "SSTI", "GET", "/vulnerabilities/xss_r/", {"name": p}))

    for p in ps["anomaly"]:
        pools["anomaly"].append(Scenario("anomaly", "Anomaly", "GET", "/vulnerabilities/sqli/", {"id": p, "Submit": "Submit"}))

    for p in ps["mixed"]:
        pools["mixed"].append(Scenario("mixed", "Mixed", "GET", "/vulnerabilities/xss_r/", {"name": p}))

    for p in ps["benign"]:
        pools["benign"].append(Scenario("benign", "Benign-XSS", "GET", "/vulnerabilities/xss_r/", {"name": p}))
        pools["benign"].append(Scenario("benign", "Benign-SQLi", "GET", "/vulnerabilities/sqli/", {"id": p, "Submit": "Submit"}))
    pools["benign"].append(Scenario("benign", "Benign-Products", "GET", "/products", {"q": "running shoes", "page": "1"}))
    pools["benign"].append(Scenario("benign", "Benign-Profile", "GET", "/profile", {"tab": "overview"}))
    pools["benign"].append(Scenario("benign", "Benign-Index", "GET", "/index.php", {}))
    pools["benign"].append(Scenario("benign", "Benign-Login", "GET", "/login.php", {}))

    return pools


def _append_tracking(params: Dict[str, str], run_id: str, idx: int, rng: random.Random) -> Dict[str, str]:
    out = dict(params)
    out["rid"] = run_id
    out["seq"] = str(idx)
    out["nonce"] = _rand_token(rng, 6)
    return out


def _status_bucket(code: int) -> str:
    if code in (403, 429):
        return "blocked"
    if code in (200, 302):
        return "allowed"
    return f"other:{code}"


def _extract_new_log_stats(start_dt: datetime, log_path: str):
    if iter_entries is None:
        return None

    entries = []
    floor = start_dt - timedelta(seconds=1)
    for e in iter_entries(log_file=log_path):
        if e.timestamp >= floor:
            entries.append(e)

    by_status = Counter(e.status for e in entries)
    by_source = Counter(e.source for e in entries)
    by_model = Counter(e.model for e in entries if e.model)
    by_zone = Counter(e.zone for e in entries if e.zone)
    return entries, by_status, by_source, by_model, by_zone


def run(args):
    rng = random.Random(args.seed)
    run_id = datetime.now().strftime("run%Y%m%d_%H%M%S")
    start_dt = datetime.now()
    benign_ratio = max(0.0, min(1.0, args.benign_ratio))

    pools = _build_pools()
    attack_kinds = ["sqli", "xss", "lfi", "cmdi", "ssti", "mixed", "anomaly"]

    session = requests.Session()
    default_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
    }
    if args.cookie:
        default_headers["Cookie"] = args.cookie

    sent = 0
    errors = 0
    by_kind_http = defaultdict(Counter)

    print("=" * 78)
    print("WAF Deep ML Test Harness")
    print(f"Target={args.waf} | run_id={run_id} | total_requests={args.requests}")
    print(f"Traffic mix target: benign={benign_ratio*100:.0f}% | attack={(1.0-benign_ratio)*100:.0f}%")
    print("Goal: exercise rule engine + master + experts + LOF + mixed payloads")
    print("=" * 78)

    for i in range(1, args.requests + 1):
        # Warmup phase: guarantee at least one request for each attack family.
        if i <= len(attack_kinds):
            kind = attack_kinds[i - 1]
        else:
            kind = "benign" if rng.random() < benign_ratio else rng.choice(attack_kinds)
        sc = rng.choice(pools[kind])
        params = _append_tracking(sc.params, run_id, i, rng)

        headers = dict(default_headers)
        headers["User-Agent"] = rng.choice(UA_POOL)

        try:
            if sc.method == "GET":
                r = session.get(f"{args.waf}{sc.path}", params=params, headers=headers, timeout=args.timeout, allow_redirects=False)
            else:
                r = session.post(f"{args.waf}{sc.path}", data=params, headers=headers, timeout=args.timeout, allow_redirects=False)

            bucket = _status_bucket(r.status_code)
            by_kind_http[kind][bucket] += 1
            sent += 1

            if args.verbose:
                print(f"[{i:03d}] {kind:8s} {sc.method:4s} {sc.path:28s} -> {r.status_code}")

        except Exception as ex:
            errors += 1
            by_kind_http[kind]["error"] += 1
            print(f"[{i:03d}] {kind:8s} ERROR: {ex}")

        time.sleep(args.delay)

        if args.cooldown_every > 0 and i % args.cooldown_every == 0 and i < args.requests:
            print(f"-- cooldown {args.cooldown_seconds}s to avoid rate-limit noise --")
            time.sleep(args.cooldown_seconds)

    print("\n" + "=" * 78)
    print(f"HTTP Summary | sent={sent} | errors={errors}")
    for kind in sorted(by_kind_http):
        c = by_kind_http[kind]
        print(
            f"{kind:8s} "
            f"blocked={c.get('blocked',0):3d} "
            f"allowed={c.get('allowed',0):3d} "
            f"other={sum(v for k,v in c.items() if k.startswith('other:')):3d} "
            f"err={c.get('error',0):2d}"
        )

    if iter_entries is None:
        print("\n[INFO] app.dashboard.log_parser non disponible: analyse logs detaillee skippee.")
        return

    stats = _extract_new_log_stats(start_dt, args.log_file)
    if not stats:
        print("\n[WARN] Aucun log analyse.")
        return

    entries, by_status, by_source, by_model, by_zone = stats

    print("\n" + "=" * 78)
    print(f"Log Summary (new entries since {start_dt.strftime('%H:%M:%S')}) | count={len(entries)}")

    print("- By status:")
    for k, v in sorted(by_status.items()):
        print(f"  {k:10s}: {v}")

    print("- By source:")
    for k, v in sorted(by_source.items()):
        print(f"  {k:10s}: {v}")

    print("- By model:")
    if by_model:
        for k, v in sorted(by_model.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {k:16s}: {v}")
    else:
        print("  (none)")

    print("- By zone:")
    if by_zone:
        for k, v in sorted(by_zone.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {k:20s}: {v}")
    else:
        print("  (none)")

    required_models = {"SQLi_Expert", "XSS_Expert", "Master_Model"}
    seen_models = set(by_model.keys())
    missing = sorted(required_models - seen_models)
    lof_seen = any(getattr(e, "lof_score", None) is not None for e in entries)
    print("\nCoverage check:")
    if missing:
        print("  Missing models in logs:", ", ".join(missing))
    else:
        print("  All target models observed in logs.")
    print(f"  LOF score observed in logs: {'yes' if lof_seen else 'no'}")

    print("=" * 78)


def parse_args():
    p = argparse.ArgumentParser(description="High-volume WAF test harness for full ML/rule coverage")
    p.add_argument("--waf", default=WAF_DEFAULT, help="WAF base URL")
    p.add_argument("--cookie", default="", help="Optional Cookie header (ex: PHPSESSID=...; security=low)")
    p.add_argument("--requests", type=int, default=150, help="Total requests to send")
    p.add_argument("--delay", type=float, default=0.70, help="Delay between requests (seconds)")
    p.add_argument("--timeout", type=float, default=6.0, help="HTTP timeout")
    p.add_argument("--seed", type=int, default=42, help="Random seed")
    p.add_argument("--benign-ratio", type=float, default=0.45, help="Share of benign requests in [0..1]")
    p.add_argument("--cooldown-every", type=int, default=80, help="Pause every N requests (0=disable)")
    p.add_argument("--cooldown-seconds", type=float, default=8.0, help="Pause duration")
    p.add_argument("--log-file", default=LOG_DEFAULT, help="WAF log file path")
    p.add_argument("--verbose", action="store_true", help="Print each request result")
    return p.parse_args()


if __name__ == "__main__":
    run(parse_args())
