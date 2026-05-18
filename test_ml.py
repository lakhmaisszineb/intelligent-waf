import argparse
import random
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import requests

try:
    from app.dashboard.log_parser import iter_entries
except Exception:
    iter_entries = None


WAF_DEFAULT = "http://localhost:8000"
LOG_DEFAULT = "logs/waf.log"

NORMAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) Safari/605.1.15",
]


@dataclass(frozen=True)
class Scenario:
    label: str
    kind: str
    malicious: bool
    method: str
    path: str
    params: dict[str, str] = field(default_factory=dict)
    data: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    expected_engine: str = "any"  # rule | ml | any | none
    note: str = ""


@dataclass
class Result:
    idx: int
    scenario: Scenario
    http_status: Optional[int]
    error: str = ""
    log_entry: object = None


def _payload_preview(sc: Scenario, max_len: int = 90) -> str:
    parts = []
    for key, value in {**sc.params, **sc.data}.items():
        parts.append(f"{key}={value}")
    if "User-Agent" in sc.headers:
        parts.append(f"UA={sc.headers['User-Agent']}")
    text = "&".join(parts) if parts else "-"
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def _cycle_pick(items: list[Scenario], count: int, rng: random.Random) -> list[Scenario]:
    if count <= 0:
        return []
    shuffled = list(items)
    rng.shuffle(shuffled)
    out = []
    while len(out) < count:
        out.extend(shuffled)
    return out[:count]


def normal_scenarios() -> list[Scenario]:
    values = [
        ("Normal search John", "/search", {"q": "John"}),
        ("Normal search product", "/search", {"q": "product-123"}),
        ("Normal search invoice", "/search", {"q": "invoice 2026 05"}),
        ("Normal help", "/help", {"topic": "contact us"}),
        ("Normal profile Alice", "/profile", {"tab": "overview", "name": "Alice"}),
        ("Normal profile status", "/profile", {"tab": "settings", "name": "status active"}),
        ("Normal products", "/products", {"q": "running shoes", "page": "1"}),
        ("Normal index", "/index.php", {}),
        ("Normal login", "/login.php", {}),
        ("Normal DVWA SQLi page", "/vulnerabilities/sqli/", {}),
        ("Normal DVWA XSS page", "/vulnerabilities/xss_r/", {"name": "John"}),
        ("Normal DVWA file include", "/vulnerabilities/fi/", {"page": "include.php"}),
        ("Normal DVWA command page", "/vulnerabilities/exec/", {}),
    ]
    return [
        Scenario(label, "normal", False, "GET", path, params=params, expected_engine="none")
        for label, path, params in values
    ]


def attack_scenario_groups() -> dict[str, list[Scenario]]:
    return {
        "sqli": [
            Scenario("SQLi classic tautology", "sqli", True, "GET", "/vulnerabilities/sqli/", {"id": "1' OR '1'='1", "Submit": "Submit"}, expected_engine="rule"),
            Scenario("SQLi union select", "sqli", True, "GET", "/vulnerabilities/sqli/", {"id": "1 UNION SELECT 1,database()--", "Submit": "Submit"}, expected_engine="rule"),
            Scenario("SQLi time based", "sqli", True, "GET", "/vulnerabilities/sqli/", {"id": "1' AND SLEEP(2)--", "Submit": "Submit"}, expected_engine="rule"),
            Scenario("SQLi hex evasion", "sqli", True, "GET", "/vulnerabilities/sqli/", {"id": "1' OR 0x313d31--", "Submit": "Submit"}, expected_engine="rule"),
            Scenario("SQLi encoded ML", "sqli", True, "GET", "/vulnerabilities/sqli/", {"id": "%53%45%4C%45%43%54%20%2A%20%46%52%4F%4D%20users", "Submit": "Submit"}, expected_engine="ml"),
        ],
        "xss": [
            Scenario("XSS script tag", "xss", True, "GET", "/vulnerabilities/xss_r/", {"name": "<script>alert(1)</script>"}, expected_engine="rule"),
            Scenario("XSS image onerror", "xss", True, "GET", "/vulnerabilities/xss_r/", {"name": "<img src=x onerror=alert(1)>"}, expected_engine="rule"),
            Scenario("XSS mixed case", "xss", True, "GET", "/vulnerabilities/xss_r/", {"name": "<ScRiPt>alert(1)</ScRiPt>"}, expected_engine="rule"),
            Scenario("XSS details ontoggle ML", "xss", True, "GET", "/vulnerabilities/xss_r/", {"name": "<details open ontoggle=alert(1)>"}, expected_engine="ml"),
            Scenario("XSS svg onload ML", "xss", True, "GET", "/vulnerabilities/xss_r/", {"name": "<svg/onload=alert(1)>"}, expected_engine="ml"),
        ],
        "lfi": [
            Scenario("LFI unix passwd", "lfi", True, "GET", "/vulnerabilities/fi/", {"page": "../../../etc/passwd"}, expected_engine="rule"),
            Scenario("LFI windows hosts", "lfi", True, "GET", "/vulnerabilities/fi/", {"page": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"}, expected_engine="rule"),
            Scenario("LFI double encoded", "lfi", True, "GET", "/vulnerabilities/fi/", {"page": "..%252f..%252fetc%252fpasswd"}, expected_engine="rule"),
            Scenario("LFI null byte", "lfi", True, "GET", "/vulnerabilities/fi/", {"page": "../../../etc/passwd%00"}, expected_engine="rule"),
        ],
        "php": [
            Scenario("PHP filter wrapper", "php", True, "GET", "/vulnerabilities/fi/", {"page": "php://filter/convert.base64-encode/resource=index.php"}, expected_engine="rule"),
            Scenario("PHP zip wrapper", "php", True, "GET", "/vulnerabilities/fi/", {"page": "zip://../../../../var/www/html/shell.zip%23shell.php"}, expected_engine="rule"),
        ],
        "cmdi": [
            Scenario("CMDi pipe whoami", "cmdi", True, "POST", "/vulnerabilities/exec/", data={"ip": "127.0.0.1|whoami", "Submit": "Submit"}, expected_engine="ml"),
            Scenario("CMDi semicolon cat", "cmdi", True, "POST", "/vulnerabilities/exec/", data={"ip": "127.0.0.1;cat /etc/passwd", "Submit": "Submit"}, expected_engine="ml"),
            Scenario("CMDi backticks", "cmdi", True, "POST", "/vulnerabilities/exec/", data={"ip": "127.0.0.1`id`", "Submit": "Submit"}, expected_engine="ml"),
            Scenario("CMDi logical OR ping", "cmdi", True, "POST", "/vulnerabilities/exec/", data={"ip": "127.0.0.1 || ping -c 1 8.8.8.8", "Submit": "Submit"}, expected_engine="ml"),
        ],
        "ssti": [
            Scenario("SSTI jinja math", "ssti", True, "GET", "/vulnerabilities/xss_r/", {"name": "{{7*7}}"}, expected_engine="rule"),
            Scenario("SSTI config items", "ssti", True, "GET", "/vulnerabilities/xss_r/", {"name": "{{config.items()}}"}, expected_engine="rule"),
            Scenario("SSTI java runtime", "ssti", True, "GET", "/vulnerabilities/xss_r/", {"name": "${T(java.lang.Runtime).getRuntime().exec('id')}"}, expected_engine="rule"),
        ],
        "anomaly": [
            Scenario("Anomaly base64 command", "anomaly", True, "GET", "/vulnerabilities/sqli/", {"id": "Q2F0IC9ldGMvcGFzc3dkIC0tLS0tLS0=", "Submit": "Submit"}, expected_engine="ml"),
            Scenario("Anomaly hex blob", "anomaly", True, "GET", "/vulnerabilities/sqli/", {"id": "0x4141414141414141414141414141", "Submit": "Submit"}, expected_engine="rule"),
            Scenario("Anomaly symbols", "anomaly", True, "GET", "/vulnerabilities/sqli/", {"id": "//////.....//////.....%%%%%%", "Submit": "Submit"}, expected_engine="rule"),
        ],
        "mixed": [
            Scenario("Mixed SQLi XSS", "mixed", True, "GET", "/vulnerabilities/xss_r/", {"name": "1' OR '1'='1 <script>alert(1)</script>"}, expected_engine="rule"),
            Scenario("Mixed LFI CMDi", "mixed", True, "GET", "/vulnerabilities/xss_r/", {"name": "../../../etc/passwd;cat /etc/passwd"}, expected_engine="rule"),
            Scenario("Mixed XSS SQLi ML", "mixed", True, "GET", "/vulnerabilities/xss_r/", {"name": "<img src=x onerror=alert(1)> AND SLEEP(1)--"}, expected_engine="rule"),
        ],
        "scanner": [
            Scenario("Scanner sqlmap UA", "scanner", True, "GET", "/index.php", headers={"User-Agent": "sqlmap/1.7.2"}, expected_engine="rule"),
            Scenario("Scanner curl UA", "scanner", True, "GET", "/index.php", headers={"User-Agent": "curl/8.0"}, expected_engine="rule"),
        ],
        "method": [
            Scenario("Forbidden TRACE", "method", True, "TRACE", "/index.php", expected_engine="rule"),
            Scenario("Forbidden CONNECT", "method", True, "CONNECT", "/index.php", expected_engine="rule"),
        ],
    }


def build_plan(args) -> list[Scenario]:
    rng = random.Random(args.seed)
    plan = _cycle_pick(normal_scenarios(), args.normal_count, rng)

    groups = attack_scenario_groups()
    for family, scenarios in groups.items():
        count = args.attacks_per_family
        if family in {"scanner", "method", "php"}:
            count = min(count, len(scenarios))
        plan.extend(_cycle_pick(scenarios, count, rng))

    if args.shuffle:
        rng.shuffle(plan)
    return plan


def read_entries(log_file: str) -> list:
    if iter_entries is None:
        return []
    return list(iter_entries(log_file=log_file))


def wait_for_next_entry(log_file: str, seen_count: int, timeout: float):
    deadline = time.time() + timeout
    while time.time() < deadline:
        entries = read_entries(log_file)
        if len(entries) > seen_count:
            return entries[seen_count], len(entries)
        time.sleep(0.05)
    return None, seen_count


def split_models(model: str) -> list[str]:
    names = []
    for chunk in (model or "").replace("+", ",").replace(";", ",").split(","):
        chunk = chunk.strip()
        if chunk:
            names.append(chunk)
    return names


def waf_decision(entry, http_status: Optional[int]) -> str:
    if entry is not None:
        return entry.status
    if http_status in (403, 429):
        return "BLOCKED"
    if http_status is None:
        return "ERROR"
    return "ALLOWED"


def is_bad_result(sc: Scenario, entry, http_status: Optional[int]) -> tuple[bool, str]:
    decision = waf_decision(entry, http_status)
    if not sc.malicious and decision in {"BLOCKED", "ALERT"}:
        return True, "FALSE_POSITIVE"
    if sc.malicious and decision == "ALLOWED":
        return True, "FALSE_NEGATIVE"
    if sc.malicious and decision == "ALERT":
        return True, "ATTACK_ALERT_NOT_BLOCKED"
    return False, ""


def send_one(session: requests.Session, args, sc: Scenario, idx: int, total: int, rng: random.Random) -> tuple[Optional[int], str]:
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "User-Agent": rng.choice(NORMAL_UA),
        "X-Test-Seq": str(idx),
    }
    headers.update(sc.headers)
    if args.cookie:
        headers["Cookie"] = args.cookie

    url = f"{args.waf}{sc.path}"
    try:
        response = session.request(
            sc.method,
            url,
            params=sc.params if sc.method.upper() == "GET" else None,
            data=sc.data if sc.method.upper() != "GET" else None,
            headers=headers,
            timeout=args.timeout,
            allow_redirects=False,
        )
        return response.status_code, ""
    except Exception as exc:
        return None, str(exc)


def print_sent_line(result: Result) -> None:
    sc = result.scenario
    entry = result.log_entry
    decision = waf_decision(entry, result.http_status)
    expected = "ATTACK" if sc.malicious else "NORMAL"
    source = getattr(entry, "source", "-") if entry is not None else "-"
    model = getattr(entry, "model", "-") if entry is not None else "-"
    category = getattr(entry, "category", "-") if entry is not None else "-"
    zone = getattr(entry, "zone", "-") if entry is not None else "-"
    bad, bad_type = is_bad_result(sc, entry, result.http_status)
    mark = "REVIEW" if bad else "OK"

    print(
        f"[{result.idx:03d}] {expected:6s} {sc.kind:8s} "
        f"{sc.method:7s} {sc.path:28s} HTTP={str(result.http_status or 'ERR'):>3s} "
        f"WAF={decision:7s} src={source:5s} model={model or '-':22s} "
        f"cat={category or '-':18s} zone={zone or '-':18s} {mark}"
    )
    print(f"      payload: {_payload_preview(sc)}")
    if result.error:
        print(f"      error: {result.error}")
    if bad:
        print(f"      issue: {bad_type}")


def summarize(results: list[Result], start_dt: datetime) -> None:
    by_expected = Counter("attack" if r.scenario.malicious else "normal" for r in results)
    by_kind = defaultdict(Counter)
    by_status = Counter()
    by_source = Counter()
    by_model = Counter()
    by_category = Counter()
    issues = defaultdict(list)

    for result in results:
        sc = result.scenario
        entry = result.log_entry
        status = waf_decision(entry, result.http_status)
        by_kind[sc.kind][status] += 1
        by_status[status] += 1
        if entry is not None:
            by_source[getattr(entry, "source", "") or "unknown"] += 1
            by_category[getattr(entry, "category", "") or "-"] += 1
            for model in split_models(getattr(entry, "model", "")):
                by_model[model] += 1
        bad, bad_type = is_bad_result(sc, entry, result.http_status)
        if bad:
            issues[bad_type].append(result)

    print("\n" + "=" * 100)
    print(f"Test summary | started={start_dt.strftime('%Y-%m-%d %H:%M:%S')} | total={len(results)}")
    print(f"Expected traffic: normal={by_expected['normal']} attack={by_expected['attack']}")

    print("\nBy WAF status:")
    for key, value in sorted(by_status.items()):
        print(f"  {key:10s}: {value}")

    print("\nBy attack/traffic kind:")
    for kind in sorted(by_kind):
        c = by_kind[kind]
        print(
            f"  {kind:8s} blocked={c.get('BLOCKED', 0):3d} "
            f"alert={c.get('ALERT', 0):3d} allowed={c.get('ALLOWED', 0):3d} "
            f"error={c.get('ERROR', 0):2d}"
        )

    print("\nBy source:")
    for key, value in sorted(by_source.items()):
        print(f"  {key:10s}: {value}")

    print("\nBy model:")
    if by_model:
        for key, value in sorted(by_model.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {key:16s}: {value}")
    else:
        print("  (none)")

    print("\nBy category:")
    for key, value in sorted(by_category.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {key:18s}: {value}")

    required_sources = {"rule", "ml"}
    required_models = {"Master_Model", "LOF", "SQLi_Expert", "XSS_Expert"}
    missing_sources = sorted(required_sources - set(by_source))
    missing_models = sorted(required_models - set(by_model))

    print("\nCoverage check:")
    print(f"  Rule Engine observed: {'yes' if 'rule' in by_source else 'no'}")
    print(f"  ML Engine observed:   {'yes' if 'ml' in by_source else 'no'}")
    print(f"  Missing sources:      {', '.join(missing_sources) if missing_sources else 'none'}")
    print(f"  Missing ML models:    {', '.join(missing_models) if missing_models else 'none'}")

    print("\nIssues to review:")
    if not issues:
        print("  No false positives or false negatives observed in this run.")
    else:
        for issue_type in ("FALSE_POSITIVE", "FALSE_NEGATIVE", "ATTACK_ALERT_NOT_BLOCKED"):
            rows = issues.get(issue_type, [])
            print(f"  {issue_type}: {len(rows)}")
            for result in rows:
                sc = result.scenario
                entry = result.log_entry
                decision = waf_decision(entry, result.http_status)
                source = getattr(entry, "source", "-") if entry is not None else "-"
                model = getattr(entry, "model", "-") if entry is not None else "-"
                category = getattr(entry, "category", "-") if entry is not None else "-"
                print(
                    f"    #{result.idx:03d} {sc.kind:8s} {sc.label} | "
                    f"WAF={decision} source={source} model={model or '-'} category={category or '-'}"
                )
                print(f"        payload: {_payload_preview(sc, 140)}")
    print("=" * 100)


def run(args) -> None:
    rng = random.Random(args.seed)
    plan = build_plan(args)
    start_dt = datetime.now()
    session = requests.Session()

    if iter_entries is None:
        print("[WARN] app.dashboard.log_parser is not available; log-level analysis will be limited.")
        seen_count = 0
    else:
        seen_count = len(read_entries(args.log_file))

    print("=" * 100)
    print("ProxiQ WAF realistic test")
    print(f"Target: {args.waf}")
    print(f"Plan: total={len(plan)} normal={sum(not s.malicious for s in plan)} attack={sum(s.malicious for s in plan)}")
    print("Each request is printed with expected type, HTTP status, WAF decision, source, model and category.")
    print("=" * 100)

    results: list[Result] = []
    for idx, scenario in enumerate(plan, start=1):
        http_status, error = send_one(session, args, scenario, idx, len(plan), rng)
        entry = None
        if iter_entries is not None:
            entry, seen_count = wait_for_next_entry(args.log_file, seen_count, args.log_wait)
        result = Result(idx, scenario, http_status, error, entry)
        results.append(result)
        print_sent_line(result)
        time.sleep(args.delay)

        if args.cooldown_every > 0 and idx % args.cooldown_every == 0 and idx < len(plan):
            print(f"-- cooldown {args.cooldown_seconds:.1f}s to avoid rate-limit noise --")
            time.sleep(args.cooldown_seconds)

    summarize(results, start_dt)


def parse_args():
    parser = argparse.ArgumentParser(description="Realistic WAF test with FP/FN reporting and engine/model coverage.")
    parser.add_argument("--waf", default=WAF_DEFAULT, help="WAF base URL, for example http://localhost:8000")
    parser.add_argument("--cookie", default="", help="Optional Cookie header, for example PHPSESSID=...; security=low")
    parser.add_argument("--log-file", default=LOG_DEFAULT, help="Path to logs/waf.log")
    parser.add_argument("--normal-count", type=int, default=24, help="Number of normal requests to include")
    parser.add_argument("--attacks-per-family", type=int, default=4, help="Number of attacks to include per attack family")
    parser.add_argument("--delay", type=float, default=0.35, help="Delay between requests in seconds")
    parser.add_argument("--timeout", type=float, default=6.0, help="HTTP timeout in seconds")
    parser.add_argument("--log-wait", type=float, default=2.0, help="Max seconds to wait for one WAF log entry after each request")
    parser.add_argument("--cooldown-every", type=int, default=80, help="Pause every N requests to reduce rate-limit noise; 0 disables")
    parser.add_argument("--cooldown-seconds", type=float, default=8.0, help="Cooldown duration in seconds")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--shuffle", action="store_true", help="Shuffle the final scenario plan")
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
