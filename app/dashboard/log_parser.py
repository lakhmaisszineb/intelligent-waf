"""
WAF Log Parser — production-grade parser for logs/waf.log.

Four log formats are emitted by app/logger.py:

    BLOCKED (rule-based)
        <ts> - WARNING - BLOCKED | IP=… | METHOD=… | PATH=… |
        RAISON=<text> | Catégorie=<cat> | Payload=<payload>

    BLOCKED (ML model — zone 'attack' or 'grey_zone_attack')
        <ts> - WARNING - BLOCKED | IP=… | METHOD=… | PATH=… |
        RAISON=ML Attack Score: <score> | MODEL=<name> | ATTACK=<type> |
        PAYLOAD=<payload> | attack

    ALERT (grey zone / anomaly — zone 'grey_zone_normal' / 'anomaly_alert')
        <ts> - WARNING - ALERT | IP=… | METHOD=… | PATH=… |
        SCORE=<score-string> | MODEL=<name> | ZONE=<zone>

    ALLOWED (clean — zone 'normal')
        <ts> - INFO - ALLOWED | IP=… | METHOD=… | PATH=…

All public functions are safe to call when the log file does not yet exist.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_LOG_FILE = Path("logs/waf.log")
_TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"

# Captures timestamp and status word from the standard log prefix.
_RE_PREFIX = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+"   # timestamp (ms dropped)
    r" - \w+ - "                                        # log level
    r"(BLOCKED|ALERT|ALLOWED)"                          # status
)

# Extracts key=value pairs; values stop at the pipe separator.
# Handles accented keys such as Catégorie (À–ÿ range covers all Latin-1).
_RE_KV = re.compile(r"([A-Za-zÀ-ÿ_]+)=([^|]+)")

# Extracts the numeric part from strings like "ML Attack Score: 0.9862"
# or "Grey Zone Normal Score: 0.4285" or "Anomaly Score: 0.0057".
_RE_SCORE = re.compile(r"Score:\s*([\d.]+)")

# Map zone strings to human-readable source labels.
_ZONE_TO_SOURCE: dict[str, str] = {
    "attack": "ml",
    "grey_zone_attack": "ml",
    "grey_zone_normal": "ml",
    "anomaly_alert": "anomaly",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogEntry:
    """Immutable representation of one WAF log line."""

    # ── Core request fields ──────────────────────────────────────────────────
    timestamp: datetime
    ip: str
    method: str
    path: str

    # ── Decision fields ──────────────────────────────────────────────────────
    status: str       # "BLOCKED" | "ALERT" | "ALLOWED"
    reason: str       # RAISON text (rule) or SCORE string (anomaly)
    category: str     # attack category: Catégorie (rule) or ATTACK (ML)

    # ── ML / model fields ────────────────────────────────────────────────────
    model: str        # ML model name; empty for rule-based entries
    attack_type: str  # ATTACK field value; empty for rule/clean entries
    payload: str      # request snippet logged by the WAF (truncated to 100 ch)
    score: float      # confidence / anomaly score; 0.0 when not applicable
    master_score: Optional[float]
    lof_score: Optional[float]
    combined_score: Optional[float]
    expert_score: Optional[float]
    sqli_score: Optional[float]
    xss_score: Optional[float]
    hybrid_score: Optional[float]

    # ── Classification metadata ──────────────────────────────────────────────
    source: str       # "rule" | "ml" | "anomaly" | "clean"
    zone: str         # raw ZONE field or empty string

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict (timestamp converted to ISO string)."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class LogFilter:
    """Declarative filter consumed by :func:`get_entries`."""

    status: Optional[str] = None    # "BLOCKED" | "ALERT" | "ALLOWED"
    status_in: Optional[set[str]] = None  # e.g. {"BLOCKED", "ALERT"}
    ip: Optional[str] = None
    category: Optional[str] = None  # case-insensitive match
    source: Optional[str] = None    # "rule" | "ml" | "anomaly" | "clean"
    model: Optional[str] = None     # case-insensitive exact model name
    zone: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    offset: int = 0
    limit: Optional[int] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_kv(segment: str) -> dict[str, str]:
    """Return {key: value} pairs from a pipe-separated log segment."""
    return {k.strip(): v.strip() for k, v in _RE_KV.findall(segment)}


def _extract_score(text: str) -> float:
    """Parse numeric score from 'ML Attack Score: 0.98' style strings."""
    m = _RE_SCORE.search(text)
    return float(m.group(1)) if m else 0.0


def _parse_float(value: Optional[str]) -> Optional[float]:
    """Parse optional float value safely from log kv pairs."""
    if value is None:
        return None
    try:
        return float(value.strip())
    except (ValueError, AttributeError):
        return None


def _classify_source(kv: dict[str, str], raison: str) -> str:
    """
    Derive detection source from the key-value pairs of a log line.

    Priority order mirrors the detection pipeline in app/main.py:
    anomaly alerts → ML detections → rule engine → clean traffic.
    """
    zone = kv.get("ZONE", "")
    if zone in _ZONE_TO_SOURCE:
        return _ZONE_TO_SOURCE[zone]
    if "MODEL" in kv and "ATTACK" in kv:
        return "ml"
    if "Score" in raison:           # ML Attack Score / Grey Zone Score
        return "ml"
    if "Catégorie" in kv or "Categorie" in kv:
        return "rule"
    return "clean"


def _parse_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single log line into a LogEntry.

    Returns None for empty lines, comment lines, or lines that do not match
    any known format — allowing the caller to skip them silently.
    """
    line = line.rstrip()
    if not line:
        return None

    m = _RE_PREFIX.match(line)
    if not m:
        return None

    try:
        timestamp = datetime.strptime(m.group(1), _TIMESTAMP_FMT)
    except ValueError:
        return None

    status = m.group(2)
    kv = _parse_kv(line[m.end():])

    ip = kv.get("IP", "")
    method = kv.get("METHOD", "")
    path = kv.get("PATH", "")
    raison = kv.get("RAISON", "")
    model = kv.get("MODEL", "")
    attack_type = kv.get("ATTACK", "")
    zone = kv.get("ZONE", "")

    # Payload: rule-based entries use "Payload" (capitalised), ML uses "PAYLOAD"
    payload = kv.get("Payload") or kv.get("PAYLOAD") or ""

    # Category: rule engine writes Catégorie, ML pipeline uses ATTACK field
    category = (
        kv.get("Catégorie")
        or kv.get("Categorie")
        or kv.get("ATTACK")
        or ""
    )

    # Score: ML embeds it in RAISON ("ML Attack Score: X"),
    # anomaly/grey-zone entries use the SCORE key ("Anomaly Score: X")
    score_text = kv.get("SCORE") or raison
    score = _extract_score(score_text)
    master_score = _parse_float(kv.get("MASTER_SCORE"))
    lof_score = _parse_float(kv.get("LOF_SCORE"))
    combined_score = _parse_float(kv.get("COMBINED_SCORE"))
    expert_score = _parse_float(kv.get("EXPERT_SCORE"))
    sqli_score = _parse_float(kv.get("SQLI_SCORE"))
    xss_score = _parse_float(kv.get("XSS_SCORE"))
    hybrid_score = _parse_float(kv.get("HYBRID_SCORE"))

    # Human-readable reason: RAISON for detections, SCORE string for alerts
    reason = raison or kv.get("SCORE", "")

    source = _classify_source(kv, raison)

    return LogEntry(
        timestamp=timestamp,
        ip=ip,
        method=method,
        path=path,
        status=status,
        reason=reason,
        category=category,
        model=model,
        attack_type=attack_type,
        payload=payload,
        score=score,
        master_score=master_score,
        lof_score=lof_score,
        combined_score=combined_score,
        expert_score=expert_score,
        sqli_score=sqli_score,
        xss_score=xss_score,
        hybrid_score=hybrid_score,
        source=source,
        zone=zone,
    )


def _matches(entry: LogEntry, f: LogFilter) -> bool:
    if f.status and entry.status != f.status:
        return False
    if f.status_in and entry.status not in f.status_in:
        return False
    if f.ip and entry.ip != f.ip:
        return False
    if f.category and entry.category.lower() != f.category.lower():
        return False
    if f.source and entry.source != f.source:
        return False
    if f.model and entry.model.lower() != f.model.lower():
        return False
    if f.zone and entry.zone != f.zone:
        return False
    if f.since and entry.timestamp < f.since:
        return False
    if f.until and entry.timestamp > f.until:
        return False
    return True


def _top_n(counts: dict[str, int], n: int = 10) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def iter_entries(log_file: Path = _LOG_FILE) -> Iterator[LogEntry]:
    """
    Yield :class:`LogEntry` objects from the WAF log file, oldest entry first.

    Skips unrecognised lines silently. Safe when the file does not exist.
    """
    try:
        with open(log_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = _parse_line(line)
                if entry is not None:
                    yield entry
    except FileNotFoundError:
        return


def get_entries(
    filters: Optional[LogFilter] = None,
    log_file: Path = _LOG_FILE,
) -> list[LogEntry]:
    """
    Return a filtered, reverse-chronological list of :class:`LogEntry` objects.

    Parameters
    ----------
    filters:
        Optional :class:`LogFilter` to narrow by status, IP, category, source,
        zone, or time window.  Pagination is handled via ``offset`` / ``limit``
        on the filter object.
    log_file:
        Path to the WAF log file; defaults to ``logs/waf.log``.
    """
    results = [
        e for e in iter_entries(log_file)
        if filters is None or _matches(e, filters)
    ]
    results.sort(key=lambda e: e.timestamp, reverse=True)

    if filters:
        results = results[filters.offset :]
        if filters.limit is not None:
            results = results[: filters.limit]

    return results


def get_entries_as_dicts(
    filters: Optional[LogFilter] = None,
    log_file: Path = _LOG_FILE,
) -> list[dict]:
    """
    Convenience wrapper around :func:`get_entries`.

    Returns JSON-serialisable dicts instead of dataclass instances —
    suitable for direct use in FastAPI response bodies.
    """
    return [e.to_dict() for e in get_entries(filters, log_file)]


def get_stats(log_file: Path = _LOG_FILE) -> dict:
    """
    Compute aggregate counters for the dashboard overview widgets.

    Returns
    -------
    dict with keys:
        total, blocked, alerts, allowed,
        by_category  — {category: count} sorted by frequency (all categories),
        by_ip        — top-10 {ip: count},
        by_method    — {method: count},
        by_source    — {source: count},
        by_zone      — {zone: count},
        top_paths    — top-10 {path: count},
        latest_timestamp — ISO-8601 string of the most recent log entry, or None.
    """
    total = blocked = alerts = allowed = 0
    by_category: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    by_method: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_zone: dict[str, int] = {}
    top_paths: dict[str, int] = {}
    latest_ts: Optional[datetime] = None

    for entry in iter_entries(log_file):
        total += 1

        if entry.status == "BLOCKED":
            blocked += 1
        elif entry.status == "ALERT":
            alerts += 1
        elif entry.status == "ALLOWED":
            allowed += 1

        if entry.category:
            by_category[entry.category] = by_category.get(entry.category, 0) + 1
        if entry.ip:
            by_ip[entry.ip] = by_ip.get(entry.ip, 0) + 1
        if entry.method:
            by_method[entry.method] = by_method.get(entry.method, 0) + 1
        if entry.source:
            by_source[entry.source] = by_source.get(entry.source, 0) + 1
        if entry.zone:
            by_zone[entry.zone] = by_zone.get(entry.zone, 0) + 1
        if entry.path:
            top_paths[entry.path] = top_paths.get(entry.path, 0) + 1

        if latest_ts is None or entry.timestamp > latest_ts:
            latest_ts = entry.timestamp

    return {
        "total": total,
        "blocked": blocked,
        "alerts": alerts,
        "allowed": allowed,
        "by_category": _top_n(by_category, n=len(by_category)),  # all categories
        "by_ip": _top_n(by_ip),
        "by_method": by_method,
        "by_source": by_source,
        "by_zone": by_zone,
        "top_paths": _top_n(top_paths),
        "latest_timestamp": latest_ts.isoformat() if latest_ts else None,
    }


def get_timeline(
    interval: str = "hour",
    log_file: Path = _LOG_FILE,
) -> list[dict]:
    """
    Aggregate event counts into time buckets for time-series charts.

    Parameters
    ----------
    interval : "minute" | "hour" | "day"
        Time bucket granularity.

    Returns
    -------
    List of dicts, each with keys:
        bucket   — ISO-formatted bucket label (string),
        blocked  — count of BLOCKED entries,
        alerts   — count of ALERT entries,
        allowed  — count of ALLOWED entries.
    Sorted oldest-first, ready for direct use in Chart.js / ApexCharts datasets.
    """
    fmt_map = {
        "minute": "%Y-%m-%dT%H:%M",
        "hour":   "%Y-%m-%dT%H:00",
        "day":    "%Y-%m-%d",
    }
    fmt = fmt_map.get(interval, fmt_map["hour"])

    buckets: dict[str, dict] = {}

    for entry in iter_entries(log_file):
        key = entry.timestamp.strftime(fmt)
        if key not in buckets:
            buckets[key] = {"bucket": key, "blocked": 0, "alerts": 0, "allowed": 0}

        if entry.status == "BLOCKED":
            buckets[key]["blocked"] += 1
        elif entry.status == "ALERT":
            buckets[key]["alerts"] += 1
        elif entry.status == "ALLOWED":
            buckets[key]["allowed"] += 1

    return sorted(buckets.values(), key=lambda b: b["bucket"])
