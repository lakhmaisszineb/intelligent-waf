"""
Dashboard routes for the WAF monitoring interface.

Two routers are exported and combined into the top-level `router`:

    html_router  — serves the dashboard HTML page at GET /dashboard
    api_router   — JSON endpoints under /api/dashboard/*
                   All responses carry Cache-Control: no-cache headers via
                   the custom _NoCacheRoute class.

Import and mounting in app/main.py:

    from app.dashboard.routes import router as dashboard_router
    waf.include_router(dashboard_router)
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator

from app.dashboard.log_parser import (
    LogFilter,
    get_entries_as_dicts,
    get_stats,
    get_timeline,
    iter_entries,
)


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


# ---------------------------------------------------------------------------
# No-cache route class — injects Cache-Control on every API response
# ---------------------------------------------------------------------------

class _NoCacheRoute(APIRoute):
    """Wraps every route handler to append no-cache headers to the response."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def _handler(request: Request) -> Response:
            response = await original(request)
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response

        return _handler


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

# HTML pages — default caching behaviour is fine for static markup
html_router = APIRouter(tags=["dashboard"])

# REST API — all routes automatically get no-cache headers
api_router = APIRouter(
    prefix="/api/dashboard",
    tags=["dashboard-api"],
    route_class=_NoCacheRoute,
)


# ---------------------------------------------------------------------------
# Reputation engine — lazy import to break the circular dependency with main
# ---------------------------------------------------------------------------

def get_reputation_engine():
    """
    Return the shared IPReputationEngine instance from app.main.

    The import is intentionally deferred to request-time so that this module
    can be imported by main.py without creating a circular dependency.
    """
    from app.main import reputation_engine  # noqa: PLC0415
    return reputation_engine


# ---------------------------------------------------------------------------
# Pydantic request bodies
# ---------------------------------------------------------------------------

class IPRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v


# ---------------------------------------------------------------------------
# Internal data-transform helpers
# ---------------------------------------------------------------------------

# ML models report category as "SQLi" / "XSS"; rule engine uses "sql_injection"
# / "xss".  This map normalises them to a single canonical key.
_CATEGORY_ALIASES: dict[str, str] = {
    "SQLi": "sql_injection",
    "XSS":  "xss",
}


def _normalise_category(cat: str) -> str:
    return _CATEGORY_ALIASES.get(cat, cat)


def _build_attacks_by_type(raw_counts: dict[str, int]) -> dict[str, int]:
    """
    Merge aliased category names and return a frequency-sorted dict.

    'SQLi' and 'sql_injection' are combined under 'sql_injection'; similarly
    'XSS' and 'xss' are combined under 'xss'.
    """
    merged: dict[str, int] = {}
    for cat, count in raw_counts.items():
        key = _normalise_category(cat)
        merged[key] = merged.get(key, 0) + count
    return dict(sorted(merged.items(), key=lambda x: x[1], reverse=True))


def _build_models_stats() -> dict[str, dict]:
    """
    Compute per-model detection statistics by scanning log entries once.

    Returns
    -------
    {
        "SQLi_Expert":   {"detections": 9, "avg_score": 0.95},
        "Master_Model":  {"detections": 4, "avg_score": 0.91},
        "LOF":           {"detections": 0, "avg_score": 0.03, "alerts": 2},
    }
    """
    accum: dict[str, dict] = {}

    for entry in iter_entries():
        if not entry.model:
            continue

        name = entry.model
        if name not in accum:
            accum[name] = {"detections": 0, "total_score": 0.0, "alerts": 0}

        if entry.status == "BLOCKED":
            accum[name]["detections"] += 1
            accum[name]["total_score"] += entry.score
        elif entry.status == "ALERT":
            accum[name]["alerts"] += 1
            accum[name]["total_score"] += entry.score

    result: dict[str, dict] = {}
    for name, data in accum.items():
        total_events = data["detections"] + data["alerts"]
        avg_score = data["total_score"] / total_events if total_events else 0.0
        out: dict = {
            "detections": data["detections"],
            "avg_score":  round(avg_score, 4),
        }
        if data["alerts"]:
            out["alerts"] = data["alerts"]
        result[name] = out

    return result


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------

@html_router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Serve the WAF monitoring dashboard."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


# ---------------------------------------------------------------------------
# GET /api/dashboard/stats
# ---------------------------------------------------------------------------

@api_router.get("/stats")
async def dashboard_stats():
    """
    Aggregate KPI counters for the overview panel.

    Extra fields beyond the raw parser output:
      blocked_by_rules        — detections from the rule engine
      blocked_by_ml           — detections from ML models
      false_positives_estimate — grey-zone requests that were *allowed*
                                 (zone = grey_zone_normal)
    """
    raw = get_stats()
    by_source: dict[str, int] = raw.get("by_source", {})
    by_zone:   dict[str, int] = raw.get("by_zone", {})

    return {
        "total":                    raw["total"],
        "blocked":                  raw["blocked"],
        "alerts":                   raw["alerts"],
        "allowed":                  raw["allowed"],
        "blocked_by_rules":         by_source.get("rule", 0),
        "blocked_by_ml":            by_source.get("ml", 0),
        "false_positives_estimate": by_zone.get("grey_zone_normal", 0),
        "latest_timestamp":         raw["latest_timestamp"],
    }


# ---------------------------------------------------------------------------
# GET /api/dashboard/logs
# ---------------------------------------------------------------------------

@api_router.get("/logs")
async def dashboard_logs(
    page: int = 1,
    limit: int = 50,
    log_status: Optional[str] = None,   # query param "log_status" avoids
    category: Optional[str] = None,     # shadowing fastapi.status in scope
    source: Optional[str] = None,
    ip: Optional[str] = None,
):
    """
    Paginated, filterable log feed — newest entries first.

    Query parameters
    ----------------
    page       : 1-based page number (default 1)
    limit      : entries per page, capped at 200 (default 50)
    log_status : filter by BLOCKED | ALERT | ALLOWED
    category   : filter by attack category, e.g. sql_injection, xss
    source     : filter by detection source: rule | ml | anomaly | clean
    ip         : filter by client IP address
    """
    limit = min(max(limit, 1), 200)
    offset = (page - 1) * limit

    filters = LogFilter(
        status=log_status.upper() if log_status else None,
        category=category,
        source=source,
        ip=ip,
        offset=offset,
        limit=limit,
    )
    entries = get_entries_as_dicts(filters)

    return {
        "page":    page,
        "limit":   limit,
        "count":   len(entries),
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# GET /api/dashboard/attacks-by-type
# ---------------------------------------------------------------------------

@api_router.get("/attacks-by-type")
async def attacks_by_type():
    """
    Frequency distribution of attack categories, sorted descending.

    ML-reported names ('SQLi', 'XSS') are merged with rule-engine names
    ('sql_injection', 'xss') under canonical keys.
    """
    raw = get_stats()
    return _build_attacks_by_type(raw.get("by_category", {}))


# ---------------------------------------------------------------------------
# GET /api/dashboard/timeline
# ---------------------------------------------------------------------------

@api_router.get("/timeline")
async def timeline(interval: str = "hour"):
    """
    Time-series event counts bucketed by the given interval.

    Parameters
    ----------
    interval : "minute" | "hour" | "day"  (default: "hour")

    Returns a list of {bucket, blocked, alerts, allowed} sorted oldest-first,
    ready for direct ingestion by Chart.js or ApexCharts.
    """
    if interval not in ("minute", "hour", "day"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="interval must be 'minute', 'hour', or 'day'",
        )
    return get_timeline(interval)


# ---------------------------------------------------------------------------
# GET /api/dashboard/top-ips
# ---------------------------------------------------------------------------

@api_router.get("/top-ips")
async def top_ips():
    """Top-10 source IPs ranked by total blocked/alert event count."""
    raw = get_stats()
    return raw.get("by_ip", {})


# ---------------------------------------------------------------------------
# GET /api/dashboard/models-stats
# ---------------------------------------------------------------------------

@api_router.get("/models-stats")
async def models_stats():
    """
    Per-model ML detection statistics derived from the log file.

    Each entry reports detection count and average confidence score.
    Anomaly models (e.g. LOF) that emit only ALERTs also include an
    'alerts' key.
    """
    return _build_models_stats()


# ---------------------------------------------------------------------------
# POST /api/dashboard/whitelist
# ---------------------------------------------------------------------------

@api_router.post("/whitelist", status_code=status.HTTP_200_OK)
async def add_to_whitelist(body: IPRequest):
    """
    Add an IP to the reputation engine whitelist.

    The IP is simultaneously removed from the blacklist if present.
    """
    engine = get_reputation_engine()
    engine.add_whitelist(body.ip)
    engine.blacklist.discard(body.ip)
    return {"status": "ok", "ip": body.ip, "action": "whitelisted"}


# ---------------------------------------------------------------------------
# POST /api/dashboard/blacklist
# ---------------------------------------------------------------------------

@api_router.post("/blacklist", status_code=status.HTTP_200_OK)
async def add_to_blacklist(body: IPRequest):
    """
    Add an IP to the reputation engine blacklist.

    The IP is simultaneously removed from the whitelist if present.
    """
    engine = get_reputation_engine()
    engine.add_blacklist(body.ip)
    engine.whitelist.discard(body.ip)
    return {"status": "ok", "ip": body.ip, "action": "blacklisted"}


# ---------------------------------------------------------------------------
# GET /api/dashboard/ip-status/{ip}
# ---------------------------------------------------------------------------

@api_router.get("/ip-status/{ip}")
async def ip_status(ip: str):
    """
    Current reputation status of an IP address.

    Response fields
    ---------------
    ip              : queried address
    is_blocked      : True if the engine would block this IP right now
    is_whitelisted  : True if the IP is in the permanent whitelist
    is_blacklisted  : True if the IP is in the permanent blacklist
    score           : cumulative risk score (higher = more suspicious)
    offenses        : total number of recorded offenses
    blocked_until   : ISO-8601 expiry of the current temporary ban, or null
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{ip}' is not a valid IP address",
        )

    engine = get_reputation_engine()
    blocked_until = engine.ip_blocked_until.get(ip)

    return {
        "ip":             ip,
        "is_blocked":     engine.is_blocked(ip),
        "is_whitelisted": ip in engine.whitelist,
        "is_blacklisted": ip in engine.blacklist,
        "score":          engine.get_score(ip),
        "offenses":       engine.get_offenses(ip),
        "blocked_until":  blocked_until.isoformat() if blocked_until else None,
    }


# ---------------------------------------------------------------------------
# Combined router — the only export main.py needs to include
# ---------------------------------------------------------------------------

router = APIRouter()
router.include_router(html_router)
router.include_router(api_router)
