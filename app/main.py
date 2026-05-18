from fastapi import FastAPI, Request
from dotenv import load_dotenv
import os

from urllib.parse import parse_qsl

from .proxy import forward_request
from .logger import log_request
from .rule_engine import analyze_request, block_response
from app.ml.ml_engine import MLDetectionEngine
from app.ml.reputation import IPReputationEngine
from app.ml.feedback import FeedbackCollector
from app.dashboard.routes import router as dashboard_router

load_dotenv()
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:9001")

waf = FastAPI()
waf.include_router(dashboard_router)

ml_engine = MLDetectionEngine()
ml_engine.load_models()

reputation_engine = IPReputationEngine()
reputation_engine.add_whitelist("127.0.0.1")

# Initialisation du collecteur de feedback pour l'apprentissage continu
feedback_collector = FeedbackCollector()


def _build_ml_payload(request: Request, body_str: str) -> str:
    """
    Build the ML input from payload values (query/form/body), not full request line.
    Models were trained on payload-like strings, so we keep inference aligned.
    """
    values = []

    for _, v in request.query_params.multi_items():
        if v:
            values.append(v)

    if body_str:
        parsed = parse_qsl(body_str, keep_blank_values=True)
        if parsed:
            for _, v in parsed:
                if v:
                    values.append(v)
        else:
            values.append(body_str)

    if values:
        return " ".join(values)

    return ""


@waf.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"])
async def proxy_request(path: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    method = request.method

    if reputation_engine.is_blocked(client_ip):
        log_request(client_ip, method, path, blocked=True, reason="IP bloquee par systeme de reputation", detail=f"Score: {reputation_engine.ip_scores[client_ip]}")
        return block_response("IP bloque", "Score de reputation depasse le seuil")

    is_blocked, reason, detail, rule_category = await analyze_request(request)

    if is_blocked:
        log_request(client_ip, method, path, blocked=True, reason=reason, detail=detail)
        reputation_engine.update_score(client_ip, is_attack=True, is_grey_zone=False, is_blocked=True)
        return block_response(reason, detail, rule_category)

    body = await request.body()
    query = str(request.url.query)
    body_str = body.decode('utf-8', errors='ignore') if body else ""

    if query:
        request_str = f"{method} {path}?{query} {body_str}".strip()
    else:
        request_str = f"{method} {path} {body_str}".strip()

    ml_payload = _build_ml_payload(request, body_str)

    if not ml_payload:
        log_request(
            client_ip, method, path,
            blocked=False,
            reason="Normal Score: 0.0000",
            detail="normal",
        )
        reputation_engine.update_score(client_ip, is_attack=False, is_grey_zone=False, is_blocked=False)
        feedback_collector.log_decision(request_str, False, 0.0, "normal", "", "", client_ip)
        return await forward_request(request, TARGET_URL, path)

    _, score, zone, model, attack_type, score_details = ml_engine.detect_attack(ml_payload)

    ml_scores = {
        "master_score":   score_details.get("master_score"),
        "lof_score":      score_details.get("lof_score"),
        "combined_score": score_details.get("combined_score"),
        "expert_score":   score_details.get("expert_score"),
        "sqli_score":     score_details.get("sqli_score"),
        "xss_score":      score_details.get("xss_score"),
        "hybrid_score":   score_details.get("hybrid_score"),
    }

    # BLOCK: attack confirmed by LOF+Master and/or expert model
    if zone == 'attack':
        log_request(
            client_ip, method, path,
            blocked=True,
            reason="ML Engine",
            detail=zone,
            model=model,
            attack_type=attack_type,
            payload=ml_payload,
            score=score,
            **ml_scores
        )
        reputation_engine.update_score(client_ip, is_attack=True, is_grey_zone=False, is_blocked=True)
        feedback_collector.log_decision(ml_payload, True, score, zone, model, attack_type, client_ip)
        return block_response("ML Detection", "", attack_type)

    # ALERT: suspicious but not confirmed enough to block
    elif zone == 'grey_zone_normal':
        log_request(
            client_ip, method, path,
            blocked=False,
            reason="ML Engine",
            detail=zone,
            alert=True,
            model=model,
            attack_type=attack_type,
            payload=ml_payload,
            score=score,
            **ml_scores
        )
        reputation_engine.update_score(client_ip, is_attack=False, is_grey_zone=True, is_blocked=False)
        feedback_collector.log_decision(ml_payload, False, score, zone, model, attack_type, client_ip)

    # NORMAL: no threat detected
    elif zone == 'normal':
        log_request(
            client_ip, method, path,
            blocked=False,
            reason=f"Normal Score: {score:.4f}",
            detail=zone,
            model=model,
            score=score,
            **ml_scores
        )
        reputation_engine.update_score(client_ip, is_attack=False, is_grey_zone=False, is_blocked=False)
        feedback_collector.log_decision(ml_payload, False, score, zone, model, attack_type, client_ip)

    if zone != 'attack':
        return await forward_request(request, TARGET_URL, path)
