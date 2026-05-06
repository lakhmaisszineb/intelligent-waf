from fastapi import FastAPI, Request
from dotenv import load_dotenv
import os
from datetime import datetime

from .proxy import forward_request
from .logger import log_request
from .rule_engine import analyze_request, block_response
from app.ml.ml_engine import MLDetectionEngine
from app.ml.reputation import IPReputationEngine

load_dotenv()
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:9001")

waf = FastAPI()

ml_engine = MLDetectionEngine()
ml_engine.load_models()

reputation_engine = IPReputationEngine()
reputation_engine.add_whitelist("127.0.0.1")

@waf.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"])
async def proxy_request(path: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    method = request.method

    if reputation_engine.is_blocked(client_ip):
        log_request(client_ip, method, path, blocked=True, reason="IP bloquee par systeme de reputation", detail=f"Score: {reputation_engine.ip_scores[client_ip]}")
        return block_response("IP bloque", "Score de reputation depasse le seuil")

    is_blocked, reason, detail = await analyze_request(request)  

    if is_blocked:
        log_request(client_ip, method, path, blocked=True, reason=reason, detail=detail)
        reputation_engine.update_score(client_ip, is_attack=True, is_grey_zone=False, is_blocked=True)
        return block_response(reason, detail)

    body = await request.body()
    query = str(request.url.query)
    body_str = body.decode('utf-8', errors='ignore') if body else ""

    if query:
        request_str = f"{method} {path}?{query} {body_str}".strip()
    else:
        request_str = f"{method} {path} {body_str}".strip()

    result, score, zone, model, attack_type = ml_engine.detect_attack(request_str)

    if zone == 'attack':
        log_request(
            client_ip, method, path,
            blocked=True,
            reason=f"ML Attack Score: {score:.4f}",
            detail=zone,
            model=model,
            attack_type=attack_type,
            payload=request_str[:100],
            score=score
        )
        return block_response("ML Detection", f"Score: {score:.4f} | {attack_type}")

    elif zone == 'grey_zone':
        log_request(
            client_ip, method, path,
            blocked=False,
            reason=f"Grey Zone Score: {score:.4f}",
            detail=zone,
            alert=True,
            model=model,
            attack_type=attack_type
        )

    elif zone == 'anomaly_alert':
        log_request(
            client_ip, method, path,
            blocked=False,
            reason=f"Anomaly Score: {score:.4f}",
            detail="anomaly_alert",
            alert=True,
            model="LOF",
            attack_type="Anomalie"
        )

    elif zone == 'normal':
        log_request(
            client_ip, method, path,
            blocked=False,
            reason=f"Normal Score: {score:.4f}",
            detail=zone
        )