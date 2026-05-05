from fastapi import FastAPI, Request
from dotenv import load_dotenv
import os

from .proxy import forward_request
from .logger import log_request
from .rule_engine import analyze_request, block_response
from app.ml.ml_engine import MLDetectionEngine

load_dotenv()
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:9001")

waf = FastAPI()

ml_engine = MLDetectionEngine()
ml_engine.load_models()

@waf.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"])
async def proxy_request(path: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    method = request.method

    # ETAPE 1: REGLES STATIQUES OWASP
    is_blocked, reason, detail = await analyze_request(request)  

    if is_blocked:
        log_request(client_ip, method, path, blocked=True, reason=reason, detail=detail)
        return block_response(reason, detail)

    # ETAPE 2: CONSTRUCTION REQUETE POUR ML
    body = await request.body()
    request_str = f"{method} {path} HTTP/1.1\n"
    for header, value in request.headers.items():
        request_str += f"{header}: {value}\n"
    if body:
        request_str += f"\n{body.decode('utf-8', errors='ignore')}"

    # ETAPE 3: DETECTION ML
    result, score, zone = ml_engine.detect_attack(request_str)

    # ETAPE 4: DECISION SELON ZONE
    if zone == 'attack':
        log_request(client_ip, method, path, blocked=True, reason=f"ML Attack Score: {score:.4f}", detail=zone)
        return block_response(f"ML Detection", f"Score: {score:.4f}")
    
    elif zone == 'grey_zone':
        log_request(client_ip, method, path, blocked=False, reason=f"Grey Zone Score: {score:.4f}", detail=zone)
        
    elif zone == 'normal':
        log_request(client_ip, method, path, blocked=False, reason=f"Normal Score: {score:.4f}", detail=zone)

    # ETAPE 5: FORWARD
    response = await forward_request(request, TARGET_URL, path)
    return response