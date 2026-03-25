from fastapi import FastAPI, Request
from dotenv import load_dotenv
import os

from .proxy import forward_request
from .logger import log_request
from .rule_engine import analyze_request, block_response

load_dotenv()
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:9001")

waf = FastAPI()

@waf.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"])
async def proxy_request(path: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    method = request.method

    is_blocked, reason, detail = await analyze_request(request)  

    if is_blocked:
        log_request(client_ip, method, path, blocked=True, reason=reason, detail=detail)
        return block_response(reason, detail)

    log_request(client_ip, method, path)
    response = await forward_request(request, TARGET_URL, path)
    return response