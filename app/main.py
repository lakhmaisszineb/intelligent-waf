from fastapi import FastAPI, Request
from dotenv import load_dotenv
import os

from .proxy import forward_request
from .logger import log_request
from .rule_engine import analyze_request, block_response

load_dotenv()
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:9001")

waf = FastAPI()

@waf.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_request(path: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    method = request.method

    log_request(client_ip, method, path)

    is_blocked, reason, detail = await analyze_request(request)
    if is_blocked:
        return block_response(reason, detail)

    response = await forward_request(request, TARGET_URL, path)
    return response