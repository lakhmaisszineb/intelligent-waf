from fastapi import FastAPI, Request
from dotenv import load_dotenv
import os

# Importe la fonction de forwarding depuis proxy.py
from .proxy import forward_request

# Charge la configuration depuis .env
load_dotenv()
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:9001")  # Valeur par défaut

# Création de l'application WAF
waf = FastAPI()

@waf.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_request(path: str, request: Request):
    response = await forward_request(request, TARGET_URL, path)

    return response
