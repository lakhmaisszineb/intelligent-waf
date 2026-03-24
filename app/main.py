from fastapi import FastAPI, Request, Response
from dotenv import load_dotenv
import os

from .proxy import forward_request
from .logger import log_request

from .rule_engine import check_request
#hna zdt la partie dyal logs
# ------------------------------------------------------
# Configuration du système de logging
# Les logs seront enregistrés dans logs/waf.log
logging.basicConfig(
    filename="logs/waf.log",  # fichier de log
    level=logging.INFO,       # niveau de log
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("waf")
# ---------------------------------------------------------
# Charge la configuration depuis .env
load_dotenv()
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:9001")  # Valeur par défaut

# Création de l'application WAF
waf = FastAPI()

@waf.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_request(path: str, request: Request):
    
    client_ip = request.client.host if request.client else "unknown"
    method = request.method

    # Log de la requête entrante
    log_request(client_ip, method, path)

    # ── Inspection de la requête par le moteur de règles ──────────────────
    # result = await check_request(request)  # TEMP: désactivé pour debug

    # if result["blocked"]:
    #     logger.warning(
    #         f"BLOCKED | IP={client_ip} | TYPE={result['type']} "
    #         f"| LOCATION={result['location']} | REASON={result['reason']}"
    #     )
    #     return Response(
    #         content=f"403 Forbidden - {result['type']} detected",
    #         status_code=403
    #     )

    # Forward de la requête vers le serveur cible
    response = await forward_request(request, TARGET_URL, path)
    return response

