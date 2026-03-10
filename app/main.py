from fastapi import FastAPI, Request
from dotenv import load_dotenv
import logging
import os

# Importe la fonction de forwarding depuis proxy.py
from .proxy import forward_request
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
    # ------------------------------------------------------
    # LOGGING: enregistrer les informations de la requête
    # Ces logs serviront plus tard pour :
    # - analyse sécurité
    # - debugging
    # - dataset pour Machine Learning
    # ------------------------------------------------------
    client_ip = request.client.host if request.client else "unknown"
    method = request.method

    logger.info(
        f"Incoming request | IP={client_ip} | METHOD={method} | PATH=/{path}"
    )

    # Forward de la requête vers le serveur cible
    response = await forward_request(request, TARGET_URL, path)

    return response
