from fastapi import FastAPI, Request
from fastapi.responses import Response
import httpx

app = FastAPI(title="WAF Intelligent - Phase 1 : Reverse Proxy Basique")

# URL du site vulnérable à protéger 
TARGET_URL = "http://localhost:9001"

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_request(path: str, request: Request):
    # Construit l'URL complète pour le site cible
    url = f"{TARGET_URL}/{path}"
    if request.query_params:
        url += "?" + str(request.query_params)

    print(f"Requête reçue : {request.method} {url}")  # Pour debug

    # Forward la requête avec httpx (async)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=url,
                headers=dict(request.headers),
                content=await request.body(),
                timeout=30.0  # Timeout pour éviter blocage
            )
        except Exception as e:
            print(f"Erreur forwarding : {e}")
            return Response(content="Erreur interne du WAF", status_code=502)

    # Renvoie la réponse exacte du site cible
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers)
    )