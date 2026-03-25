import httpx
from fastapi import Request
from fastapi.responses import Response

async def forward_request(request: Request, target_url: str, path: str) -> Response:
    """
    Fonction qui forwarde la requête vers le site cible.
    Retourne la réponse exacte du site cible.
    """
    # Reconstruit l'URL complète
    url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
    if request.query_params:
        url += "?" + str(request.query_params)

    # Envoi avec httpx (asynchrone)
    response = None
    try:
        # ------------------------------------------------------
        # Forward de la requête vers le serveur cible
        # httpx agit ici comme client HTTP
        # ------------------------------------------------------
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=await request.body(),
                timeout=30.0
            )

    except httpx.RequestError:
        # ------------------------------------------------------
        # Gestion erreur : serveur backend inaccessible
        # Exemple : serveur down ou timeout
        # ------------------------------------------------------
        return Response(
            content="Backend server unavailable",
            status_code=502
        )

    excluded_headers = {"content-length", "transfer-encoding", "content-encoding", "set-cookie"}
    response_headers = {
        k: v for k, v in response.headers.items()
        if k.lower() not in excluded_headers
    }
    if "location" in response_headers:
        import re as _re
        waf_base = str(request.base_url).rstrip("/")
        response_headers["location"] = _re.sub(
            r"^https?://[^/]+", waf_base, response_headers["location"]
        )

    resp = Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers
    )
    for key, value in response.headers.multi_items():
        if key.lower() == "set-cookie":
            resp.headers.append(key, value)

    return resp