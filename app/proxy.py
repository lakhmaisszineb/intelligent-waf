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
    # modifit lcode hna pour la Gestion des erreurs backend
    response = None
    try:

        # ------------------------------------------------------
        # Forward de la requête vers le serveur cible
        # httpx agit ici comme client HTTP
        # ------------------------------------------------------
        headers = dict(request.headers)
        headers.pop("host", None)
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
    # Renvoie la réponse telle quelle
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers)
    )