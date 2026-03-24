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
        headers.pop("content-length", None)

        # DEBUG TEMPORAIRE
        if "login.php" in path:
            print(f"\n=== DEBUG {request.method} /login.php ===")
            print(f"Cookie header: {headers.get('cookie', 'AUCUN COOKIE')}")
            print(f"=======================================\n")

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
    # On filtre les headers qui causent des conflits dans un reverse proxy :
    # - content-length  : recalculé automatiquement par FastAPI
    # - transfer-encoding : on ne streame pas, on bufférise tout
    # - content-encoding : httpx décode déjà la réponse (gzip, etc.)
    excluded_headers = {"content-length", "transfer-encoding", "content-encoding"}
    filtered_headers = {
        k: v for k, v in response.headers.items()
        if k.lower() not in excluded_headers
    }

    # Réécriture du header Location :
    # Si le backend redirige vers lui-même (ex: http://127.0.0.1/index.php)
    # on remplace par l'adresse du WAF (ex: http://127.0.0.1:8000/index.php)
    # pour que le navigateur reste sur le WAF et ne contourne pas la protection
    if "location" in filtered_headers:
        filtered_headers["location"] = filtered_headers["location"].replace(
            target_url.rstrip("/"), "http://127.0.0.1:8000"
        )

    # DEBUG TEMPORAIRE - afficher tous les Set-Cookie envoyés au navigateur
    if "login.php" in path:
        print(f"\n=== DEBUG RESPONSE /login.php ===")
        for k, v in response.headers.multi_items():
            if k.lower() == "set-cookie":
                print(f"Set-Cookie trouvé: {v}")
        print(f"Set-Cookie dans filtered_headers: {filtered_headers.get('set-cookie', 'ABSENT')}")
        print(f"=================================\n")

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=filtered_headers
    )