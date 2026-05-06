import logging

# Fix encoding Windows
logging.basicConfig(
    filename="logs/waf.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding='utf-8'   # ← ajouter
)

logger = logging.getLogger("waf")

def log_request(
    client_ip: str,
    method: str,
    path: str,
    blocked: bool = False,
    reason: str = "",
    detail: str = "",
    alert: bool = False,
    # Nouveaux paramètres
    model: str = "",
    attack_type: str = "",
    payload: str = "",
    score: float = 0.0
):
    # Tronquer le payload pour les logs
    payload_log = payload[:100] if payload else ""

    if blocked:
        logger.warning(
            f"BLOCKED | IP={client_ip} | METHOD={method} | PATH=/{path} | "
            f"RAISON={reason} | "
            f"{'MODEL=' + model + ' | ' if model else ''}"
            f"{'ATTACK=' + attack_type + ' | ' if attack_type else ''}"
            f"{'PAYLOAD=' + payload_log + ' | ' if payload_log else ''}"
            f"{detail}"
        )
    elif alert:
        logger.warning(
            f"ALERT | IP={client_ip} | METHOD={method} | PATH=/{path} | "
            f"SCORE={reason} | "
            f"{'MODEL=' + model + ' | ' if model else ''}"
            f"ZONE={detail}"
        )
    else:
        logger.info(
            f"ALLOWED | IP={client_ip} | METHOD={method} | PATH=/{path}"
        )