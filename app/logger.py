import logging

logging.basicConfig(
    filename="logs/waf.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("waf")

def log_request(client_ip: str, method: str, path: str, blocked: bool = False, reason: str = "", detail: str = "", alert: bool = False):
    if blocked:
        logger.warning(
            f"BLOCKED | IP={client_ip} | METHOD={method} | PATH=/{path} | RAISON={reason} | {detail}"
        )
    elif alert:
        logger.warning(
            f"ALERT | IP={client_ip} | METHOD={method} | PATH=/{path} | SCORE={reason} | ZONE={detail}"
        )
    else:
        logger.info(
            f"ALLOWED | IP={client_ip} | METHOD={method} | PATH=/{path}"
        )