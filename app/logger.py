import logging

# Configuration du système de logging
# ------------------------------------------------------
logging.basicConfig(
    filename="logs/waf.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("waf")


def log_request(client_ip: str, method: str, path: str):
    if client_ip == "unknown":
        logger.warning(
            f"Request with unknown IP | METHOD={method} | PATH=/{path}"
        )

    logger.info(
        f"Incoming request | IP={client_ip} | METHOD={method} | PATH=/{path}"
    )