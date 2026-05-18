import logging
from typing import Optional

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
    score: float = 0.0,
    master_score: Optional[float] = None,
    lof_score: Optional[float] = None,
    combined_score: Optional[float] = None,
    expert_score: Optional[float] = None,
    sqli_score: Optional[float] = None,
    xss_score: Optional[float] = None,
    hybrid_score: Optional[float] = None,
):
    # Tronquer le payload pour les logs
    payload_log = payload[:100] if payload else ""

    def _fmt_score(name: str, value: Optional[float]) -> str:
        return f"{name}={value:.4f} | " if value is not None else ""

    score_fields = (
        _fmt_score("MASTER_SCORE", master_score) +
        _fmt_score("LOF_SCORE", lof_score) +
        _fmt_score("SQLI_SCORE", sqli_score) +
        _fmt_score("XSS_SCORE", xss_score)
    )

    if blocked:
        display_reason = reason
        if not model and (
            reason.startswith("Attaque dans")
            or reason.startswith("Scanner")
            or reason.startswith("Methode")
            or reason.startswith("MÃ©thode")
        ):
            display_reason = "Rule Engine"

        detail_field = f"ZONE={detail}" if model and detail else detail

        logger.warning(
            f"BLOCKED | IP={client_ip} | METHOD={method} | PATH=/{path} | "
            f"RAISON={display_reason} | "
            f"{'MODEL=' + model + ' | ' if model else ''}"
            f"{score_fields}"
            f"{'ATTACK=' + attack_type + ' | ' if attack_type else ''}"
            f"{'PAYLOAD=' + payload_log + ' | ' if payload_log else ''}"
            f"{detail_field}"
        )
    elif alert:
        logger.warning(
            f"ALERT | IP={client_ip} | METHOD={method} | PATH=/{path} | "
            f"RAISON={reason} | "
            f"{'MODEL=' + model + ' | ' if model else ''}"
            f"{score_fields}"
            f"{'ATTACK=' + attack_type + ' | ' if attack_type else ''}"
            f"{'PAYLOAD=' + payload_log + ' | ' if payload_log else ''}"
            f"ZONE={detail}"
        )
    else:
        logger.info(
            f"ALLOWED | IP={client_ip} | METHOD={method} | PATH=/{path} | "
            f"{'MODEL=' + model + ' | ' if model else ''}"
            f"{score_fields}"
            f"{'ZONE=' + detail if detail else ''}"
        )
