"""Guardrails explícitos para uso autorizado e de baixo impacto."""
from __future__ import annotations

from urllib.parse import urlparse


def require_authorization(input_fn=input, output_fn=print) -> bool:
    """Pede confirmação inequívoca antes de ações de rede."""
    answer = input_fn("Você possui autorização explícita para este alvo? [sim/N]: ")
    if answer.strip().lower() not in {"sim", "s", "yes", "y"}:
        output_fn("Operação cancelada: autorização não confirmada.")
        return False
    return True


def valid_target(target: str) -> bool:
    """Aceita hostname, IPv4 ou IPv6 simples; evita argumentos iniciados por hífen."""
    return bool(target) and not target.startswith("-") and all(c not in target for c in " ;|&`$<>\n\r")


def valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc) and " " not in url


def valid_port_spec(value: str) -> bool:
    """Permite uma porta ou intervalo curto e numérico (ex.: 443 ou 80-100)."""
    if not value or any(c not in "0123456789-" for c in value) or value.count("-") > 1:
        return False
    try:
        parts = [int(x) for x in value.split("-")]
    except ValueError:
        return False
    if not all(1 <= p <= 65535 for p in parts):
        return False
    return len(parts) == 1 or parts[0] <= parts[1] and (parts[1] - parts[0] <= 1000)
