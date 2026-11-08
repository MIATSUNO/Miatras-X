"""Wrappers restritos para ferramentas legítimas de diagnóstico de rede."""
from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable

from .safety import require_authorization, valid_port_spec, valid_target, valid_url

Output = Callable[[str], None]
Input = Callable[[str], str]


def _run(command: list[str], output: Output, timeout: int = 45) -> int:
    executable = command[0]
    if not shutil.which(executable):
        output(f"Ferramenta indisponível: {executable}. Execute o instalador Termux ou instale-a manualmente.")
        return 127
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        output(f"Tempo limite de {timeout}s excedido; processo interrompido.")
        return 124
    except OSError as exc:
        output(f"Não foi possível iniciar {executable}: {exc}")
        return 126
    if result.stdout:
        output(result.stdout.rstrip())
    if result.stderr:
        output(result.stderr.rstrip())
    return result.returncode


def nmap(target: str, ports: str | None, input_fn: Input = input, output: Output = print) -> int:
    """TCP connect scan pequeno; sem scripts, evasão, UDP ou varredura agressiva."""
    if not valid_target(target):
        output("Alvo inválido. Informe um host/IP simples, sem opções ou metacaracteres.")
        return 2
    if ports and not valid_port_spec(ports):
        output("Portas inválidas. Use uma porta ou intervalo máximo de 1000 portas (ex.: 443 ou 80-100).")
        return 2
    if not require_authorization(input_fn, output):
        return 3
    cmd = ["nmap", "-sT", "-T2", "--max-retries", "2", "--host-timeout", "45s"]
    if ports:
        cmd.extend(["-p", ports])
    cmd.append(target)
    return _run(cmd, output, timeout=60)


def dig(domain: str, input_fn: Input = input, output: Output = print) -> int:
    if not valid_target(domain):
        output("Domínio inválido.")
        return 2
    if not require_authorization(input_fn, output):
        return 3
    return _run(["dig", "+time=5", "+tries=1", "+short", domain], output, timeout=15)


def whois(query: str, input_fn: Input = input, output: Output = print) -> int:
    if not valid_target(query):
        output("Consulta inválida.")
        return 2
    if not require_authorization(input_fn, output):
        return 3
    return _run(["whois", query], output, timeout=30)


def curl(url: str, input_fn: Input = input, output: Output = print) -> int:
    """Somente cabeçalhos HTTP(S); não envia dados nem executa downloads."""
    if not valid_url(url):
        output("URL inválida. Use http:// ou https:// com host.")
        return 2
    if not require_authorization(input_fn, output):
        return 3
    return _run(["curl", "--head", "--location", "--max-time", "20", "--connect-timeout", "8", "--user-agent", "Miatras-X/0.1", url], output, timeout=25)
