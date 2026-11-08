"""Diagnósticos locais, sem acesso à rede."""
from __future__ import annotations

import os
import platform
import shutil
import sys


def system_report() -> str:
    tools = ("nmap", "dig", "whois", "curl")
    lines = [
        "Diagnóstico local do sistema",
        f"Python: {sys.version.split()[0]}",
        f"Plataforma: {platform.platform()}",
        f"Arquitetura: {platform.machine() or 'desconhecida'}",
        f"Diretório atual: {os.getcwd()}",
        "Ferramentas disponíveis:",
    ]
    lines.extend(f"  - {tool}: {'sim' if shutil.which(tool) else 'não'}" for tool in tools)
    return "\n".join(lines)
