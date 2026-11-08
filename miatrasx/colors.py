"""Saída colorida opcional, sem dependências externas."""
from __future__ import annotations

import os
import sys


class Colors:
    def __init__(self, enabled: bool | None = None) -> None:
        if enabled is None:
            enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.enabled = enabled

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def cyan(self, text: str) -> str:
        return self.paint(text, "96")

    def green(self, text: str) -> str:
        return self.paint(text, "92")

    def yellow(self, text: str) -> str:
        return self.paint(text, "93")

    def red(self, text: str) -> str:
        return self.paint(text, "91")

    def bold(self, text: str) -> str:
        return self.paint(text, "1")
