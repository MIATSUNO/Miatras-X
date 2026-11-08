"""Extras opcionais e transparentes do Miatra para uso no Termux.

Este módulo é independente da CLI principal.  Ele não instala pacotes, não abre
rede durante a importação e jamais usa ``shell=True``.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

Output = Callable[[str], None]
Run = Callable[..., subprocess.CompletedProcess[str]]

FEEDS: dict[str, str] = {
    "agencia-brasil": "https://agenciabrasil.ebc.com.br/rss/ultimasnoticias/feed.xml",
    "bbc-mundo": "https://feeds.bbci.co.uk/mundo/rss.xml",
    "guardian-world": "https://www.theguardian.com/world/rss",
}
MAX_FEED_BYTES = 1_000_000


def _has_command(command: str) -> bool:
    return shutil.which(command) is not None


def _run(command: Sequence[str], output: Output = print, run: Run = subprocess.run) -> int:
    """Executa argv literalmente, mantendo a semântica normal do Termux."""
    executable = command[0]
    if not _has_command(executable):
        output(f"Ferramenta indisponível: {executable}. Instale-a manualmente no Termux e tente novamente.")
        return 127
    output("Executando: " + " ".join(command))
    try:
        result = run(list(command), check=False)
    except FileNotFoundError:
        output(f"Ferramenta indisponível: {executable}.")
        return 127
    except PermissionError:
        output(f"Permissão negada ao executar: {executable}.")
        return 126
    except OSError as exc:
        output(f"Não foi possível iniciar {executable}: {exc}")
        return 126
    return result.returncode


def debian_status(output: Output = print) -> int:
    """Informa se proot-distro e a distro Debian já estão disponíveis."""
    if not _has_command("proot-distro"):
        output("proot-distro não está disponível. Instale-o manualmente no Termux para usar Debian.")
        return 127
    try:
        result = subprocess.run(["proot-distro", "login", "debian", "--", "true"], capture_output=True, text=True, check=False, timeout=15)
    except subprocess.TimeoutExpired:
        output("A verificação do Debian excedeu 15s; confirme manualmente com: proot-distro login debian")
        return 124
    except OSError as exc:
        output(f"Não foi possível verificar Debian: {exc}")
        return 126
    if result.returncode == 0:
        output("Debian está instalado e pronto. Abra com: proot-distro login debian")
        return 0
    output("Debian não parece instalado. Para instalar, use: miatra-extras debian install --confirmar")
    return 1


def debian_open(output: Output = print, run: Run = subprocess.run) -> int:
    """Abre somente uma instalação Debian existente; nunca instala nada."""
    if not _has_command("proot-distro"):
        output("proot-distro não está disponível. Instale-o manualmente no Termux.")
        return 127
    output("Abrindo Debian existente com: proot-distro login debian")
    return _run(["proot-distro", "login", "debian"], output, run)


def debian_install(confirmed: bool, output: Output = print, run: Run = subprocess.run) -> int:
    """Instala Debian somente após confirmação explícita na própria linha."""
    if not confirmed:
        output("Instalação não executada. Ela baixa e cria um ambiente Debian; confirme com --confirmar.")
        return 3
    if not _has_command("proot-distro"):
        output("proot-distro não está disponível. Instale-o manualmente no Termux antes de continuar.")
        return 127
    output("Confirmação recebida: será executado proot-distro install debian.")
    return _run(["proot-distro", "install", "debian"], output, run)


def tor_status(output: Output = print) -> int:
    if not _has_command("tor"):
        output("Tor não está instalado. Instale-o manualmente no Termux se desejar usá-lo.")
        return 127
    output("Tor está disponível. 'tor start' inicia o processo em primeiro plano; Ctrl-C o encerra.")
    output("Aviso: usar Tor aqui não anonimiza automaticamente outros apps ou todo o tráfego do aparelho.")
    return 0


def tor_start(output: Output = print, run: Run = subprocess.run) -> int:
    if not _has_command("tor"):
        output("Tor não está instalado. Instale-o manualmente no Termux se desejar usá-lo.")
        return 127
    output("Iniciando Tor em primeiro plano. Pressione Ctrl-C para encerrar.")
    output("Isso não anonimiza automaticamente outros apps ou todo o tráfego do aparelho.")
    return _run(["tor"], output, run)


def git(args: Sequence[str], output: Output = print, run: Run = subprocess.run) -> int:
    """Encaminha argumentos Git literais, sem armazenar ou alterar credenciais."""
    if not args:
        output("Uso: git ARGS (ex.: git status, git log -1, git clone URL). Credenciais não são manipuladas.")
        return 2
    return _run(["git", *args], output, run)


def adb(args: Sequence[str], output: Output = print, run: Run = subprocess.run) -> int:
    """Encaminha argumentos ADB literais, incluindo 'adb shell' real."""
    if not args:
        output("Uso: adb ARGS (ex.: adb devices, adb shell). Os argumentos são passados diretamente ao ADB.")
        return 2
    return _run(["adb", *args], output, run)


def _text(element: ET.Element, name: str) -> str:
    value = element.findtext(name)
    return " ".join(value.split()) if value else ""


def _local_name(tag: str) -> str:
    """Retorna o nome local de uma tag XML, com ou sem namespace."""
    return tag.rsplit("}", 1)[-1].split(":")[-1]


def _child_text(element: ET.Element, name: str) -> str:
    """Lê texto de um filho direto, independentemente do namespace."""
    for child in element:
        if _local_name(child.tag) == name:
            return " ".join("".join(child.itertext()).split())
    return ""


def _atom_alternate_link(element: ET.Element) -> str:
    """Escolhe o link Atom alternativo; aceita fallback para link sem rel."""
    fallback = ""
    for child in element:
        if _local_name(child.tag) != "link":
            continue
        href = child.get("href", "").strip()
        if not href:
            continue
        if child.get("rel", "alternate").lower() == "alternate":
            return href
        if not fallback:
            fallback = href
    return fallback


def _feed_items(root: ET.Element) -> list[ET.Element]:
    """Localiza entradas RSS ou Atom sem depender dos namespaces usados."""
    return [element for element in root.iter() if _local_name(element.tag) in {"item", "entry"}]


def fetch_feed(name: str, limit: int = 5, output: Output = print, opener=urlopen) -> int:
    """Busca um RSS/Atom público via HTTPS e faz parse XML limitado e seguro."""
    url = FEEDS.get(name)
    if url is None:
        output("Feed desconhecido. Disponíveis: " + ", ".join(FEEDS))
        return 2
    if not 1 <= limit <= 20:
        output("O limite deve ficar entre 1 e 20.")
        return 2
    request = Request(url, headers={"User-Agent": "Miatra-Extras/1.0", "Accept": "application/rss+xml, application/atom+xml, application/xml"})
    try:
        with opener(request, timeout=10) as response:
            data = response.read(MAX_FEED_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        output(f"Não foi possível obter o feed '{name}': {exc}. Verifique a rede e tente novamente.")
        return 1
    if len(data) > MAX_FEED_BYTES:
        output(f"O feed '{name}' excede o limite seguro de {MAX_FEED_BYTES} bytes.")
        return 1
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.IGNORECASE):
        output(f"O feed '{name}' contém declaração XML não permitida (DOCTYPE ou ENTITY).")
        return 1
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        output(f"O feed '{name}' retornou XML inválido: {exc}")
        return 1
    items = _feed_items(root)
    if not items:
        output(f"O feed '{name}' não contém notícias reconhecíveis.")
        return 1
    output(f"Feed: {name} — {url}")
    for index, item in enumerate(items[:limit], 1):
        title = _child_text(item, "title") or "(sem título)"
        link = _atom_alternate_link(item) or _child_text(item, "link")
        output(f"{index}. {title}" + (f"\n   {link}" if link else ""))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="miatra-extras", description="Extras práticos e transparentes do Miatra para Termux.")
    sub = parser.add_subparsers(dest="command", required=True)
    debian = sub.add_parser("debian", help="verificar, abrir ou instalar Debian PRoot")
    debian_sub = debian.add_subparsers(dest="debian_command", required=True)
    debian_sub.add_parser("status", help="verifica se Debian já está instalado")
    debian_sub.add_parser("open", help="abre apenas Debian já instalado")
    install = debian_sub.add_parser("install", help="instala Debian após confirmação explícita")
    install.add_argument("--confirmar", action="store_true", help="confirma download e instalação do Debian")
    tor = sub.add_parser("tor", help="status ou execução de Tor")
    tor.add_argument("action", choices=("status", "start"))
    for name, help_text in (("git", "encaminha argumentos para Git"), ("adb", "encaminha argumentos para ADB")):
        item = sub.add_parser(name, help=help_text)
        item.add_argument("args", nargs=argparse.REMAINDER, help="argumentos literais da ferramenta")
    feeds = sub.add_parser("feeds", help="lê feeds públicos RSS/Atom por HTTPS")
    feeds.add_argument("feed", nargs="?", choices=tuple(FEEDS), help="feed a consultar")
    feeds.add_argument("--limite", type=int, default=5, help="notícias a exibir (1-20)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "debian":
        if args.debian_command == "status": return debian_status()
        if args.debian_command == "open": return debian_open()
        return debian_install(args.confirmar)
    if args.command == "tor":
        return tor_status() if args.action == "status" else tor_start()
    if args.command == "git": return git(args.args)
    if args.command == "adb": return adb(args.args)
    if args.command == "feeds":
        if not args.feed:
            print("Feeds disponíveis: " + ", ".join(FEEDS))
            print("Uso: feeds NOME [--limite 5]")
            return 0
        return fetch_feed(args.feed, args.limite)
    return 1


if __name__ == "__main__":
    sys.exit(main())
