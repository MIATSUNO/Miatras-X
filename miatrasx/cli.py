"""Interface em português para Miatras-X."""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence

from . import __version__, miatra_extras, miatra_network, tools
from .colors import Colors
from .diagnostics import system_report

BANNER = r"""
███╗   ███╗██╗ █████╗ ████████╗██████╗  █████╗ ███████╗      ██╗  ██╗
████╗ ████║██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝      ╚██╗██╔╝
██╔████╔██║██║███████║   ██║   ██████╔╝███████║███████╗ ███╗  ╚███╔╝ 
██║╚██╔╝██║██║██╔══██║   ██║   ██╔══██╗██╔══██╗╚════██║ ╚══╝  ██╔██╗ 
██║ ╚═╝ ██║██║██║  ██║   ██║   ██║   ██║██║  ██║███████║      ██╔╝ ██╗
╚═╝     ╚═╝╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝      ╚═╝  ╚═╝
"""
HELP = """Comandos Miatras-X:
  shell                              abre o shell interativo
  diagnostico                        mostra informações locais e ferramentas disponíveis
  nmap ALVO [PORTAS|--portas PORTAS] TCP connect scan limitado (exige autorização)
  dig DOMINIO                        consulta DNS simples (exige autorização)
  whois CONSULTA                     consulta WHOIS (exige autorização)
  curl URL                           consulta somente cabeçalhos HTTP(S) (exige autorização)
  rede ARGS...                       consultas de rede seguras; use: rede --help
  extra|extras ARGS...               recursos opcionais; use: extras --help
  help                               mostra esta ajuda

Rede: dns, tls, headers, rdap e crtsh exigem --authorized. Ex.: rede --authorized dns exemplo.org
Extras: debian, tor, git, adb e feeds. Ex.: extras feeds bbc-mundo
No shell: cd CAMINHO, pwd, diagnostico, rede, extra/extras, ajuda/help, exit/sair e comandos normais.
Comandos normais são executados pelo subprocess do sistema: este programa não substitui o terminal.
"""


def prompt_for(cwd: str) -> str:
    """Prompt dinâmico solicitado, com diretório atual entre aspas."""
    return f'↳"{os.path.basename(cwd) or cwd}"/"{cwd}"/Miatras-x:>  $ '


def print_banner(output: Callable[[str], None] = print, colors: Colors | None = None) -> None:
    colors = colors or Colors()
    output(colors.cyan(BANNER.rstrip()))
    output(colors.bold(f"Miatras-X {__version__} — base modular para diagnóstico autorizado."))


def execute_normal(argv: list[str], output: Callable[[str], None] = print) -> int:
    if not argv:
        return 0
    try:
        completed = subprocess.run(argv, check=False)
        return completed.returncode
    except FileNotFoundError:
        output(f"Comando não encontrado: {argv[0]}")
        return 127
    except PermissionError:
        output(f"Permissão negada: {argv[0]}")
        return 126
    except OSError as exc:
        output(f"Falha ao executar comando: {exc}")
        return 126
    except KeyboardInterrupt:
        output("\nComando interrompido.")
        return 130


def run_extension(name: str, argv: Sequence[str], output: Callable[[str], None] = print) -> int:
    """Despacha extensões sem deixar argparse encerrar o shell hospedeiro."""
    if not argv:
        output(f"Uso: {name} ARGS... (consulte '{name} --help')")
        return 2
    handler = miatra_network.main if name == "rede" else miatra_extras.main
    try:
        return handler(list(argv))
    except SystemExit as exc:
        # argparse usa SystemExit para --help e erros; no shell, volte ao prompt.
        return int(exc.code) if isinstance(exc.code, int) else 1


def parse_shell_nmap(args: Sequence[str], output: Callable[[str], None] = print) -> tuple[str, str | None] | None:
    """Valida os argumentos de nmap no shell sem deixar erros derrubarem a sessão."""
    usage = "Uso: nmap ALVO [PORTAS|--portas PORTAS|-p PORTAS]"
    if not args:
        output(usage)
        return None
    if args[0].startswith("-"):
        output(f"Opção desconhecida para nmap: {args[0]}. {usage}")
        return None

    target = args[0]
    ports: str | None = None
    index = 1
    while index < len(args):
        item = args[index]
        if item in {"--portas", "-p"}:
            if index + 1 == len(args) or args[index + 1].startswith("-"):
                output(f"A opção {item} exige PORTAS. {usage}")
                return None
            if ports is not None:
                output(f"Portas informadas mais de uma vez. {usage}")
                return None
            ports = args[index + 1]
            index += 2
        elif item.startswith("--portas="):
            value = item.split("=", 1)[1]
            if not value:
                output(f"A opção --portas exige PORTAS. {usage}")
                return None
            if ports is not None:
                output(f"Portas informadas mais de uma vez. {usage}")
                return None
            ports = value
            index += 1
        elif item.startswith("-"):
            output(f"Opção desconhecida para nmap: {item}. {usage}")
            return None
        elif ports is None:
            ports = item
            index += 1
        else:
            output(f"Argumento desconhecido para nmap: {item}. {usage}")
            return None
    return target, ports


def interactive_shell(input_fn: Callable[[str], str] = input, output: Callable[[str], None] = print) -> int:
    output("Shell Miatras-X. Digite 'ajuda' para ver opções; 'exit' para sair.")
    while True:
        try:
            raw = input_fn(prompt_for(os.getcwd()))
        except EOFError:
            output("\nSessão encerrada.")
            return 0
        except KeyboardInterrupt:
            output("\nUse 'exit' para encerrar.")
            continue
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            output(f"Sintaxe inválida: {exc}")
            continue
        if not parts:
            continue
        command, *args = parts
        if command in {"exit", "sair", "quit"}:
            return 0
        if command in {"help", "ajuda"}:
            output(HELP)
        elif command == "pwd":
            output(os.getcwd())
        elif command == "cd":
            target = args[0] if args else os.path.expanduser("~")
            try:
                os.chdir(os.path.expanduser(target))
            except OSError as exc:
                output(f"cd: {exc}")
        elif command in {"diagnostico", "diag"}:
            output(system_report())
        elif command == "nmap":
            parsed_nmap = parse_shell_nmap(args, output)
            if parsed_nmap is not None:
                tools.nmap(*parsed_nmap)
        elif command == "dig":
            if not args:
                output("Uso: dig DOMINIO")
            else:
                tools.dig(args[0])
        elif command == "whois":
            if not args:
                output("Uso: whois CONSULTA")
            else:
                tools.whois(args[0])
        elif command == "curl":
            if not args:
                output("Uso: curl URL")
            else:
                tools.curl(args[0])
        elif command == "rede":
            run_extension("rede", args, output)
        elif command in {"extra", "extras"}:
            run_extension("extras", args, output)
        else:
            execute_normal(parts, output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="miatras-x", description="Miatras-X: diagnósticos autorizados.")
    parser.add_argument("--sem-cor", action="store_true", help="desativa cores ANSI")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("shell", help="abre shell interativo")
    sub.add_parser("diagnostico", aliases=["diag"], help="diagnóstico local")
    scan = sub.add_parser("nmap", help="scan TCP limitado e autorizado")
    scan.add_argument("alvo")
    scan.add_argument("portas_posicional", nargs="?", metavar="PORTAS")
    scan.add_argument("--portas", "-p")
    for name, label in (("dig", "dominio"), ("whois", "consulta"), ("curl", "url")):
        item = sub.add_parser(name, help=f"wrapper {name} autorizado")
        item.add_argument(label)
    for name, help_text in (("rede", "consultas de rede de baixo impacto"), ("extra", "extras opcionais do Termux"), ("extras", "alias para extra")):
        # As extensões recebem suas próprias opções (inclusive --help), sem a CLI pai consumi-las.
        item = sub.add_parser(name, help=help_text, add_help=False)
        item.add_argument("extension_args", nargs=argparse.REMAINDER, help="argumentos da extensão; use --help após o comando")
    sub.add_parser("help", help="mostra ajuda")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    command_line = list(argv) if argv is not None else sys.argv[1:]
    args, unknown = parser.parse_known_args(command_line)
    if args.command not in {"rede", "extra", "extras"} and unknown:
        parser.error("unrecognized arguments: " + " ".join(unknown))
    if args.command in {"rede", "extra", "extras"}:
        # Preserve a ordem exata: opções globais das extensões podem vir antes do subcomando delas.
        args.extension_args = command_line[command_line.index(args.command) + 1:]
    colors = Colors(enabled=False if args.sem_cor else None)
    if args.command is None:
        print_banner(colors=colors)
        if sys.stdin.isatty():
            return interactive_shell()
        print(HELP)
        return 0
    if args.command == "shell":
        print_banner(colors=colors)
        return interactive_shell()
    if args.command in {"diagnostico", "diag"}:
        print(system_report())
        return 0
    if args.command == "nmap":
        if args.portas and args.portas_posicional:
            parser.error("informe PORTAS uma única vez, por posição ou com --portas/-p")
        return tools.nmap(args.alvo, args.portas or args.portas_posicional)
    if args.command == "dig": return tools.dig(args.dominio)
    if args.command == "whois": return tools.whois(args.consulta)
    if args.command == "curl": return tools.curl(args.url)
    if args.command == "rede": return run_extension("rede", args.extension_args)
    if args.command in {"extra", "extras"}: return run_extension("extras", args.extension_args)
    if args.command == "help":
        print(HELP)
        return 0
    return 1
