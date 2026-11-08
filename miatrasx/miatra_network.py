"""Consultas de rede de baixo impacto para alvos autorizados.

Este módulo usa somente a biblioteca padrão do Python. Ele não executa comandos
externos, limita o volume de dados recebido e evita seguir redirecionamentos.
Use-o exclusivamente em domínios e serviços para os quais exista autorização.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import queue
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from typing import Any, Iterable
from urllib.parse import quote, urlsplit

DEFAULT_TIMEOUT = 5.0
MAX_TIMEOUT = 20.0
MAX_RESPONSE_BYTES = 512 * 1024
MAX_CERTIFICATES = 200
USER_AGENT = "Miatras-X-Network/0.1 (authorized-security-diagnostics)"
AUTHORIZATION_NOTICE = "Use somente em alvos para os quais você possui autorização explícita."


class NetworkInputError(ValueError):
    """Entrada inválida ou destino que não é seguro para esta consulta."""


def _timeout(value: float) -> float:
    try:
        value = float(value)
    except (TypeError, ValueError) as exc:
        raise NetworkInputError("timeout deve ser numérico") from exc
    if not 0.1 <= value <= MAX_TIMEOUT:
        raise NetworkInputError(f"timeout deve ficar entre 0.1 e {MAX_TIMEOUT:g} segundos")
    return value


def validate_hostname(host: str) -> str:
    """Valida um hostname ou endereço IP, sem aceitar sintaxe de URL."""
    if not isinstance(host, str):
        raise NetworkInputError("alvo deve ser texto")
    host = host.strip().rstrip(".")
    if not host or len(host) > 253 or any(char.isspace() for char in host):
        raise NetworkInputError("hostname inválido")
    if any(char in host for char in "/\\@:#?[]"):
        raise NetworkInputError("informe apenas hostname ou IP, sem URL, porta ou credenciais")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NetworkInputError("hostname inválido") from exc
    if len(ascii_host) > 253 or "." not in ascii_host:
        raise NetworkInputError("informe um hostname totalmente qualificado")
    labels = ascii_host.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           or not all(char.isalnum() or char == "-" for char in label) for label in labels):
        raise NetworkInputError("hostname inválido")
    return ascii_host.lower()


def _is_public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.is_global and not any((
        address.is_private, address.is_loopback, address.is_link_local,
        address.is_multicast, address.is_reserved, address.is_unspecified,
    ))


def _getaddrinfo_with_timeout(host: str, port: int | None, timeout: float) -> list[tuple[Any, ...]]:
    """Executa resolução em thread daemon, sem alterar timeout global do processo."""
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result.put((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except Exception as exc:
            result.put((False, exc))

    worker = threading.Thread(target=resolve, daemon=True)
    worker.start()
    try:
        succeeded, value = result.get(timeout=timeout)
    except queue.Empty as exc:
        raise NetworkInputError(f"a resolução de {host} excedeu o prazo de {timeout:g} segundos") from exc
    if not succeeded:
        raise value
    return value


def _public_addresses(host: str, port: int, timeout: float) -> list[str]:
    """Resolve e aceita somente endereços globalmente roteáveis.

    A conexão subsequente usa um IP validado, evitando uma segunda resolução
    (DNS rebinding) e acessos a serviços locais via nomes controlados pelo alvo.
    """
    try:
        infos = _getaddrinfo_with_timeout(host, port, timeout)
    except socket.gaierror as exc:
        raise NetworkInputError(f"não foi possível resolver {host}") from exc
    addresses: list[str] = []
    for _family, _socktype, _proto, _canonname, sockaddr in infos:
        address = sockaddr[0]
        if _is_public_ip(address) and address not in addresses:
            addresses.append(address)
    if not addresses:
        raise NetworkInputError("o alvo não resolve para um endereço IP público")
    return addresses


def dns_lookup(host: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Resolve A/AAAA pelo resolvedor configurado no sistema, sem varredura."""
    host = validate_hostname(host)
    timeout = _timeout(timeout)
    try:
        infos = _getaddrinfo_with_timeout(host, None, timeout)
    except socket.gaierror as exc:
        raise NetworkInputError(f"não foi possível resolver {host}") from exc
    addresses = sorted({info[4][0] for info in infos}, key=lambda item: (":" in item, item))
    return {"target": host, "addresses": addresses, "count": len(addresses)}


def _certificate_time(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return value


def tls_certificate(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Obtém o certificado apresentado por HTTPS com validação TLS obrigatória."""
    host = validate_hostname(host)
    timeout = _timeout(timeout)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise NetworkInputError("porta deve estar entre 1 e 65535")
    deadline = time.monotonic() + timeout
    addresses = _public_addresses(host, port, _remaining_timeout(deadline))
    context = ssl.create_default_context()  # CA do sistema e hostname verificados por padrão.
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with _connect_tls(host, addresses, port, deadline, context) as secure_socket:
            certificate = secure_socket.getpeercert()
            protocol = secure_socket.version()
            cipher = secure_socket.cipher()
    except (OSError, ssl.SSLError) as exc:
        raise NetworkInputError(f"falha na conexão TLS: {exc}") from exc
    return {
        "target": host,
        "port": port,
        "verified": True,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "subject": dict(certificate.get("subject", ())),
        "issuer": dict(certificate.get("issuer", ())),
        "serial_number": certificate.get("serialNumber"),
        "not_before": _certificate_time(certificate.get("notBefore")),
        "not_after": _certificate_time(certificate.get("notAfter")),
        "subject_alt_names": [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"],
    }


def _validated_https_url(url: str) -> tuple[str, int, str, str]:
    if not isinstance(url, str) or len(url) > 2048 or any(char.isspace() for char in url):
        raise NetworkInputError("URL inválida")
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise NetworkInputError("URL inválida") from exc
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise NetworkInputError("use uma URL HTTPS sem credenciais ou fragmento")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise NetworkInputError("porta inválida") from exc
    try:
        parsed_host = parsed.hostname or ""
    except ValueError as exc:
        raise NetworkInputError("hostname inválido") from exc
    host = validate_hostname(parsed_host)
    if not 1 <= port <= 65535:
        raise NetworkInputError("porta inválida")
    path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
    return host, port, path, parsed.geturl()


def _read_limited(response: HTTPResponse, maximum: int = MAX_RESPONSE_BYTES) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = response.read(min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    content = b"".join(chunks)
    if len(content) > maximum:
        raise NetworkInputError(f"resposta excede o limite de {maximum} bytes")
    return content


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("prazo de conexão excedido")
    return remaining


def _connect_tls(host: str, addresses: list[str], port: int, deadline: float, context: ssl.SSLContext) -> ssl.SSLSocket:
    """Tenta cada IP público já validado, compartilhando um único prazo total."""
    last_error: OSError | ssl.SSLError | None = None
    for address in addresses:
        raw_socket = None
        try:
            raw_socket = socket.create_connection((address, port), timeout=_remaining_timeout(deadline))
            return context.wrap_socket(raw_socket, server_hostname=host)
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            if raw_socket is not None:
                raw_socket.close()
    if last_error is not None:
        raise last_error
    raise socket.timeout("nenhum endereço público disponível")


def _host_header(host: str, port: int) -> str:
    """Retorna Host correto, incluindo porta não padrão e colchetes IPv6."""
    rendered_host = f"[{host}]" if ":" in host else host
    return rendered_host if port == 443 else f"{rendered_host}:{port}"


class _PinnedHTTPSConnection(HTTPSConnection):
    """HTTPSConnection que conecta a IPs já validados, mantendo SNI do hostname."""

    def __init__(self, host: str, pinned_ips: list[str], port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ips = pinned_ips

    def connect(self) -> None:
        deadline = time.monotonic() + self.timeout
        self.sock = _connect_tls(self.host, self._pinned_ips, self.port, deadline, self._context)


def _https_get(
    url: str, timeout: float, headers: dict[str, str] | None = None, method: str = "GET"
) -> tuple[int, dict[str, str], bytes]:
    """Faz uma única requisição HTTPS para IP público, sem seguir redirects."""
    if method not in {"GET", "HEAD"}:
        raise NetworkInputError("método HTTP não permitido")
    host, port, path, _original_url = _validated_https_url(url)
    deadline = time.monotonic() + timeout
    addresses = _public_addresses(host, port, _remaining_timeout(deadline))
    request_headers = {"Host": _host_header(host, port), "User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.1"}
    if headers:
        request_headers.update(headers)
    context = ssl.create_default_context()
    # O IP é fixado após validação: não há segunda resolução suscetível a DNS rebinding.
    connection = _PinnedHTTPSConnection(host, addresses, port, _remaining_timeout(deadline), context)
    try:
        connection.request(method, path, headers=request_headers)
        response = connection.getresponse()
        body = _read_limited(response)
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, response_headers, body
    except (OSError, ssl.SSLError) as exc:
        raise NetworkInputError(f"falha na requisição HTTPS: {exc}") from exc
    finally:
        connection.close()


def secure_http_headers(url: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Lê cabeçalhos de uma URL HTTPS, sem baixar conteúdo nem seguir redirects."""
    timeout = _timeout(timeout)
    _host, _port, _path, normalized_url = _validated_https_url(url)
    status, headers, _body = _https_get(normalized_url, timeout, {"Accept": "*/*"}, method="HEAD")
    important = (
        "strict-transport-security", "content-security-policy", "x-content-type-options",
        "x-frame-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
    )
    present = {name: headers[name] for name in important if name in headers}
    return {
        "url": normalized_url,
        "status": status,
        "redirected": 300 <= status < 400,
        "security_headers": present,
        "missing_security_headers": [name for name in important if name not in headers],
    }


def rdap_lookup(target: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Consulta RDAP no endpoint HTTPS fixo rdap.org; não usa URL do alvo."""
    timeout = _timeout(timeout)
    target = validate_hostname(target)
    try:
        resource_type = "ip" if ipaddress.ip_address(target) else "domain"
    except ValueError:
        resource_type = "domain"
    url = f"https://rdap.org/{resource_type}/{quote(target, safe='')}"
    status, headers, body = _https_get(url, timeout)
    if status != 200:
        raise NetworkInputError(f"RDAP respondeu HTTP {status}")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkInputError("RDAP retornou JSON inválido") from exc
    return {"source": "https://rdap.org", "target": target, "data": data}


def crtsh_lookup(domain: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Consulta crt.sh via HTTPS fixo e retorna no máximo 200 certificados."""
    timeout = _timeout(timeout)
    domain = validate_hostname(domain)
    if _is_ip_literal(domain):
        raise NetworkInputError("crt.sh aceita apenas nomes de domínio")
    url = f"https://crt.sh/?q={quote(domain, safe='')}&output=json"
    status, _headers, body = _https_get(url, timeout)
    if status != 200:
        raise NetworkInputError(f"crt.sh respondeu HTTP {status}")
    try:
        records = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkInputError("crt.sh retornou JSON inválido") from exc
    if not isinstance(records, list):
        raise NetworkInputError("crt.sh retornou formato inesperado")
    cleaned: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for item in records:
        if not isinstance(item, dict):
            continue
        key = (item.get("id"), item.get("name_value"))
        if key in seen:
            continue
        seen.add(key)
        cleaned.append({name: item.get(name) for name in ("id", "issuer_name", "common_name", "name_value", "not_before", "not_after")})
        if len(cleaned) >= MAX_CERTIFICATES:
            break
    return {"source": "https://crt.sh", "domain": domain, "count": len(cleaned), "truncated": len(records) > len(cleaned), "certificates": cleaned}


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def format_result(result: dict[str, Any], as_json: bool = False) -> str:
    """Serializa resultado em JSON ou texto legível sem depender de pacotes externos."""
    if as_json:
        return json.dumps(result, ensure_ascii=False, indent=2, default=str)
    lines = []
    for key, value in result.items():
        label = key.replace("_", " ").capitalize()
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, ensure_ascii=False, indent=2, default=str)
            lines.append(f"{label}:\n{rendered}")
        else:
            lines.append(f"{label}: {value}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Consultas de rede de baixo impacto (somente uso autorizado).")
    parser.add_argument("--authorized", action="store_true", help="confirma que você tem autorização explícita")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="timeout por operação (0.1 a 20 segundos)")
    parser.add_argument("--json", action="store_true", help="emite JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)
    dns = subparsers.add_parser("dns", help="resolve A/AAAA")
    dns.add_argument("target")
    tls = subparsers.add_parser("tls", help="consulta certificado TLS verificado")
    tls.add_argument("target")
    tls.add_argument("--port", type=int, default=443)
    headers = subparsers.add_parser("headers", help="inspeciona cabeçalhos de uma URL HTTPS")
    headers.add_argument("url")
    rdap = subparsers.add_parser("rdap", help="consulta RDAP por rdap.org")
    rdap.add_argument("target")
    crtsh = subparsers.add_parser("crtsh", help="consulta transparência de certificados por crt.sh")
    crtsh.add_argument("domain")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    """Interface pública de linha de comando; retorna código de saída POSIX."""
    parser = build_parser()
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    if not arguments.authorized:
        parser.error(f"{AUTHORIZATION_NOTICE} Repita com --authorized para confirmar.")
    try:
        if arguments.command == "dns":
            result = dns_lookup(arguments.target, arguments.timeout)
        elif arguments.command == "tls":
            result = tls_certificate(arguments.target, arguments.port, arguments.timeout)
        elif arguments.command == "headers":
            result = secure_http_headers(arguments.url, arguments.timeout)
        elif arguments.command == "rdap":
            result = rdap_lookup(arguments.target, arguments.timeout)
        else:
            result = crtsh_lookup(arguments.domain, arguments.timeout)
    except NetworkInputError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    print(AUTHORIZATION_NOTICE)
    print(format_result(result, arguments.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
