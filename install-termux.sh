#!/usr/bin/env sh
# Instalador explícito: usa somente pacotes oficiais do repositório Termux.
set -u

fail() { printf 'Erro: %s\n' "$1" >&2; exit 1; }
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || fail "não foi possível determinar a pasta do projeto"
command -v pkg >/dev/null 2>&1 || fail "'pkg' não encontrado. Execute este script dentro do Termux oficial."
case "${PREFIX:-}" in
    /data/data/com.termux/files/usr) ;;
    *) [ -n "${TERMUX_VERSION:-}" ] || fail "Termux real não identificado; por segurança, nenhuma instalação foi tentada." ;;
esac
[ -t 0 ] && [ -t 1 ] || fail "a confirmação explícita requer um terminal interativo. Nenhuma instalação foi tentada."

# Formato: executável:pacote Termux. Não use nomes de pacote para detectar presença.
REQUIRED_TOOLS='nmap:nmap dig:dnsutils whois:whois curl:curl git:git tor:tor proot-distro:proot-distro adb:android-tools'

missing_packages() {
    missing=
    for item in $REQUIRED_TOOLS; do
        tool=${item%%:*}
        package=${item#*:}
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $package"
    done
    printf '%s' "$missing"
}

missing_tools() {
    missing=
    for item in $REQUIRED_TOOLS; do
        tool=${item%%:*}
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    printf '%s' "$missing"
}

confirm() {
    printf '%s' "$1 [s/N]: "
    read -r reply || return 1
    case "$reply" in s|S|sim|SIM|Sim) return 0 ;; *) return 1 ;; esac
}

offer_debian_rootfs() {
    # O pacote proot-distro não é um rootfs; Debian sempre exige uma segunda confirmação.
    if ! command -v proot-distro >/dev/null 2>&1; then
        return 0
    fi
    printf '%s\n' "Opcional: o rootfs Debian ainda não foi instalado automaticamente."
    if confirm "Instalar o rootfs Debian agora com 'proot-distro install debian'?"; then
        if proot-distro install debian; then
            printf '%s\n' "Rootfs Debian instalado. Abra-o depois com: proot-distro login debian"
        else
            printf '%s\n' "Os pacotes Termux foram verificados, mas a instalação opcional do rootfs Debian falhou." >&2
            return 1
        fi
    else
        printf '%s\n' "Rootfs Debian não instalado; use 'proot-distro install debian' quando quiser, com confirmação explícita."
    fi
}

packages=$(missing_packages)
if [ -n "$packages" ]; then
    printf '%s\n' "Miatras-X instalará somente pacotes oficiais do Termux:$packages"
    printf '%s\n' "Eles habilitam: nmap, dig, whois, curl, git, Tor, PRoot/Debian e ADB."
    if ! confirm "Continuar?"; then
        printf '%s\n' "Instalação cancelada."
        exit 0
    fi

    if ! pkg update -y; then
        fail "Falha ao atualizar índices do pkg. Verifique conexão e repositórios Termux."
    fi
    install_failed=0
    if ! pkg install -y $packages; then
        install_failed=1
        printf '%s\n' "O pkg informou falha ao instalar um ou mais pacotes; verificando executáveis individualmente." >&2
    fi
else
    install_failed=0
    printf '%s\n' "Todos os pacotes Termux dos recursos implementados já parecem disponíveis."
fi

unavailable=$(missing_tools)
if [ "$install_failed" -ne 0 ] || [ -n "$unavailable" ]; then
    [ -n "$unavailable" ] && printf '%s\n' "Dependências ainda indisponíveis (por executável):$unavailable" >&2
    printf '%s\n' "Instalação incompleta: não será declarada como sucesso. Tente novamente ou instale os pacotes informados manualmente." >&2
    exit 1
fi

chmod +x "$BASE_DIR/miatras-x" || fail "as dependências estão disponíveis, mas não foi possível marcar o launcher como executável"
offer_debian_rootfs || exit 1
printf '%s\n' "Dependências Termux verificadas com sucesso. Inicie com: $BASE_DIR/miatras-x help"
