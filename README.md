# Miatras-X

Base **modular e educacional** para uma CLI de diagnóstico e segurança autorizada em Python, pensada para Termux. É uma adaptação independente de ideias de uso observáveis na análise do aplicativo Miatra: **não reutiliza código do APK** e não reivindica licença, autoria ou paridade com ele.

> Use somente em ativos, domínios e redes para os quais você tenha autorização explícita. A pessoa operadora responde por permissões, escopo e legislação aplicável.

## O que a CLI entrega

- Interface PT-BR, banner ASCII e cores opcionais (`--sem-cor` ou `NO_COLOR=1`).
- Sem argumento, `./miatras-x` mostra o banner e abre o shell **somente se houver TTY**. Em pipe/CI/execução não interativa, mostra banner e ajuda, e termina sem bloquear.
- Shell com `cd` persistente na sessão, `pwd`, `diagnostico`, `ajuda/help`, `rede`, `extra/extras`, `exit/sair` e execução literal de comandos normais por `subprocess`. Não substitui um emulador de terminal.
- Diagnóstico local de Python, plataforma, arquitetura, diretório e ferramentas disponíveis.
- Wrappers conservadores: `nmap` TCP connect limitado, `dig`, `whois` e `curl` somente de cabeçalhos HTTP(S), todos com confirmação de autorização.
- Extensão `rede`, implementada apenas com biblioteca padrão: DNS, certificado TLS validado, cabeçalhos HTTPS sem redirects, RDAP por `rdap.org` e transparência de certificados por `crt.sh`. Ela exige `--authorized`, bloqueia destinos locais para consultas HTTPS, limita timeout/resposta e não faz varredura.
- Extensão `extra`/`extras`: status/abertura/instalação explícita de Debian PRoot, Tor em primeiro plano, encaminhamento literal de Git/ADB e feeds RSS/Atom HTTPS limitados.

## Início no Termux

Use o **Termux oficial** de fonte confiável; não misture fontes ou repositórios.

```sh
pkg install git
git clone https://github.com/MIATSUNO/Miatras-X.git miatras-x
cd miatras-x
chmod +x miatras-x install-termux.sh
./miatras-x
```

Na primeira execução interativa em um Termux real, se Python não existir, o launcher explica e pede confirmação antes de executar `pkg install python`. Se faltar qualquer executável dos recursos implementados, ele mostra o nome do executável e do pacote correspondente e oferece executar `install-termux.sh`, também com confirmação. O conjunto completo é: `nmap`/`nmap`, `dig`/`dnsutils`, `whois`/`whois`, `curl`/`curl`, `git`/`git`, `tor`/`tor`, `proot-distro`/`proot-distro` e `adb`/`android-tools`.

Não há instalação automática fora do Termux, sem `pkg` ou sem TTY. Se a instalação falhar, o launcher informa a falha e não a declara concluída; enquanto houver dependência faltante, a oferta reaparece em um próximo início interativo. Também é possível revisar e chamar explicitamente:

```sh
./install-termux.sh
```

O instalador exige Termux identificado e terminal interativo para não tentar instalar nada sem confirmação. Ele usa exclusivamente os pacotes oficiais disponíveis via `pkg`, detecta ausências por executável (não apenas pelo nome do pacote), instala somente os que faltam e verifica cada executável depois. Se houver falha parcial, lista o que continua indisponível e **não** declara sucesso.

`proot-distro` é instalado como parte desse conjunto para habilitar o recurso opcional de Debian, mas o **rootfs Debian não é instalado automaticamente**. Ao terminar a verificação dos pacotes, o instalador oferece, em uma segunda confirmação explícita, rodar `proot-distro install debian`; recusar mantém o rootfs ausente sem erro. Também é possível usar depois `./miatras-x extras debian install --confirmar`.

Fora do Termux, tenha **Python >= 3.10** no `PATH` e execute `./miatras-x` ou `python -m miatrasx` a partir da raiz do projeto. O launcher resolve sua própria pasta de forma estável, por isso funciona mesmo invocado de outro diretório.

## Todos os comandos

### CLI principal

```sh
./miatras-x                         # banner + shell em TTY; ajuda em modo não interativo
./miatras-x help
./miatras-x --sem-cor diagnostico
./miatras-x shell
./miatras-x nmap exemplo.interno --portas 443
./miatras-x dig exemplo.interno
./miatras-x whois exemplo.interno
./miatras-x curl https://exemplo.interno/status
```

`nmap`, `dig`, `whois` e `curl` pedem confirmação humana. `nmap` aceita `nmap ALVO PORTAS`, `nmap ALVO --portas PORTAS` e `nmap ALVO -p PORTAS`; é somente TCP connect (`-sT`), ritmo moderado e intervalo máximo de 1000 portas; não há UDP, scripts, evasão ou varredura agressiva. `curl` não envia dados, não baixa conteúdo e consulta somente cabeçalhos.

### Rede (`rede`)

```sh
./miatras-x rede --help
./miatras-x rede --authorized dns exemplo.org
./miatras-x rede --authorized --timeout 5 tls exemplo.org --port 443
./miatras-x rede --authorized headers https://exemplo.org/status
./miatras-x rede --authorized --json rdap exemplo.org
./miatras-x rede --authorized crtsh exemplo.org
```

Também funciona dentro do shell: `rede --authorized dns exemplo.org`. Opções: `--authorized` confirma autorização explícita; `--timeout` aceita 0,1–20 segundos; `--json` gera JSON. Subcomandos: `dns ALVO`, `tls ALVO [--port PORTA]`, `headers URL_HTTPS`, `rdap ALVO` e `crtsh DOMINIO`.

### Extras (`extra` ou `extras`)

```sh
./miatras-x extras --help
./miatras-x extras debian status
./miatras-x extras debian open
./miatras-x extras debian install --confirmar
./miatras-x extras tor status
./miatras-x extras tor start
./miatras-x extras git status
./miatras-x extras adb devices
./miatras-x extras feeds
./miatras-x extras feeds bbc-mundo --limite 5
```

Os mesmos comandos estão disponíveis no shell por `extra ...` ou `extras ...`. `debian install` só roda após `--confirmar`; `debian open` jamais instala. `tor start` fica em primeiro plano e **não anonimiza globalmente** os apps ou todo o tráfego do aparelho. `git` e `adb` apenas repassam vetores de argumentos, sem manipular credenciais, mas são comandos completos: argumentos como os de escrita, exclusão, instalação ou alteração de dispositivos podem modificar dados ou o estado do aparelho. Feeds disponíveis: `agencia-brasil`, `bbc-mundo` e `guardian-world`; o limite é de 1–20 itens, as fontes são de terceiros e os itens trazem conteúdo externo não verificado pela CLI.

## Matriz honesta de recursos em relação ao Miatra analisado

A análise do APK serve como referência funcional, não como fonte de código. “Adaptado” não quer dizer idêntico, completo ou garantido.

| Recurso associado ao Miatra | Situação no Miatras-X | Limite / observação |
|---|---|---|
| Navegador / WebView | **Ausente** | Não há navegador embutido, renderização de páginas ou WebView. |
| DevTools | **Ausente** | Não há inspeção de DOM, console remoto ou ferramentas de desenvolvedor. |
| Git | **Adaptado via wrapper opcional** | `extras git ARGS` requer `git` instalado e não gerencia credenciais. |
| ADB | **Adaptado via wrapper opcional** | `extras adb ARGS` requer ADB/`android-tools`; permissões e conexão seguem as regras do Android. |
| Tor | **Adaptado, não global** | `extras tor status/start` requer `tor`; inicia processo local em primeiro plano e não anonimiza o aparelho nem outros apps. |
| Debian | **Adaptado por PRoot opcional** | `extras debian` usa `proot-distro`, com instalação explicitamente confirmada; PRoot não é VM, root real ou isolamento forte. |
| Redes | **Adaptado de forma restrita** | Wrappers autorizados e consultas `rede`; sem exploração, captura, evasão, scanner agressivo ou garantias de alcance. |
| Feeds | **Adaptado** | RSS/Atom HTTPS público, tamanho e quantidade limitados; disponibilidade depende das fontes. |
| Câmeras | **Ausente** | Não controla câmera, captura imagem/vídeo ou permissões de câmera. |
| Mirtis | **Ausente / não integrado** | Não há componente Mirtis identificado e portado nesta CLI. |
| Terminal | **Adaptado parcialmente** | Shell leve e subprocessos; não é emulador Android completo nem substitui Termux. |

Portanto, não há promessa de paridade total com o Miatra, de compatibilidade universal, de resultado de rede, de anonimato ou de garantia de 100%.

## Segurança e limitações

- A confirmação, validação, timeouts e argumentos restritos reduzem erros acidentais; não substituem autorização, controles organizacionais ou revisão real.
- Estão fora de escopo: exploração, persistência, coleta de credenciais, evasão, phishing, bypass de controles, scanners agressivos e execução de scripts de terceiros.
- PRoot não concede permissões de kernel, root real, captura de pacotes, portas privilegiadas ou acesso irrestrito a interfaces.
- Armazenamento compartilhado normalmente exige `termux-setup-storage` e consentimento Android. Recursos como monitor mode, captura e portas privilegiadas dependem de root, hardware/driver e autorização.
- Ferramentas e fontes externas podem estar indisponíveis, ter versões diferentes ou falhar; nunca trate a CLI como garantia de segurança, resultado ou compatibilidade.

## Testes

Os testes unitários não realizam rede nem chamam ferramentas externas. O teste de shell cria um `PATH` temporário com comandos falsos e um `pkg` falso: não chama o `pkg` real nem instala pacotes. Ele cobre o conjunto completo, a verificação individual após uma instalação bem-sucedida e a recusa de declarar sucesso em falha parcial:

```sh
python -m unittest discover -s tests -v
sh -n miatras-x install-termux.sh
python -m unittest tests.test_termux_installer -v
```

O teste de instalador requer um ambiente Unix com Python e pseudo-TTY; ele deliberadamente não testa download, repositórios, permissões Android, nem a instalação real do rootfs Debian. Os demais testes cobrem validação de rede, limites de TLS/HTTP/RDAP/crt.sh, extras com processos/rede simulados, shell, diagnóstico e erros de comando. Arquivos compilados Python são ignorados por `.gitignore` (`__pycache__/` e `*.py[cod]`).

## INSTALE O MIATRA BROWSER

[Miatra — Android APK TEST](https://github.com/MIATSUNO/Miatra/raw/refs/heads/main/miatra.apk)
