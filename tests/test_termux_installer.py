"""Offline checks for install-termux.sh; no real pkg command is invoked."""
from __future__ import annotations

import os
import pty
import select
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install-termux.sh"


class TermuxInstallerOfflineTests(unittest.TestCase):
    def run_installer(self, replies: bytes, partial: bool = False) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            log = Path(temporary) / "pkg.log"
            # O PATH contém só este diretório: evita detectar curl/git/dig do host.
            for name, target in (("dirname", "/usr/bin/dirname"), ("chmod", "/bin/chmod")):
                helper = fake_bin / name
                helper.write_text(f"#!/bin/sh\nexec {target} \"$@\"\n", encoding="utf-8")
                helper.chmod(0o755)
            pkg = fake_bin / "pkg"
            pkg.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$PKG_LOG\"\n"
                "if [ \"$1\" = install ]; then\n"
                "  shift; [ \"$1\" = -y ] && shift\n"
                "  for package in \"$@\"; do\n"
                "    [ \"$FAKE_PARTIAL\" = 1 ] && [ \"$package\" = android-tools ] && continue\n"
                "    case \"$package\" in\n"
                "      nmap) executable=nmap ;; dnsutils) executable=dig ;; whois) executable=whois ;;\n"
                "      curl) executable=curl ;; git) executable=git ;; tor) executable=tor ;;\n"
                "      proot-distro) executable=proot-distro ;; android-tools) executable=adb ;;\n"
                "    esac\n"
                "    printf '#!/usr/bin/env sh\\nexit 0\\n' > \"$FAKE_BIN/$executable\"\n"
                "    chmod +x \"$FAKE_BIN/$executable\"\n"
                "  done\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            pkg.chmod(0o755)
            env = os.environ | {
                "PATH": str(fake_bin),
                "TERMUX_VERSION": "offline-test",
                "PREFIX": "/data/data/com.termux/files/usr",
                "PKG_LOG": str(log),
                "FAKE_BIN": str(fake_bin),
                "FAKE_PARTIAL": "1" if partial else "0",
            }
            master, slave = pty.openpty()
            try:
                process = subprocess.Popen(
                    ["/bin/sh", str(INSTALLER)],
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    env=env,
                    cwd=ROOT,
                    close_fds=True,
                )
                os.close(slave)
                os.write(master, replies)
                chunks: list[bytes] = []
                while process.poll() is None:
                    ready, _, _ = select.select([master], [], [], 0.1)
                    if ready:
                        try:
                            chunks.append(os.read(master, 4096))
                        except OSError:
                            break
                process.wait(timeout=5)
                while True:
                    ready, _, _ = select.select([master], [], [], 0)
                    if not ready:
                        break
                    try:
                        data = os.read(master, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    chunks.append(data)
                return process.returncode, b"".join(chunks).decode("utf-8", "replace"), log.read_text()
            finally:
                os.close(master)

    def test_installs_complete_package_set_and_keeps_debian_optional(self) -> None:
        code, output, log = self.run_installer(b"s\nn\n")
        self.assertEqual(code, 0, output)
        self.assertIn("update -y", log)
        self.assertIn("install -y nmap dnsutils whois curl git tor proot-distro android-tools", log)
        self.assertIn("Rootfs Debian não instalado", output)
        self.assertIn("Dependências Termux verificadas com sucesso", output)

    def test_partial_install_is_not_reported_as_success(self) -> None:
        code, output, log = self.run_installer(b"s\n", partial=True)
        self.assertEqual(code, 1, output)
        self.assertIn("install -y nmap dnsutils whois curl git tor proot-distro android-tools", log)
        self.assertIn("adb", output)
        self.assertIn("Instalação incompleta", output)
        self.assertNotIn("Dependências Termux verificadas com sucesso", output)


if __name__ == "__main__":
    unittest.main()
