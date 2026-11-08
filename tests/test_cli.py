import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from miatrasx.cli import interactive_shell, main, prompt_for
from miatrasx.diagnostics import system_report


class CliTests(unittest.TestCase):
    def test_prompt_contains_directory_and_brand(self):
        value = prompt_for("/tmp/projeto")
        self.assertIn('"projeto"', value)
        self.assertIn('"/tmp/projeto"', value)
        self.assertIn("Miatras-x", value)

    def test_shell_cd_is_persistent_during_session(self):
        original = os.getcwd()
        responses = iter(["cd /tmp", "pwd", "exit"])
        seen = []
        try:
            interactive_shell(lambda _: next(responses), seen.append)
            self.assertIn("/tmp", seen)
        finally:
            os.chdir(original)

    def test_diagnostics_is_local(self):
        report = system_report()
        self.assertIn("Python:", report)
        self.assertIn("Ferramentas disponíveis:", report)

    def test_unknown_command_is_handled(self):
        responses = iter(["comando-que-nao-existe-miatras", "exit"])
        seen = []
        with patch("miatrasx.cli.subprocess.run", side_effect=FileNotFoundError):
            interactive_shell(lambda _: next(responses), seen.append)
        self.assertIn("Comando não encontrado: comando-que-nao-existe-miatras", seen)

    def test_main_without_arguments_does_not_block_without_tty(self):
        capture = io.StringIO()
        with patch("miatrasx.cli.sys.stdin.isatty", return_value=False), redirect_stdout(capture):
            self.assertEqual(0, main([]))
        self.assertIn("Miatras-X", capture.getvalue())
        self.assertIn("Comandos Miatras-X", capture.getvalue())

    def test_rede_forwards_all_extension_arguments_in_order(self):
        with patch("miatrasx.cli.miatra_network.main", return_value=0) as network_main:
            self.assertEqual(0, main(["rede", "--authorized", "dns", "example.org"]))
        network_main.assert_called_once_with(["--authorized", "dns", "example.org"])

    def test_extras_are_available_in_main_cli_and_shell(self):
        with patch("miatrasx.cli.miatra_extras.main", return_value=0) as extras_main:
            self.assertEqual(0, main(["extras", "feeds", "bbc-mundo"]))
        extras_main.assert_called_once_with(["feeds", "bbc-mundo"])
        responses = iter(["extra feeds", "exit"])
        with patch("miatrasx.cli.miatra_extras.main", return_value=0) as extras_main:
            self.assertEqual(0, interactive_shell(lambda _: next(responses), lambda _: None))
        extras_main.assert_called_once_with(["feeds"])

    def test_shell_nmap_accepts_long_flag_and_legacy_port_argument(self):
        responses = iter(["nmap exemplo.interno --portas 80", "nmap exemplo.interno 443", "exit"])
        with patch("miatrasx.cli.tools.nmap", return_value=0) as nmap:
            self.assertEqual(0, interactive_shell(lambda _: next(responses), lambda _: None))
        self.assertEqual(
            [("exemplo.interno", "80"), ("exemplo.interno", "443")],
            [call.args for call in nmap.call_args_list],
        )

    def test_shell_nmap_accepts_short_flag(self):
        responses = iter(["nmap exemplo.interno -p 53", "exit"])
        with patch("miatrasx.cli.tools.nmap", return_value=0) as nmap:
            interactive_shell(lambda _: next(responses), lambda _: None)
        nmap.assert_called_once_with("exemplo.interno", "53")

    def test_shell_nmap_reports_invalid_arguments_and_keeps_running(self):
        responses = iter(["nmap exemplo.interno --desconhecida 80", "nmap exemplo.interno 80 extra", "pwd", "exit"])
        seen = []
        with patch("miatrasx.cli.tools.nmap") as nmap:
            self.assertEqual(0, interactive_shell(lambda _: next(responses), seen.append))
        nmap.assert_not_called()
        self.assertTrue(any("Opção desconhecida para nmap: --desconhecida" in line for line in seen))
        self.assertTrue(any("Argumento desconhecido para nmap: extra" in line for line in seen))
        self.assertIn(os.getcwd(), seen)

    def test_main_nmap_accepts_legacy_positional_port(self):
        with patch("miatrasx.cli.tools.nmap", return_value=0) as nmap:
            self.assertEqual(0, main(["nmap", "exemplo.interno", "80"]))
        nmap.assert_called_once_with("exemplo.interno", "80")


if __name__ == "__main__":
    unittest.main()
