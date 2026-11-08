"""Testes offline dos extras: processos e rede são sempre simulados."""
import subprocess
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from miatrasx import miatra_extras as extras


class ExtrasTests(unittest.TestCase):
    def test_debian_install_requires_explicit_confirmation(self):
        seen = []
        with patch.object(extras, "_has_command") as has_command:
            code = extras.debian_install(False, seen.append)
        self.assertEqual(3, code)
        has_command.assert_not_called()
        self.assertIn("--confirmar", seen[0])

    def test_debian_install_uses_only_proot_distro_command(self):
        seen = []
        completed = subprocess.CompletedProcess([], 0)
        with patch.object(extras, "_has_command", return_value=True):
            code = extras.debian_install(True, seen.append, run=MagicMock(return_value=completed))
        self.assertEqual(0, code)
        self.assertIn("proot-distro install debian", " ".join(seen))

    def test_debian_status_reports_existing_installation(self):
        seen = []
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(extras, "_has_command", return_value=True), patch.object(extras.subprocess, "run", return_value=completed) as run:
            code = extras.debian_status(seen.append)
        self.assertEqual(0, code)
        self.assertEqual(["proot-distro", "login", "debian", "--", "true"], run.call_args.args[0])
        self.assertIn("pronto", seen[0])

    def test_tor_start_explains_limits_and_foreground(self):
        seen = []
        runner = MagicMock(return_value=subprocess.CompletedProcess([], 0))
        with patch.object(extras, "_has_command", return_value=True):
            code = extras.tor_start(seen.append, runner)
        self.assertEqual(0, code)
        self.assertTrue(any("primeiro plano" in line for line in seen))
        self.assertTrue(any("não anonimiza" in line for line in seen))
        self.assertEqual(["tor"], runner.call_args.args[0])

    def test_git_and_adb_pass_literal_argument_vectors(self):
        runner = MagicMock(return_value=subprocess.CompletedProcess([], 0))
        with patch.object(extras, "_has_command", return_value=True):
            self.assertEqual(0, extras.git(["status", "--short"], run=runner))
            self.assertEqual(0, extras.adb(["shell", "id"], run=runner))
        self.assertEqual(["git", "status", "--short"], runner.call_args_list[0].args[0])
        self.assertEqual(["adb", "shell", "id"], runner.call_args_list[1].args[0])

    def test_feed_is_parsed_offline_with_https_request_and_timeout(self):
        body = b"<rss><channel><item><title>Noticia segura</title><link>https://example.test/a</link></item></channel></rss>"
        response = MagicMock()
        response.read.return_value = body
        response.__enter__.return_value = response
        seen = []
        opener = MagicMock(return_value=response)
        code = extras.fetch_feed("bbc-mundo", 1, seen.append, opener)
        self.assertEqual(0, code)
        request = opener.call_args.args[0]
        self.assertTrue(request.full_url.startswith("https://"))
        self.assertEqual(10, opener.call_args.kwargs["timeout"])
        self.assertIn("Noticia segura", "\n".join(seen))

    def test_feed_network_error_is_useful(self):
        seen = []
        code = extras.fetch_feed("bbc-mundo", output=seen.append, opener=MagicMock(side_effect=URLError("offline")))
        self.assertEqual(1, code)
        self.assertIn("Verifique a rede", seen[0])

    def test_feed_accepts_namespaced_rss(self):
        body = b'''<?xml version="1.0"?>
        <rss xmlns="https://example.test/rss"><channel><item>
          <title>RSS com namespace</title><link>https://example.test/rss-item</link>
        </item></channel></rss>'''
        response = MagicMock()
        response.read.return_value = body
        response.__enter__.return_value = response
        seen = []
        self.assertEqual(0, extras.fetch_feed("bbc-mundo", output=seen.append, opener=MagicMock(return_value=response)))
        self.assertIn("RSS com namespace", "\n".join(seen))
        self.assertIn("https://example.test/rss-item", "\n".join(seen))

    def test_atom_uses_alternate_link_even_when_not_first(self):
        body = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry>
          <title>Entrada Atom</title>
          <link rel="self" href="https://example.test/api/1" />
          <link rel="alternate" href="https://example.test/article/1" />
        </entry></feed>'''
        response = MagicMock()
        response.read.return_value = body
        response.__enter__.return_value = response
        seen = []
        self.assertEqual(0, extras.fetch_feed("bbc-mundo", output=seen.append, opener=MagicMock(return_value=response)))
        rendered = "\n".join(seen)
        self.assertIn("Entrada Atom", rendered)
        self.assertIn("https://example.test/article/1", rendered)
        self.assertNotIn("https://example.test/api/1", rendered)

    def test_feed_keeps_byte_limit_before_xml_parse(self):
        response = MagicMock()
        response.read.return_value = b"x" * (extras.MAX_FEED_BYTES + 1)
        response.__enter__.return_value = response
        seen = []
        self.assertEqual(1, extras.fetch_feed("bbc-mundo", output=seen.append, opener=MagicMock(return_value=response)))
        response.read.assert_called_once_with(extras.MAX_FEED_BYTES + 1)
        self.assertIn("excede o limite seguro", seen[0])

    def test_feed_rejects_doctype_and_entity_before_parsing(self):
        body = b'''<!DOCTYPE rss [<!ENTITY bomb "never parse this">]>
        <rss><channel><item><title>&bomb;</title></item></channel></rss>'''
        response = MagicMock()
        response.read.return_value = body
        response.__enter__.return_value = response
        seen = []
        self.assertEqual(1, extras.fetch_feed("bbc-mundo", output=seen.append, opener=MagicMock(return_value=response)))
        self.assertIn("DOCTYPE ou ENTITY", seen[0])

    def test_feed_rejects_entity_declaration_without_doctype(self):
        body = b'<!ENTITY unsafe "x"><rss />'
        response = MagicMock()
        response.read.return_value = body
        response.__enter__.return_value = response
        seen = []
        self.assertEqual(1, extras.fetch_feed("bbc-mundo", output=seen.append, opener=MagicMock(return_value=response)))
        self.assertIn("DOCTYPE ou ENTITY", seen[0])

    def test_main_does_not_fetch_without_named_feed(self):
        with patch.object(extras, "fetch_feed") as fetch, patch("builtins.print"):
            self.assertEqual(0, extras.main(["feeds"]))
        fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
