import io
import json
import socket
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from miatrasx import miatra_network as network


class NetworkValidationTests(unittest.TestCase):
    def test_hostname_validation_rejects_urls_and_local_names(self):
        self.assertEqual(network.validate_hostname("ExAmple.org."), "example.org")
        for target in ("https://example.org", "localhost", "example.org:443", "bad host.org"):
            with self.subTest(target=target):
                with self.assertRaises(network.NetworkInputError):
                    network.validate_hostname(target)

    def test_dns_lookup_uses_socket_and_deduplicates(self):
        infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.8", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::8", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.8", 0)),
        ]
        with patch("miatrasx.miatra_network.socket.getaddrinfo", return_value=infos):
            result = network.dns_lookup("example.org", timeout=1)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["addresses"], ["198.51.100.8", "2001:db8::8"])

    def test_private_destinations_are_blocked_before_https_request(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("miatrasx.miatra_network.socket.getaddrinfo", return_value=infos):
            with self.assertRaisesRegex(network.NetworkInputError, "IP público"):
                network._https_get("https://example.org/", 1)

    def test_dns_timeout_does_not_change_process_default_timeout(self):
        started = threading.Event()
        release = threading.Event()

        def blocked_resolution(*_args, **_kwargs):
            started.set()
            release.wait(1)
            return []

        with patch("miatrasx.miatra_network.socket.getaddrinfo", side_effect=blocked_resolution), \
             patch("miatrasx.miatra_network.socket.setdefaulttimeout") as set_default:
            started_at = time.monotonic()
            with self.assertRaisesRegex(network.NetworkInputError, "excedeu o prazo"):
                network.dns_lookup("example.org", timeout=0.1)
            self.assertLess(time.monotonic() - started_at, 0.5)
            set_default.assert_not_called()
        release.set()

    def test_invalid_url_hostname_keeps_hostname_error(self):
        with self.assertRaisesRegex(network.NetworkInputError, "hostname inválido"):
            network.secure_http_headers("https://-bad.example/", timeout=1)

    def test_malformed_url_is_reported_as_input_error(self):
        with self.assertRaisesRegex(network.NetworkInputError, "URL inválida"):
            network.secure_http_headers("https://[bad", timeout=1)

    def test_http_url_is_not_accepted(self):
        with self.assertRaises(network.NetworkInputError):
            network.secure_http_headers("http://example.org", timeout=1)


class NetworkServiceTests(unittest.TestCase):
    def test_tls_certificate_uses_verified_context_and_sni(self):
        raw_socket = MagicMock()
        secure_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket
        secure_socket.__enter__.return_value = secure_socket
        secure_socket.getpeercert.return_value = {
            "subject": (("commonName", "example.org"),),
            "issuer": (("commonName", "Test CA"),),
            "serialNumber": "01",
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": "Jan 01 00:00:00 2027 GMT",
            "subjectAltName": (("DNS", "example.org"),),
        }
        secure_socket.version.return_value = "TLSv1.3"
        secure_socket.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
        context = MagicMock()
        context.wrap_socket.return_value = secure_socket
        with patch("miatrasx.miatra_network._public_addresses", return_value=["8.8.8.8"]), \
             patch("miatrasx.miatra_network.socket.create_connection", return_value=raw_socket), \
             patch("miatrasx.miatra_network.ssl.create_default_context", return_value=context):
            result = network.tls_certificate("example.org", timeout=1)
        self.assertTrue(result["verified"])
        self.assertEqual(result["subject_alt_names"], ["example.org"])
        self.assertEqual(context.verify_mode, network.ssl.CERT_REQUIRED)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="example.org")

    def test_headers_do_not_follow_a_redirect(self):
        with patch("miatrasx.miatra_network._https_get", return_value=(302, {"location": "https://127.0.0.1/"}, b"")) as request:
            result = network.secure_http_headers("https://example.org/start", timeout=1)
        self.assertTrue(result["redirected"])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.kwargs["method"], "HEAD")
        self.assertIn("strict-transport-security", result["missing_security_headers"])

    def test_tls_falls_back_to_second_validated_address(self):
        raw_socket = MagicMock()
        secure_socket = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value = secure_socket
        deadline = time.monotonic() + 1
        with patch("miatrasx.miatra_network.socket.create_connection", side_effect=[OSError("IPv6 indisponível"), raw_socket]) as connect:
            result = network._connect_tls("example.org", ["2001:4860:4860::8888", "8.8.8.8"], 443, deadline, context)
        self.assertIs(result, secure_socket)
        self.assertEqual(connect.call_count, 2)
        self.assertEqual(connect.call_args_list[0].args[0], ("2001:4860:4860::8888", 443))
        self.assertEqual(connect.call_args_list[1].args[0], ("8.8.8.8", 443))
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="example.org")

    def test_https_request_uses_host_with_nonstandard_port(self):
        response = MagicMock()
        response.status = 200
        response.read.return_value = b""
        response.getheaders.return_value = []
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch("miatrasx.miatra_network._public_addresses", return_value=["8.8.8.8"]), \
             patch("miatrasx.miatra_network.ssl.create_default_context"), \
             patch("miatrasx.miatra_network._PinnedHTTPSConnection", return_value=connection):
            network._https_get("https://example.org:8443/path", 1)
        self.assertEqual(connection.request.call_args.kwargs["headers"]["Host"], "example.org:8443")

    def test_rdap_uses_fixed_trusted_endpoint(self):
        payload = {"objectClassName": "domain", "ldhName": "example.org"}
        with patch("miatrasx.miatra_network._https_get", return_value=(200, {}, json.dumps(payload).encode())) as request:
            result = network.rdap_lookup("example.org", timeout=1)
        self.assertEqual(result["data"], payload)
        self.assertEqual(request.call_args.args[0], "https://rdap.org/domain/example.org")

    def test_crtsh_limits_and_deduplicates_results(self):
        records = [{"id": index, "name_value": f"{index}.example.org"} for index in range(205)]
        records.append({"id": 0, "name_value": "0.example.org"})
        with patch("miatrasx.miatra_network._https_get", return_value=(200, {}, json.dumps(records).encode())):
            result = network.crtsh_lookup("example.org", timeout=1)
        self.assertEqual(result["count"], network.MAX_CERTIFICATES)
        self.assertTrue(result["truncated"])


class NetworkCliTests(unittest.TestCase):
    def test_main_requires_explicit_authorization(self):
        with self.assertRaises(SystemExit) as exit_error, redirect_stdout(io.StringIO()):
            network.main(["dns", "example.org"])
        self.assertEqual(exit_error.exception.code, 2)

    def test_main_emits_authorization_notice_and_json(self):
        capture = io.StringIO()
        with patch("miatrasx.miatra_network.dns_lookup", return_value={"target": "example.org", "count": 1}):
            with redirect_stdout(capture):
                code = network.main(["--authorized", "--json", "dns", "example.org"])
        self.assertEqual(code, 0)
        self.assertIn(network.AUTHORIZATION_NOTICE, capture.getvalue())
        self.assertIn('"count": 1', capture.getvalue())


if __name__ == "__main__":
    unittest.main()
