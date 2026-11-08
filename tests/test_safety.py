import unittest

from miatrasx.safety import valid_port_spec, valid_target, valid_url


class SafetyTests(unittest.TestCase):
    def test_accepts_simple_targets(self):
        self.assertTrue(valid_target("example.org"))
        self.assertTrue(valid_target("192.0.2.1"))

    def test_rejects_injection_like_target(self):
        self.assertFalse(valid_target("example.org; id"))
        self.assertFalse(valid_target("--script=default"))

    def test_port_limits(self):
        self.assertTrue(valid_port_spec("443"))
        self.assertTrue(valid_port_spec("80-100"))
        self.assertFalse(valid_port_spec("1-2000"))
        self.assertFalse(valid_port_spec("abc"))

    def test_http_urls_only(self):
        self.assertTrue(valid_url("https://example.org/status"))
        self.assertFalse(valid_url("file:///etc/passwd"))
        self.assertFalse(valid_url("notaurl"))


if __name__ == "__main__":
    unittest.main()
