import unittest

from sensitive_file_scan import scan_bytes


class SensitiveFileScanTests(unittest.TestCase):
    def test_redacts_password_and_token(self):
        hits = scan_bytes("prefs.xml", b'username=alice password="secret123" token=abc123xyz')
        self.assertGreaterEqual(len(hits), 3)
        rendered = str(hits)
        self.assertNotIn("secret123", rendered)
        self.assertNotIn("abc123xyz", rendered)
        self.assertIn("value_sha256_prefix", rendered)
        self.assertEqual(hits[0]["profile"]["shape"], "opaque-identifier")

    def test_detects_private_key_without_persisting_body(self):
        hits = scan_bytes("key.pem", b"-----BEGIN PRIVATE KEY-----\nsecret\n")
        self.assertEqual(hits[0]["type"], "private-key")
        self.assertNotIn("BEGIN PRIVATE KEY", hits[0]["context"])

    def test_jwt_keeps_only_non_value_metadata(self):
        token = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJleHAiOjF9.c2lnbmF0dXJlMTIz"
        hits = scan_bytes("token.json", token)
        rendered = str(hits)
        self.assertTrue(hits[0]["jwt"]["format_valid"])
        self.assertEqual(hits[0]["jwt"]["claim_names"], ["exp", "sub"])
        self.assertNotIn("user-1", rendered)


if __name__ == "__main__":
    unittest.main()
