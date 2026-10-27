import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from game_sec_core import authorize, init_case, make_finding, risk_score, sha256_file


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.apk = self.root / "sample.apk"
        self.apk.write_bytes(b"authorized sample")
        self.case = self.root / "case"
        init_case(self.case, self.apk, "com.example.game", "test", ["device-1"],
                  ["static", "device-read"], "test-account")

    def tearDown(self):
        self.temp.cleanup()

    def test_authorize_matches_all_target_dimensions(self):
        case, scope = authorize(self.case, "device-read", apk=self.apk,
                                package="com.example.game", device="device-1")
        self.assertEqual(case, self.case.resolve())
        self.assertEqual(scope["target"]["apk_sha256"], sha256_file(self.apk))

    def test_authorize_rejects_action_package_device_and_hash(self):
        with self.assertRaises(PermissionError):
            authorize(self.case, "frida-observe")
        with self.assertRaises(PermissionError):
            authorize(self.case, "device-read", package="com.other.game")
        with self.assertRaises(PermissionError):
            authorize(self.case, "device-read", device="device-2")
        changed = self.root / "changed.apk"
        changed.write_bytes(b"different")
        with self.assertRaises(PermissionError):
            authorize(self.case, "static", apk=changed)

    def test_risk_matrix_and_finding_schema(self):
        self.assertEqual(risk_score(4, 4), (16, "high"))
        finding = make_finding(
            "G-001", "Test", "observation", "low", 2, 3,
            "summary", ["evidence/a.json"], "fix", "retest",
            section="client.component-security")
        self.assertEqual(finding["risk_score"], 6)
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["section"], "client.component-security")
        with self.assertRaises(ValueError):
            make_finding("G-002", "Bad", "unknown", "low", 1, 1, "", [], "", "")
        with self.assertRaises(ValueError):
            make_finding(
                "G-003", "Bad section", "observation", "low", 1, 1,
                "", [], "", "", section="client.unknown")
        findings = json.loads((self.case / "findings.json").read_text())
        self.assertEqual(findings["schema_version"], 2)

    def test_scope_contains_no_credential_field(self):
        scope = json.loads((self.case / "scope.json").read_text())
        serialized = json.dumps(scope).lower()
        self.assertNotIn("password", serialized)
        self.assertNotIn("access_token", serialized)


if __name__ == "__main__":
    unittest.main()
