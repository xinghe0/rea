import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import apk_triage


class ApkTriageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make_apk(self):
        apk = self.root / "fixture.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("classes.dex", b"dex")
            archive.writestr("lib/arm64-v8a/libil2cpp.so", b"elf")
            archive.writestr("lib/arm64-v8a/libunity.so", b"elf")
            archive.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"\xaf\x1b\xb1\xfa\x1d\x00\x00\x00")
            archive.writestr("assets/config.json", '{"url":"https://test.example.invalid/api"}')
            archive.writestr("assets/large.json", b"x" * (apk_triage.MAX_TEXT_ENTRY + 1))
        return apk

    def test_zip_scan_detects_unity_without_loading_large_text_entry(self):
        report = apk_triage.scan_zip(str(self.make_apk()))
        self.assertIn("Unity IL2CPP", report["engines"])
        self.assertEqual(report["abis"], ["arm64-v8a"])
        self.assertEqual(report["unity"]["metadata_size"], 8)
        self.assertEqual(report["skipped_text_entries"][0]["path"], "assets/large.json")
        self.assertIn("https://test.example.invalid/api", report["urls"])

    def test_manifest_parser_uses_decoded_aapt_output(self):
        badging = """package: name='com.example.game' versionCode='7' versionName='1.2.3'\nsdkVersion:'26'\ntargetSdkVersion:'35'\nuses-permission: name='android.permission.CAMERA'\n"""
        xml = """E: manifest\n  E: application\n    A: android:debuggable(0x0101000f)=(type 0x12)0x0\n    A: android:allowBackup(0x01010280)=(type 0x12)0xffffffff\n    A: android:usesCleartextTraffic(0x010104ec)=(type 0x12)0x0\n    A: android:networkSecurityConfig(0x01010527)=@0x7f120001\n    E: activity\n      A: android:name(0x01010003)=\"com.example.game.Entry\"\n      A: android:exported(0x01010010)=(type 0x12)0xffffffff\n      A: android:permission(0x01010006)=\"com.example.SIGNATURE\"\n"""
        with mock.patch.object(apk_triage, "run", side_effect=[(0, badging, ""), (0, xml, "")]):
            result = apk_triage.parse_manifest("fixture.apk", "/fake/aapt")
        self.assertEqual(result["package"], "com.example.game")
        self.assertFalse(result["debuggable"])
        self.assertTrue(result["allow_backup"])
        self.assertFalse(result["cleartext"])
        self.assertEqual(result["exported"][0]["permission"], "com.example.SIGNATURE")

    def test_signature_parser_reports_schemes_and_certificate(self):
        output = """Verifies\nVerified using v1 scheme (JAR signing): false\nVerified using v2 scheme (APK Signature Scheme v2): true\nVerified using v3 scheme (APK Signature Scheme v3): true\nSigner #1 certificate SHA-256 digest: deadbeef\n"""
        with mock.patch.object(apk_triage, "run", return_value=(0, output, "")):
            result = apk_triage.signature_info("fixture.apk", "/fake/apksigner")
        self.assertTrue(result["verified"])
        self.assertTrue(result["schemes"]["v2"])
        self.assertEqual(result["certificates"], ["deadbeef"])

    def test_no_packer_match_is_an_observation_not_a_vulnerability(self):
        archive = apk_triage.scan_zip(str(self.make_apk()))
        rows = apk_triage.observations({}, archive, {"verified": None, "schemes": {}})
        row = next(item for item in rows if item["id"] == "REV-001")
        self.assertEqual(row["status"], "observation")
        self.assertEqual(row["confidence"], "low")
        self.assertEqual(row["title"], "未匹配已知商业加固特征")

    def test_markdown_localizes_reader_facing_statuses(self):
        archive = apk_triage.scan_zip(str(self.make_apk()))
        signature = {"verified": None, "schemes": {}, "certificates": []}
        report = {
            "apk": "fixture.apk",
            "manifest": {
                "exported": [{"type": "activity", "name": "com.example.Entry", "permission": None}],
            },
            "archive": archive,
            "signature": signature,
        }
        report["observations"] = apk_triage.observations({}, archive, signature)
        text = apk_triage.markdown(report)
        self.assertIn("# 未知包名 静态分诊报告", text)
        self.assertIn("| REV-001 | 观察项 | 低 |", text)
        self.assertIn("## Manifest 摘要", text)
        self.assertIn("`networkSecurityConfig`：`未设置`", text)
        self.assertIn("权限=`未设置`", text)
        self.assertNotIn("| observation | low |", text)
        self.assertNotIn("权限=`None`", text)


if __name__ == "__main__":
    unittest.main()
