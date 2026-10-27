import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from unity_il2cpp import render, run_dumper


class UnityIl2CppTests(unittest.TestCase):
    def test_completed_outputs_survive_known_terminal_read_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "dumper"
            output.mkdir()
            (output / "DummyDll").mkdir()
            for name in ("dump.cs", "il2cpp.h", "script.json", "stringliteral.json"):
                (output / name).write_text("fixture\n", encoding="utf-8")
            result = subprocess.CompletedProcess(
                [], -6, stdout="Done!\nPress any key to exit...",
                stderr="Unhandled exception. Cannot read keys when application does not have a console.")
            with patch("unity_il2cpp.subprocess.run", return_value=result):
                report = run_dumper(["dotnet", "Il2CppDumper.dll"],
                                    root / "libil2cpp.so", root / "metadata.dat", output)
            self.assertTrue(report["completed"])
            self.assertTrue(report["known_terminal_error"])
            self.assertEqual(report["return_code"], -6)

    def test_missing_outputs_are_not_completed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "dumper"
            output.mkdir()
            result = subprocess.CompletedProcess([], 1, stdout="failed", stderr="error")
            with patch("unity_il2cpp.subprocess.run", return_value=result):
                report = run_dumper(["dumper"], root / "binary", root / "metadata", output)
            self.assertFalse(report["completed"])
            self.assertFalse(report["known_terminal_error"])

    def test_render_localizes_boolean_summary_values(self):
        report = {
            "apk_sha256": "deadbeef",
            "abi": "arm64-v8a",
            "metadata_version": {"version": 31, "magic_valid": True},
            "dumper": {"completed": True},
            "files": {},
            "candidates": {},
        }
        text = render(report)
        self.assertIn("Metadata magic 校验有效：`是`", text)
        self.assertIn("已执行 Il2CppDumper：`是`", text)
        self.assertIn("Il2CppDumper 输出完整：`是`", text)
        self.assertNotIn("：`True`", text)


if __name__ == "__main__":
    unittest.main()
