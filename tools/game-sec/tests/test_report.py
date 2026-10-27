import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from game_sec_core import init_case, make_finding, replace_findings, write_json
from report_gen import render


class ReportTests(unittest.TestCase):
    def test_report_separates_findings_observations_and_untested_controls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            apk.write_bytes(b"sample")
            case = root / "case"
            init_case(case, apk, "com.example.game", "test", [], ["static"], None)
            evidence = case / "evidence/raw/repro.txt"
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text("reproduced\n", encoding="utf-8")
            replace_findings(case, [
                make_finding(
                    "G-001", "已确认测试问题", "confirmed", "high", 3, 4,
                    "已复现", ["evidence/raw/repro.txt"], "修复问题", "重复测试",
                    section="client.component-security"),
                make_finding(
                    "G-002", "较低评级观察项", "observation", "medium", 2, 3,
                    "需要上下文", ["evidence/raw/repro.txt"], "复核问题", "重复复核",
                    section="client.file-security"),
            ])
            triage = case / "evidence/derived/triage"
            triage.mkdir(parents=True)
            write_json(triage / "com.example.game_triage.json", {
                "observations": [
                    {"id": "G-001", "status": "not-tested", "confidence": "low",
                     "title": "过期重复项", "detail": "必须被抑制"},
                    {"id": "REV-001", "status": "observation", "confidence": "low",
                     "title": "未发现加固特征", "detail": "不能证明不存在保护"},
                ]})
            text = render(case)
            self.assertIn("G-001：已确认测试问题", text)
            self.assertIn("最高风险等级：`高`", text)
            self.assertLess(text.index("## 一、客户端安全"), text.index("## 二、应用层安全"))
            self.assertLess(text.index("## 二、应用层安全"), text.index("## 三、总结"))
            self.assertLess(text.index("### 组件安全"), text.index("G-001：已确认测试问题"))
            self.assertLess(text.index("### 文件安全"), text.index("G-002：较低评级观察项"))
            self.assertEqual(text.count("G-001：已确认测试问题"), 1)
            self.assertEqual(text.count("G-002：较低评级观察项"), 1)
            self.assertNotIn("过期重复项", text)
            self.assertIn("自动化静态观察", text)
            self.assertIn("未测试", text)
            self.assertIn("[evidence/raw/repro.txt](evidence/raw/repro.txt)", text)
            self.assertIn("不能证明不存在保护", text)

    def test_report_derives_completed_dynamic_states_from_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            apk.write_bytes(b"sample")
            case = root / "case"
            init_case(case, apk, "com.example.game", "test", [], ["static"], None)
            device = case / "evidence/raw/device"
            device.mkdir(parents=True)
            (device / "manifest.json").write_text("{}\n", encoding="utf-8")
            (device / "activity_h5_probe.txt").write_text("Status: ok\n", encoding="utf-8")
            frida = case / "evidence/raw/frida"
            frida.mkdir(parents=True)
            (frida / "probe.jsonl").write_text(
                '{"type":"driver.start","timeout":30}\n'
                '{"type":"driver.loaded"}\n{"type":"driver.stop"}\n', encoding="utf-8")
            (frida / "failed.jsonl").write_text(
                '{"type":"driver.start","timeout":60}\n'
                '{"type":"driver.loaded"}\n{"type":"driver.stop"}\n'
                '{"type":"driver.error"}\n', encoding="utf-8")
            (case / "timeline.jsonl").write_text(
                '{"time":"2026-01-01T00:00:00+00:00","event":"dynamic.repack","status":"ok","command":"repack"}\n',
                encoding="utf-8",
            )
            text = render(case)
            self.assertIn("文件名、权限和脱敏日志基线：已执行有界检查", text)
            self.assertIn("导出 H5 Activity 设备启动验证：已执行", text)
            self.assertIn("Root、调试器与插桩行为：已执行有界观察", text)
            self.assertNotIn("重打包与签名自检", text)
            self.assertNotIn("dynamic.repack", text)

    def test_report_is_generic_for_static_only_cases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            apk.write_bytes(b"sample")
            case = root / "case"
            init_case(case, apk, "com.example.game", "test", [], ["static"], None)
            text = render(case)
            self.assertIn("可复现的静态分析", text)
            self.assertNotIn("Pixel 8 Pro", text)
            self.assertNotIn("Google Play Games", text)
            self.assertNotIn("pic_error_742.zip", text)
            self.assertIn("登录与会话生命周期：未发现案件内运行证据", text)
            self.assertIn("游戏核心业务及经济系统的后端权威校验：**不在本次测试范围**", text)
            self.assertIn("稳定性与兼容性", text)
            self.assertIn("结论为**未测试**", text)

    def test_report_rejects_unknown_section(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            apk.write_bytes(b"sample")
            case = root / "case"
            init_case(case, apk, "com.example.game", "test", [], ["static"], None)
            evidence = case / "evidence/raw/repro.txt"
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text("reproduced\n", encoding="utf-8")
            finding = make_finding(
                "G-001", "测试问题", "observation", "low", 1, 1,
                "摘要", ["evidence/raw/repro.txt"], "修复", "回归")
            finding["section"] = "client.unknown"
            replace_findings(case, [finding])
            with self.assertRaises(ValueError):
                render(case)

    def test_report_rejects_missing_or_escaping_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            apk.write_bytes(b"sample")
            case = root / "case"
            init_case(case, apk, "com.example.game", "test", [], ["static"], None)
            for evidence in ("evidence/raw/missing.txt", "../outside.txt"):
                replace_findings(case, [make_finding(
                    "G-001", "错误证据", "confirmed", "high", 3, 4,
                    "已复现", [evidence], "修复问题", "重复测试")])
                with self.assertRaises((FileNotFoundError, ValueError)):
                    render(case)


if __name__ == "__main__":
    unittest.main()
