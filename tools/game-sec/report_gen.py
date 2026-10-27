#!/usr/bin/env python3
"""从 game-sec 案件生成可追溯的中文 Markdown 报告。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from game_sec_core import VALID_REPORT_SECTIONS, evidence_manifest, read_json


STATUS_LABELS = {
    "confirmed": "已确认",
    "likely": "高可能",
    "observation": "观察项",
    "not-observed": "未观察到",
    "not-tested": "未测试",
}
STATUS_ORDER = ("confirmed", "likely", "observation", "not-observed", "not-tested")
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "信息",
    "none": "无",
}
CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低"}
BOOL_LABELS = {True: "是", False: "否", None: "未知"}
REPORT_SECTIONS = (
    ("client.code-hardening", "### 代码加固"),
    ("client.component-security", "### 组件安全"),
    ("client.file-security", "### 文件安全"),
    ("client.dynamic-debugging", "### 动态调试"),
    ("client.reverse-engineering", "### 逆向破解"),
    ("application.functional-testing", "### 功能测试"),
    ("application.game-security", "### 游戏安全"),
)


def highest_severity(findings: list[dict]) -> str:
    if not findings:
        return "none"
    return max(findings, key=lambda item: item.get("risk_score", 0))["severity"]


def load_optional(path: Path, default):
    return read_json(path) if path.exists() else default


def evidence_link(case: Path, relative: str) -> str:
    target = (case / relative).resolve()
    try:
        target.relative_to(case.resolve())
    except ValueError as exc:
        raise ValueError(f"证据路径越出案件目录：{relative}") from exc
    if not target.is_file():
        raise FileNotFoundError(f"问题项引用的证据不存在：{relative}")
    return f"[{relative}]({relative})"


def optional_evidence_link(case: Path, relative: str) -> str | None:
    return evidence_link(case, relative) if (case / relative).is_file() else None


def timeline_rows(case: Path) -> list[dict]:
    path = case / "timeline.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row.get("event") == "dynamic.repack":
                continue
            rows.append(row)
    return rows


def completed_frida_probe(case: Path) -> str | None:
    root = case / "evidence/raw/frida"
    if not root.exists():
        return None
    completed = []
    for path in sorted(root.glob("*.jsonl")):
        rows = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        event_types = {row.get("type") for row in rows}
        if ({"driver.loaded", "driver.stop"}.issubset(event_types)
                and "driver.error" not in event_types):
            timeout = next((row.get("timeout", 0) for row in rows
                            if row.get("type") == "driver.start"), 0)
            completed.append((timeout, path))
    if not completed:
        return None
    return str(max(completed, key=lambda item: item[0])[1].relative_to(case))


def finding_section(finding: dict) -> str:
    section = finding.get("section", "application.game-security")
    if section not in VALID_REPORT_SECTIONS:
        raise ValueError(f"问题项 {finding.get('id')} 使用了未知报告章节：{section}")
    return section


def render_finding(case: Path, finding: dict) -> list[str]:
    evidence = finding.get("evidence", [])
    links = "、".join(evidence_link(case, item) for item in evidence) or "无"
    reproduction = finding.get("reproduction", [])
    severity = SEVERITY_LABELS.get(finding["severity"], finding["severity"])
    confidence = CONFIDENCE_LABELS.get(finding["confidence"], finding["confidence"])
    lines = [
        f"#### {finding['id']}：{finding['title']}",
        "",
        f"- 状态：**{STATUS_LABELS.get(finding['status'], finding['status'])}**",
        f"- 严重度：**{severity}**（{finding['likelihood']} × {finding['impact']} = {finding['risk_score']}）",
        f"- 证据置信度：**{confidence}**",
        f"- 测试结论：{finding['summary']}",
    ]
    if finding.get("impact_narrative"):
        lines.append(f"- 安全影响：{finding['impact_narrative']}")
    lines.append(f"- 测试证据：{links}")
    if reproduction:
        lines += ["", "复现步骤：", ""]
        lines.extend(f"{index}. {step}" for index, step in enumerate(reproduction, 1))
    lines += [
        "",
        f"修复建议：{finding['remediation']}",
        "",
        f"回归标准：{finding['retest']}",
        "",
    ]
    return lines


def render_section_findings(case: Path, findings: list[dict], section: str) -> list[str]:
    selected = [item for item in findings if finding_section(item) == section]
    if not selected:
        return ["本节未形成独立问题项；这表示当前证据不足以形成问题结论，不代表该领域已验证安全。", ""]
    lines = []
    for status in STATUS_ORDER:
        for finding in selected:
            if finding["status"] == status:
                lines += render_finding(case, finding)
    return lines


def render(case: Path) -> str:
    case = case.resolve()
    scope = read_json(case / "scope.json")
    findings_doc = load_optional(case / "findings.json", {"findings": []})
    findings = findings_doc["findings"]
    for finding in findings:
        finding_section(finding)
    triage_files = list((case / "evidence/derived/triage").glob("*_triage.json"))
    triage = load_optional(triage_files[0], {}) if triage_files else {}
    unity = load_optional(case / "evidence/derived/unity/unity_inventory.json", {})
    manifest = evidence_manifest(case)
    timeline = timeline_rows(case)
    target = scope["target"]
    archive = triage.get("archive", {})
    engines = archive.get("engines", [])
    engine_text = "、".join(engines) or "未识别"
    signature = triage.get("signature", {})
    device_evidence = "evidence/raw/device/manifest.json"
    device_done = (case / device_evidence).is_file()
    h5_evidence_candidates = (
        "evidence/raw/device/component_probe/integrate_debug_h5_probe.json",
        "evidence/raw/device/activity_h5_probe.txt",
    )
    h5_evidence = next((path for path in h5_evidence_candidates if (case / path).is_file()), h5_evidence_candidates[0])
    h5_done = (case / h5_evidence).is_file()
    h5_screenshot = "evidence/raw/device/component_probe/integrate_debug_h5_data_url.png"
    frida_evidence = completed_frida_probe(case)
    frida_done = frida_evidence is not None
    security_review = optional_evidence_link(case, "evidence/derived/unity/security_review.md")
    sensitive_scan_path = case / "evidence/raw/device/sensitive_content_scan.json"
    sensitive_scan = load_optional(sensitive_scan_path, {})
    highest = highest_severity(findings)
    findings_by_id = {item["id"]: item for item in findings}
    methods = "静态分析"
    if device_done:
        methods += "和经授权的只读设备验证"
    if frida_done:
        methods += "，并执行了有界运行时观察"

    lines = [
        "# 【zjom】安全测试报告",
        "",
        f"> 测试环境：{scope['environment']}",
        ">",
        f"> 应用版本：{triage.get('manifest', {}).get('version_name', '未知')}（{triage.get('manifest', {}).get('version_code', '未知')}）",
        ">",
        f"> 应用包名：{target['package']}",
        ">",
        f"> 开发引擎：{engine_text}",
        ">",
        f"> 测试设备：{', '.join(scope.get('devices', [])) or '未使用设备'}",
        ">",
        f"> 测试账号：{scope.get('account_label') or '未使用'}（不记录账号凭据）",
        "",
        "## 评估说明",
        "",
        f"本次对目标 APK 执行了可复现的{methods}。报告结构对齐参考人工报告，结论仍严格区分已确认、观察项、未观察到和未测试；静态关键词、UI 数值变化或工具可用性不会直接升级为漏洞或服务端成功。",
        "",
        f"- APK SHA-256：`{target['apk_sha256']}`",
        f"- APK 大小：`{archive.get('size', '未知')}` 字节",
        f"- 已确认问题：`{sum(item['status'] == 'confirmed' for item in findings)}` 项",
        f"- 观察项：`{sum(item['status'] in ('likely', 'observation') for item in findings)}` 项",
        f"- 最高风险等级：`{SEVERITY_LABELS.get(highest, highest)}`",
        "- 测试范围：客户端与安装包、本地文件与数据、资源与热更新、登录/账号/会话、协议与服务端输入安全。",
        "- 不在范围：游戏核心业务安全（货币、商城、奖励、战斗、充值等）和稳定性/兼容性测试；另禁止拒绝服务、批量账号、真实支付、破坏性状态修改、生产环境滥用和审计规避。",
        "",
        "## 一、客户端安全",
        "",
        "### 代码加固",
        "",
    ]

    triage_link = evidence_link(case, str(triage_files[0].relative_to(case))) if triage_files else "无"
    dumper = unity.get("dumper", {})
    outputs = set(dumper.get("outputs_present", []))
    dumper_done = dumper.get("completed")
    if dumper_done is None:
        dumper_done = {"DummyDll", "dump.cs", "il2cpp.h", "script.json", "stringliteral.json"}.issubset(outputs)
    lines += [
        f"- Java/Android 静态分诊：{'已执行' if triage_files else '未测试'}；证据：{triage_link}",
        f"- Unity IL2CPP 恢复：{'Il2CppDumper 必需输出完整' if dumper_done else '未完成或不适用'}。能够恢复类型和方法不等于已确认漏洞。",
        f"- 原始 APK 签名：{'验证通过' if signature.get('verified') else '未验证'}；签名方案：`{', '.join(name for name, enabled in signature.get('schemes', {}).items() if enabled) or '未知'}`。应用运行时签名自检另行测试。",
        "",
    ]
    lines += render_section_findings(case, findings, "client.code-hardening")

    lines += ["### 组件安全", ""]
    lines += render_section_findings(case, findings, "client.component-security")
    lines += [
        f"- 导出 H5 Activity 设备启动验证：{'已执行' if h5_done else '未测试'}；证据：{evidence_link(case, h5_evidence) if h5_done else '无'}",
        *( ["", "复现截图：", "", f"![导出 H5 Activity 加载受控 URL]({h5_screenshot})"] if (case / h5_screenshot).is_file() else [] ),
        "",
        "### 文件安全",
        "",
    ]
    lines += render_section_findings(case, findings, "client.file-security")
    lines += [
        f"- 公私有目录敏感内容扫描：{'已执行脱敏扫描' if sensitive_scan else '未测试'}；检查文件 `{sensitive_scan.get('files_examined', 0)}` 个，命中文件 `{sensitive_scan.get('files_with_hits', 0)}` 个，命中特征 `{sensitive_scan.get('hit_count', 0)}` 个；证据：{evidence_link(case, 'evidence/raw/device/sensitive_content_scan.json') if sensitive_scan else '无'}。命中需人工复核语义，空结果不代表不存在未知格式或加密存储的敏感数据。",
        f"- 文件名、权限和脱敏日志基线：{'已执行有界检查' if device_done else '未测试'}；证据：{evidence_link(case, device_evidence) if device_done else '无'}。",
        "",
        "### 动态调试",
        "",
    ]
    lines += render_section_findings(case, findings, "client.dynamic-debugging")
    lines += [
        f"- Root、调试器与插桩行为：{'已执行有界观察' if frida_done else '未测试'}；证据：{evidence_link(case, frida_evidence) if frida_done else '无'}。本报告不要求也未执行反调试绕过。",
        "",
        "### 逆向破解",
        "",
    ]
    lines += render_section_findings(case, findings, "client.reverse-engineering")
    if security_review:
        lines += [f"- Unity 网络、资源、热更新、账号和支付静态边界已形成专项审查：{security_review}", ""]

    lines += [
        "## 二、应用层安全",
        "",
        "### 功能测试",
        "",
    ]
    lines += render_section_findings(case, findings, "application.functional-testing")
    if security_review:
        lines += [
            "- 登录：已完成 SDK 和回调边界的静态定位；未执行测试账号登录、令牌生命周期、退出登录、换号或跨端会话验证，结论为**未测试**。",
            "- 支付、经济系统与游戏核心业务：**不在本次测试范围**。",
            "",
        ]
    else:
        lines += [
            "- 登录与会话生命周期：未发现案件内运行证据，结论为**未测试**。",
            "- 支付、经济系统与游戏核心业务：**不在本次测试范围**。",
            "",
        ]
    lines += [
        "### 游戏安全",
        "",
    ]
    lines += render_section_findings(case, findings, "application.game-security")
    if security_review:
        lines.append("- 协议加密情况：已定位 socket/消息/序列化静态边界；未采集登录后运行时载荷，不能判断业务协议正文是否为明文，结论为**未测试**。")
    else:
        lines.append("- 协议加密情况：未发现案件内运行时载荷或序列化边界证据，结论为**未测试**。")
    lines += [
        "- 游戏核心业务及经济系统的后端权威校验：**不在本次测试范围**。",
        "- 重放与序列保护：未执行请求重放；结论为**未测试**。",
        "",
        "## 三、总结",
        "",
        f"本次评估确认 `{target['package']}` 存在 {sum(item['status'] == 'confirmed' for item in findings)} 项可复现问题，并形成 {sum(item['status'] in ('likely', 'observation') for item in findings)} 项需要运行时或服务端上下文的观察项。客户端静态分析{'、组件设备验证和文件基线' if device_done else ''}{'、有界动态观察' if frida_done else ''}已有案件证据；登录、会话和协议正文仍待动态验证，不能据此评价为安全。游戏核心业务和稳定性测试不在本次范围。",
        "",
        "### 人工报告测试项自动化覆盖",
        "",
        "| 人工报告测试项 | 当前工具与证据 | 自动化程度 | zjom 结论 |",
        "|---|---|---|---|",
        f"| Java/引擎代码反编译与加固识别 | APK triage、JADX、Il2CppDumper | 全自动静态 + 人工复核 | {'已完成静态分诊' if triage_files else '未测试'}；{'已完成 IL2CPP 恢复' if dumper_done else '引擎专项未完成或不适用'}；不以可恢复性单独判定漏洞 |",
        f"| 组件安全 | Manifest、JADX、scrcpy/ADB | 全自动静态 + 有界设备验证 | {findings_by_id['COMP-001']['summary'] if 'COMP-001' in findings_by_id else '依据已录入问题项和组件证据判断；未录入即不作安全结论'} |",
        f"| 文件安全 | 公私有目录敏感内容脱敏扫描、权限和日志基线 | 半自动 | {findings_by_id['FILE-001']['summary'] if 'FILE-001' in findings_by_id else ('已执行敏感内容扫描；未形成独立问题项' if sensitive_scan else '未测试')} |",
        f"| 动态调试 | IDA/JADX、Frida 只读探针 | 半自动 | {'已完成有界观察' if frida_done else '未测试'}；不执行绕过 |",
        f"| 逆向破解、资源与热更新 | Il2CppDumper、IDA、资源清单 | 全自动分诊 + 人工复核 | {'已形成专项静态审查；动态攻击路径未验证' if security_review else '未形成案件内专项证据'} |",
        f"| 登录功能 | SDK/回调静态定位、设备交互 | 需人工登录 | {'静态边界已定位；' if security_review else ''}未测试登录和会话生命周期 |",
        f"| 协议加密 | 序列化边界定位、Frida/代理观察 | 需登录后的半自动动态测试 | 未测试运行时协议正文 |",
        "| 游戏核心业务与经济系统 | 不执行 | 不在范围 | 不测试货币、商城、奖励、战斗、充值和业务账本 |",
        "| 稳定性与兼容性 | 不执行 | 不在范围 | 不测试性能、弱网稳定性、ANR、机型和系统版本兼容 |",
        "",
        "### 样本完整性",
        "",
        f"- 签名验证通过：`{BOOL_LABELS.get(signature.get('verified'), '未知')}`",
        f"- 签名方案：`{', '.join(name for name, enabled in signature.get('schemes', {}).items() if enabled) or '无'}`",
        f"- 证书 SHA-256：`{', '.join(signature.get('certificates', [])) or '未知'}`",
        f"- Source Stamp SHA-256：`{signature.get('source_stamp') or '未观察到'}`",
        "",
        "### 自动化静态观察",
        "",
        f"来源：{triage_link}",
        "",
        "| ID | 状态 | 置信度 | 观察结果 |",
        "|---|---|---|---|",
    ]
    finding_ids = {item["id"] for item in findings}
    observations = [
        item for item in triage.get("observations", [])
        if item.get("id") not in finding_ids
    ]
    for row in observations:
        detail = row["detail"].replace("|", "/")
        status = STATUS_LABELS.get(row["status"], row["status"])
        confidence = CONFIDENCE_LABELS.get(row["confidence"], row["confidence"])
        lines.append(f"| {row['id']} | {status} | {confidence} | {row['title']}：{detail} |")

    lines += [
        "",
        "### 限制与待验证项",
        "",
        "- 尚未执行测试账号登录、会话生命周期和协议正文捕获；不执行生产流量变异或请求重放。",
        "- 游戏核心业务、支付、经济系统、性能、稳定性和兼容性不在本次测试范围。",
        f"- 动态观察状态：{'存在成功的有界探针执行证据' if frida_done else '未测试'}；该状态不代表防护已被绕过或所有生命周期均已覆盖。",
        "- 未匹配特征或空文件列表均是有边界的观察结果，不代表控制或敏感数据不存在。",
        "- 登录、协议和服务端权威需要用户手工登录，并在现有 scope 之外对相应动作单独授权。",
        "",
        "### 测试时间线",
        "",
        "| 时间（UTC） | 事件 | 状态 | 命令 | 证据 |",
        "|---|---|---|---|---|",
    ]
    for row in timeline:
        command = row.get("command", "").replace("|", "/")
        evidence = "、".join(row.get("evidence", [])) or "-"
        lines.append(f"| {row.get('time')} | `{row.get('event')}` | `{row.get('status')}` | `{command}` | {evidence} |")

    lines += ["", "### 证据清单", "", "| 路径 | 大小（字节） | SHA-256 |", "|---|---:|---|"]
    for row in manifest:
        lines.append(f"| [{row['path']}]({row['path']}) | {row['size']} | `{row['sha256']}` |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case")
    args = parser.parse_args()
    case = Path(args.case).resolve()
    output = case / "report.md"
    output.write_text(render(case), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
