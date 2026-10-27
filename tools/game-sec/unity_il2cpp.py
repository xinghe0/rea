#!/usr/bin/env python3
"""从 APK 提取 Unity IL2CPP 分析输入并生成清单。"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

from game_sec_core import sha256_file, write_json


METADATA = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
KEYWORDS = {
    "network": ["socket", "websocket", "http", "request", "response", "protobuf", "messagepack", "serialize"],
    "crypto": ["encrypt", "decrypt", "cipher", "aes", "xxtea", "signature", "certificate", "hmac"],
    "update": ["hotfix", "hotupdate", "assetbundle", "catalog", "download", "patch", "manifest"],
    "account": ["login", "account", "token", "session", "openid", "oauth"],
    "economy": ["currency", "diamond", "coin", "inventory", "reward", "purchase", "order", "payment"],
    "gameplay": ["battle", "damage", "cooldown", "speed", "result", "score", "rank"],
    "defense": ["anticheat", "root", "frida", "debugger", "integrity", "tamper", "emulator"],
}


def metadata_version(path: Path) -> dict:
    raw = path.read_bytes()[:8]
    if len(raw) < 8:
        return {"magic_valid": False, "version": None}
    magic, version = struct.unpack("<II", raw)
    return {"magic": f"0x{magic:08x}", "magic_valid": magic == 0xFAB11BAF, "version": version}


def extract_member(archive: zipfile.ZipFile, name: str, output: Path) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(name) as source, open(output, "wb") as target:
        shutil.copyfileobj(source, target, length=4 * 1024 * 1024)
    return {"path": str(output), "size": output.stat().st_size, "sha256": sha256_file(output)}


def candidate_lines(dump_cs: Path) -> dict[str, list[str]]:
    result = {category: [] for category in KEYWORDS}
    if not dump_cs.exists():
        return result
    with open(dump_cs, encoding="utf-8", errors="ignore") as source:
        for line in source:
            stripped = line.strip()
            lowered = stripped.lower()
            if not stripped or len(stripped) > 500:
                continue
            for category, words in KEYWORDS.items():
                if len(result[category]) < 300 and any(word in lowered for word in words):
                    result[category].append(stripped)
    return result


def resolve_dumper(path: str | None) -> list[str] | None:
    if not path:
        return None
    target = Path(path).resolve()
    if target.is_file() and target.suffix == ".dll":
        return ["dotnet", str(target)]
    if target.is_file():
        return [str(target)]
    dlls = list(target.glob("**/Il2CppDumper.dll"))
    return ["dotnet", str(dlls[0])] if dlls else None


def run_dumper(command: list[str], binary: Path, metadata: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    full = command + [str(binary), str(metadata), str(output)]
    required_outputs = {"DummyDll", "dump.cs", "il2cpp.h", "script.json", "stringliteral.json"}
    try:
        result = subprocess.run(full, capture_output=True, text=True, timeout=1800,
                                env={**os.environ, "DOTNET_ROLL_FORWARD": "LatestMajor"})
        outputs = sorted(path.name for path in output.iterdir())
        completed = required_outputs.issubset(outputs)
        known_terminal_error = (
            result.returncode != 0
            and completed
            and "Cannot read keys" in result.stderr
            and "Press any key to exit" in result.stdout
        )
        return {
            "command": full,
            "return_code": result.returncode,
            "completed": completed,
            "known_terminal_error": known_terminal_error,
            "stdout_tail": result.stdout[-4000:],
            "stderr_tail": result.stderr[-4000:],
            "outputs_present": outputs,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "command": full,
            "return_code": 127,
            "completed": False,
            "known_terminal_error": False,
            "error": str(exc),
            "outputs_present": [],
        }


def render(report: dict) -> str:
    category_labels = {
        "network": "网络",
        "crypto": "密码学",
        "update": "热更新",
        "account": "账号",
        "economy": "经济系统",
        "gameplay": "玩法与战斗",
        "defense": "运行时防护",
    }
    bool_labels = {True: "是", False: "否", None: "未知"}
    lines = ["# Unity IL2CPP 分析清单", "",
             f"- APK SHA-256：`{report['apk_sha256']}`",
             f"- ABI：`{report.get('abi')}`",
             f"- Metadata 版本：`{report['metadata_version'].get('version')}`",
             f"- Metadata magic 校验有效：`{bool_labels.get(report['metadata_version'].get('magic_valid'), '未知')}`",
             f"- 已执行 Il2CppDumper：`{bool_labels[bool(report.get('dumper'))]}`",
             f"- Il2CppDumper 输出完整：`{bool_labels[report.get('dumper', {}).get('completed', False)]}`", "",
             "## 已提取输入", ""]
    for name, item in report["files"].items():
        lines.append(f"- {name}：`{item['path']}`（{item['size']} 字节，`{item['sha256']}`）")
    lines += ["", "## 候选审查面", ""]
    for category, rows in report["candidates"].items():
        lines.append(f"### {category_labels.get(category, category)}（{len(rows)}）")
        lines.extend(f"- `{row}`" for row in rows[:50])
        lines.append("")
    lines += ["## 解释边界", "",
              "- APK 中包含 IL2CPP metadata，可用于恢复类型和方法，但这本身不是漏洞。",
              "- 关键词命中只用于定位审查目标；安全结论必须结合调用点和运行时行为确认。"]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk")
    parser.add_argument("-o", "--out", required=True)
    parser.add_argument("--dumper")
    parser.add_argument("--run-dumper", action="store_true")
    args = parser.parse_args()
    apk = Path(args.apk).resolve()
    out = Path(args.out).resolve()
    inputs = out / "inputs"
    analysis = out / "dumper"
    out.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "apk": str(apk), "apk_sha256": sha256_file(apk), "files": {}}
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        binary = next((name for name in names if re.fullmatch(r"lib/[^/]+/libil2cpp\.so", name)), None)
        if not binary or METADATA not in names:
            raise SystemExit("APK 不包含完整的 Unity IL2CPP 二进制文件与 metadata 文件组合")
        report["abi"] = binary.split("/")[1]
        binary_path = inputs / "libil2cpp.so"
        metadata_path = inputs / "global-metadata.dat"
        report["files"]["libil2cpp"] = extract_member(archive, binary, binary_path)
        report["files"]["global_metadata"] = extract_member(archive, METADATA, metadata_path)
        for optional in ("assets/bin/Data/boot.config", "assets/bin/Data/globalgamemanagers"):
            if optional in names:
                report["files"][Path(optional).name] = extract_member(archive, optional, inputs / Path(optional).name)
    report["metadata_version"] = metadata_version(metadata_path)
    dumper = resolve_dumper(args.dumper)
    if args.run_dumper:
        if not dumper:
            raise SystemExit("使用 --run-dumper 时，必须通过 --dumper 指定可执行文件、DLL 或构建目录")
        report["dumper"] = run_dumper(dumper, binary_path, metadata_path, analysis)
    report["candidates"] = candidate_lines(analysis / "dump.cs")
    write_json(out / "unity_inventory.json", report)
    (out / "unity_inventory.md").write_text(render(report), encoding="utf-8")
    print(out / "unity_inventory.json")
    print(out / "unity_inventory.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
