#!/usr/bin/env python3
"""对 Android 游戏 APK 执行带证据边界的静态分诊。"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from game_sec_core import sha256_file, write_json


RISKY_PERMS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE", "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
}
PACKER_LIBS = {
    "libjiagu": "360", "libdexhelper": "Bangcle", "libexec": "Ijiami",
    "libsecexe": "Tencent Legu", "libtup": "Tencent Legu", "libshell": "Legu/generic",
    "libmobisec": "Alibaba", "libnesec": "NetEase", "libbaiduprotect": "Baidu",
    "libprotectclass": "Dingxiang", "libdexjni": "PayEgis",
}
ENGINES = {
    "libcocos": "Cocos", "libil2cpp": "Unity IL2CPP", "libmono": "Unity Mono",
    "libunity": "Unity", "libue4": "Unreal Engine 4", "libunreal": "Unreal Engine",
    "libflutter": "Flutter", "libegret": "Egret", "liblaya": "LayaAir",
}
SECRET_PATTERNS = [
    ("cloud-access-key", re.compile(r"\b(AKID|AKIA|LTAI)[0-9A-Za-z]{12,}")),
    ("app-secret", re.compile(r"(?i)(app_?secret|appsecret)['\"\s:=]+['\"]?([0-9a-zA-Z/+_=-]{8,})")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
    ("api-key", re.compile(r"(?i)(api_?key|apikey)['\"\s:=]+['\"]?([0-9a-zA-Z/+_=-]{8,})")),
]
URL_RE = re.compile(rb"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,}")
TEXT_SUFFIXES = (".js", ".json", ".properties", ".xml", ".txt", ".html", ".htm", ".lua", ".cfg", ".ini")
MAX_TEXT_ENTRY = 8 * 1024 * 1024


def run(command: list[str], timeout: int = 180) -> tuple[int, str, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def find_build_tool(name: str, user_path: str | None = None) -> str | None:
    if user_path and Path(user_path).is_file():
        return user_path
    found = shutil.which(name)
    if found:
        return found
    root = Path.home() / "Library/Android/sdk/build-tools"
    candidates = sorted(root.glob(f"*/{name}"), reverse=True)
    return str(candidates[0]) if candidates else None


def bool_attr(block: str, name: str) -> bool | None:
    match = re.search(rf"android:{re.escape(name)}.*?\(type 0x12\)(0x[0-9a-f]+)", block)
    return match.group(1) != "0x0" if match else None


def parse_manifest(apk: str, aapt: str | None) -> dict:
    info = {
        "package": None, "version_code": None, "version_name": None,
        "min_sdk": None, "target_sdk": None, "debuggable": None,
        "allow_backup": None, "data_extraction_rules": False,
        "full_backup_content": False, "cleartext": None,
        "network_security_config": False, "permissions": [], "exported": [], "schemes": [],
    }
    if not aapt:
        info["warning"] = "aapt 不可用"
        return info
    _, badging, badging_err = run([aapt, "dump", "badging", apk])
    package = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", badging)
    if package:
        info.update(package=package.group(1), version_code=package.group(2), version_name=package.group(3))
    for key, pattern in (("min_sdk", r"sdkVersion:'([^']+)'"), ("target_sdk", r"targetSdkVersion:'([^']+)'")):
        match = re.search(pattern, badging)
        info[key] = match.group(1) if match else None
    info["permissions"] = sorted(set(re.findall(r"uses-permission(?:-sdk-\d+)?: name='([^']+)'", badging)))

    rc, xml, xml_err = run([aapt, "dump", "xmltree", apk, "AndroidManifest.xml"])
    if rc != 0:
        info["warning"] = xml_err or badging_err or "Manifest 解码失败"
        return info
    info["debuggable"] = bool_attr(xml, "debuggable")
    info["allow_backup"] = bool_attr(xml, "allowBackup")
    info["cleartext"] = bool_attr(xml, "usesCleartextTraffic")
    info["network_security_config"] = "android:networkSecurityConfig" in xml
    info["data_extraction_rules"] = "android:dataExtractionRules" in xml
    info["full_backup_content"] = "android:fullBackupContent" in xml
    info["schemes"] = sorted(set(re.findall(r'android:scheme\([^)]*\)="([^"]+)"', xml)))

    component = None
    depth = -1
    attrs: dict[str, str | bool] = {}
    for line in xml.splitlines() + ["E: __end__"]:
        indent = len(line) - len(line.lstrip())
        match = re.search(r"E: (activity|activity-alias|service|receiver|provider)(?:\s|$)", line)
        if match or (component and indent <= depth and "E:" in line):
            if component and attrs.get("exported") is True:
                info["exported"].append({
                    "type": component,
                    "name": attrs.get("name"),
                    "permission": attrs.get("permission"),
                    "grant_uri_permissions": attrs.get("grantUriPermissions"),
                })
            component = match.group(1) if match else None
            depth = indent if match else -1
            attrs = {}
        if not component:
            continue
        for attr in ("name", "permission"):
            value = re.search(rf'android:{attr}\([^)]*\)="([^"]+)"', line)
            if value and attr not in attrs:
                attrs[attr] = value.group(1)
        if "android:exported" in line:
            attrs["exported"] = "0xffffffff" in line
        if "android:grantUriPermissions" in line:
            attrs["grantUriPermissions"] = "0xffffffff" in line
    return info


def signature_info(apk: str, apksigner: str | None) -> dict:
    info = {"verified": None, "schemes": {}, "certificates": [], "source_stamp": None}
    if not apksigner:
        info["warning"] = "apksigner 不可用"
        return info
    rc, output, error = run([apksigner, "verify", "--verbose", "--print-certs", apk])
    text = output + "\n" + error
    info["verified"] = rc == 0
    for version in ("v1", "v2", "v3", "v3.1", "v4"):
        match = re.search(rf"Verified using {re.escape(version)} scheme[^:]*:\s*(true|false)", text, re.I)
        if match:
            info["schemes"][version] = match.group(1).lower() == "true"
    info["certificates"] = sorted(set(re.findall(r"Signer #\d+ certificate SHA-256 digest:\s*([0-9a-f]+)", text, re.I)))
    stamp = re.search(r"Source Stamp Signer certificate SHA-256 digest:\s*([0-9a-f]+)", text, re.I)
    info["source_stamp"] = stamp.group(1) if stamp else None
    if rc != 0:
        info["error"] = text.strip()[-1000:]
    return info


def scan_zip(apk: str) -> dict:
    result = {
        "size": os.path.getsize(apk), "sha256": sha256_file(apk), "entries": 0,
        "dex": [], "native_libraries": [], "abis": [], "engines": [], "packer_indicators": [],
        "scripts": {"js": 0, "jsc": 0, "lua": 0, "luac": 0},
        "h5_files": [], "hot_update": [], "unity": {}, "secrets": [], "urls": [],
        "skipped_text_entries": [], "network_security_config_entries": [],
    }
    urls: set[str] = set()
    engines: set[str] = set()
    packers: set[str] = set()
    abis: set[str] = set()
    with zipfile.ZipFile(apk) as archive:
        infos = archive.infolist()
        result["entries"] = len(infos)
        names = {entry.filename for entry in infos}
        for entry in infos:
            name = entry.filename
            lower = name.lower()
            base = Path(lower).name
            if lower.endswith(".dex"):
                result["dex"].append({"path": name, "size": entry.file_size})
            if lower.startswith("lib/") and lower.endswith(".so"):
                parts = name.split("/")
                if len(parts) >= 3:
                    abis.add(parts[1])
                result["native_libraries"].append({"path": name, "size": entry.file_size})
                for marker, engine in ENGINES.items():
                    if base.startswith(marker):
                        engines.add(engine)
                for marker, packer in PACKER_LIBS.items():
                    if base.startswith(marker):
                        packers.add(packer)
            for suffix in result["scripts"]:
                if lower.endswith("." + suffix):
                    result["scripts"][suffix] += 1
            if lower.endswith((".html", ".htm")):
                result["h5_files"].append(name)
            if base in {"project.manifest", "version.manifest", "catalog.json", "catalog.hash"} or "hotupdate" in lower:
                result["hot_update"].append(name)
            if lower.startswith("res/xml/") and ("network" in lower or "security" in lower):
                result["network_security_config_entries"].append(name)
            if lower.endswith(TEXT_SUFFIXES):
                if entry.file_size > MAX_TEXT_ENTRY:
                    result["skipped_text_entries"].append({"path": name, "size": entry.file_size})
                    continue
                try:
                    data = archive.read(entry)
                except (RuntimeError, zipfile.BadZipFile):
                    continue
                text = data.decode("utf-8", "ignore")
                for label, pattern in SECRET_PATTERNS:
                    for match in pattern.finditer(text):
                        result["secrets"].append({"file": name, "type": label, "offset": match.start()})
                        if len(result["secrets"]) >= 100:
                            break
                if lower.endswith((".js", ".json", ".properties", ".xml", ".cfg", ".ini")):
                    for raw in URL_RE.findall(data):
                        urls.add(raw.decode("utf-8", "ignore"))
        metadata = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
        il2cpp = next((n for n in names if n.endswith("/libil2cpp.so")), None)
        if metadata in names or il2cpp:
            result["unity"] = {
                "il2cpp_binary": il2cpp,
                "metadata": metadata if metadata in names else None,
                "metadata_size": archive.getinfo(metadata).file_size if metadata in names else None,
            }
    result["abis"] = sorted(abis)
    result["engines"] = sorted(engines)
    result["packer_indicators"] = sorted(packers)
    result["urls"] = sorted(urls)
    return result


def observations(manifest: dict, archive: dict, signature: dict) -> list[dict]:
    rows = []

    def add(item_id: str, status: str, title: str, detail: str, confidence: str = "high") -> None:
        rows.append({"id": item_id, "status": status, "title": title, "detail": detail, "confidence": confidence})

    if manifest.get("debuggable") is True:
        add("APK-001", "likely", "发布包允许调试", "android:debuggable=true")
    elif manifest.get("debuggable") is False:
        add("APK-001", "not-observed", "发布包未开启调试", "android:debuggable=false")
    else:
        add("APK-001", "not-tested", "未解析出 debuggable 标志", "manifest 未声明该属性，或解析器无法解析", "medium")

    if manifest.get("allow_backup") is True:
        detail = "android:allowBackup=true"
        if manifest.get("data_extraction_rules") or manifest.get("full_backup_content"):
            detail += "；已声明备份规则，需要继续审查具体内容"
        add("APK-002", "observation", "应用已启用备份", detail, "medium")
    elif manifest.get("allow_backup") is False:
        add("APK-002", "not-observed", "应用已禁用备份", "android:allowBackup=false")

    if manifest.get("cleartext") is True:
        add("NET-001", "likely", "Manifest 允许明文传输", "android:usesCleartextTraffic=true")
    elif manifest.get("cleartext") is False:
        add("NET-001", "not-observed", "Manifest 禁止明文传输", "android:usesCleartextTraffic=false")
    else:
        add("NET-001", "not-tested", "需要解析实际明文流量策略", "属性未声明；仍需结合平台默认值和 network security config", "medium")

    if archive["packer_indicators"]:
        add("REV-001", "observation", "检测到已知保护特征", ", ".join(archive["packer_indicators"]), "medium")
    else:
        add("REV-001", "observation", "未匹配已知商业加固特征", "这不代表应用没有保护", "low")

    scripts = archive["scripts"]
    if "Cocos" in archive["engines"] and scripts["js"] and not scripts["jsc"]:
        add("RES-001", "likely", "Cocos JavaScript 以明文打包", f"js={scripts['js']}, jsc=0")
    if archive["unity"].get("metadata"):
        add("REV-002", "observation", "APK 包含 Unity IL2CPP metadata", archive["unity"]["metadata"], "high")
    if archive["secrets"]:
        add("SEC-001", "observation", "发现秘密模式候选", f"{len(archive['secrets'])} 个模式命中，需要人工验证", "low")
    if signature.get("verified") is False:
        add("SIG-001", "confirmed", "APK 签名验证失败", signature.get("error", "apksigner 验证失败"))
    elif signature.get("verified") is True:
        schemes = ", ".join(k for k, v in signature["schemes"].items() if v)
        add("SIG-001", "not-observed", "APK 密码学签名有效", f"已验证方案：{schemes or '由 apksigner 报告'}")
    return rows


def markdown(report: dict) -> str:
    manifest, archive, signature = report["manifest"], report["archive"], report["signature"]
    status_labels = {
        "confirmed": "已确认",
        "likely": "高可能",
        "observation": "观察项",
        "not-observed": "未观察到",
        "not-tested": "未测试",
    }
    confidence_labels = {"high": "高", "medium": "中", "low": "低"}
    bool_labels = {True: "是", False: "否", None: "未知"}
    lines = [
        f"# {manifest.get('package') or '未知包名'} 静态分诊报告",
        "",
        f"- APK：`{report['apk']}`",
        f"- SHA-256：`{archive['sha256']}`",
        f"- 版本：`{manifest.get('version_name') or '未知'}`（`{manifest.get('version_code') or '未知'}`）",
        f"- SDK：最低 `{manifest.get('min_sdk') or '未知'}`，目标 `{manifest.get('target_sdk') or '未知'}`",
        f"- 引擎：{', '.join(archive['engines']) or '未识别'}",
        f"- ABI：{', '.join(archive['abis']) or '未识别'}",
        f"- 签名方案：{', '.join(k for k, v in signature['schemes'].items() if v) or '未解析'}",
        "",
        "## 观察结果",
        "",
        "| ID | 状态 | 置信度 | 观察项 | 证据 |",
        "|---|---|---|---|---|",
    ]
    for row in report["observations"]:
        detail = row["detail"].replace("|", "\\|").replace("\n", " ")
        status = status_labels.get(row["status"], row["status"])
        confidence = confidence_labels.get(row["confidence"], row["confidence"])
        lines.append(f"| {row['id']} | {status} | {confidence} | {row['title']} | {detail} |")
    lines += [
        "", "## Manifest 摘要", "",
        f"- `debuggable`：`{bool_labels.get(manifest.get('debuggable'), '未知')}`",
        f"- `allowBackup`：`{bool_labels.get(manifest.get('allow_backup'), '未知')}`",
        f"- `usesCleartextTraffic`：`{bool_labels.get(manifest.get('cleartext'), '未知')}`",
        f"- `networkSecurityConfig`：`{'已设置' if manifest.get('network_security_config') else '未设置'}`",
        f"- 导出组件数量：`{len(manifest.get('exported', []))}`",
        f"- 高风险权限：`{', '.join(p for p in manifest.get('permissions', []) if p in RISKY_PERMS) or '无'}`",
        "", "## 导出组件", "",
    ]
    for component in manifest.get("exported", []):
        permission = component.get("permission") or "未设置"
        lines.append(f"- `{component['type']}` `{component.get('name')}`，权限=`{permission}`")
    domains = sorted({urlsplit(url).hostname for url in archive["urls"] if urlsplit(url).hostname})
    lines += ["", "## 制品清单", "",
              f"- DEX 文件：`{len(archive['dex'])}`",
              f"- 原生库：`{len(archive['native_libraries'])}`",
              f"- JS/JSC：`{archive['scripts']['js']}/{archive['scripts']['jsc']}`",
              f"- Lua/Luac：`{archive['scripts']['lua']}/{archive['scripts']['luac']}`",
              f"- H5 文件：`{len(archive['h5_files'])}`",
              f"- URL 域名：`{len(domains)}`",
              "", "## URL 域名", ""]
    lines.extend(f"- `{domain}`" for domain in domains)
    lines += ["", "## 解释边界", "",
              "- 未匹配已知加固特征，不代表应用不存在保护。",
              "- 声明网络安全配置不代表存在 TLS 证书锁定；仍需审查 Java 和原生代码。",
              "- 秘密模式命中只是候选，必须通过使用点或成功的密码学操作确认。",
              "- 导出组件需要逐项审查权限和输入校验。"]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk")
    parser.add_argument("-o", "--out", default=str(Path(__file__).resolve().parent / "out"))
    parser.add_argument("--aapt")
    parser.add_argument("--apksigner")
    args = parser.parse_args()
    apk = str(Path(args.apk).resolve())
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = parse_manifest(apk, find_build_tool("aapt", args.aapt))
    archive = scan_zip(apk)
    signature = signature_info(apk, find_build_tool("apksigner", args.apksigner))
    report = {
        "schema_version": 2,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "apk": Path(apk).name,
        "manifest": manifest,
        "archive": archive,
        "signature": signature,
    }
    report["observations"] = observations(manifest, archive, signature)
    package = manifest.get("package") or "unknown"
    json_path = out / f"{package}_triage.json"
    md_path = out / f"{package}_triage.md"
    write_json(json_path, report)
    md_path.write_text(markdown(report), encoding="utf-8")
    print(json_path)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
