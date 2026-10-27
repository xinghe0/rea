#!/usr/bin/env python3
"""Read-only, redacted sensitive-content scan for an authorized Android package."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import subprocess
import time
from pathlib import Path

from game_sec_core import authorize, record_event, utc_now, write_json


MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES = 2000
TEXT_EXTENSIONS = {
    ".xml", ".json", ".txt", ".log", ".conf", ".config", ".ini", ".properties",
    ".csv", ".db", ".sqlite", ".sqlite3", ".mkva", ".mkvb", ".pb", "",
}
KEY_VALUE = re.compile(
    rb"(?i)(account|username|user_name|login|password|passwd|pwd|token|access_token|"
    rb"refresh_token|session|sessionid|cookie|authorization|secret|api[_-]?key|"
    rb"private[_-]?key|phone|mobile|email)\s*[\"']?\s*[:=]\s*[\"']?([^\s\"'&,;}{]{3,512})"
)
JWT = re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
AWS_KEY = re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
EMAIL = re.compile(rb"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b")
PHONE = re.compile(rb"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")


def adb(device: str, *args: str, check: bool = True) -> bytes:
    result = subprocess.run(["adb", "-s", device, *args], capture_output=True)
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def redact(value: bytes) -> dict[str, str | int]:
    digest = hashlib.sha256(value).hexdigest()[:16]
    return {"redacted": f"<redacted:{len(value)} bytes>", "value_sha256_prefix": digest}


def value_profile(value: bytes) -> dict:
    text = value.decode("utf-8", errors="replace")
    classes = []
    for name, pattern in (
        ("lower", r"[a-z]"), ("upper", r"[A-Z]"), ("digit", r"\d"),
        ("symbol", r"[^A-Za-z0-9]"),
    ):
        if re.search(pattern, text):
            classes.append(name)
    counts = {byte: value.count(byte) for byte in set(value)}
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values()) if value else 0.0
    if re.fullmatch(r"(?i:true|false|null|none|success|failed|guest|login|logout)", text):
        shape = "status-or-keyword"
    elif re.fullmatch(r"\d+", text):
        shape = "numeric"
    elif re.fullmatch(r"[A-Za-z0-9_-]+", text):
        shape = "opaque-identifier"
    else:
        shape = "structured-or-free-text"
    return {
        "length": len(value), "character_classes": classes, "shape": shape,
        "entropy_bits_per_byte": round(entropy, 2), "is_empty": not bool(value),
    }


def jwt_profile(value: bytes) -> dict:
    profile = {"format_valid": False}
    try:
        header_part, payload_part, _ = value.decode("ascii").split(".")
        decode = lambda part: json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        header, payload = decode(header_part), decode(payload_part)
        now = int(time.time())
        profile.update({
            "format_valid": True,
            "algorithm": header.get("alg"),
            "claim_names": sorted(payload.keys()),
            "has_expiry": isinstance(payload.get("exp"), (int, float)),
            "expired_at_scan": payload.get("exp", now + 1) <= now if isinstance(payload.get("exp"), (int, float)) else None,
            "has_subject": "sub" in payload,
            "has_audience": "aud" in payload,
            "has_issuer": "iss" in payload,
        })
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        pass
    return profile


def scan_bytes(path: str, data: bytes) -> list[dict]:
    hits = []
    seen = set()

    def add(kind: str, match: re.Match[bytes], value: bytes) -> None:
        key = (kind, match.start(), hashlib.sha256(value).digest())
        if key in seen:
            return
        seen.add(key)
        row = {"type": kind, "offset": match.start(), "context": f"{kind}=<redacted>"}
        row.update(redact(value))
        row["profile"] = value_profile(value)
        if kind == "jwt":
            row["jwt"] = jwt_profile(value)
        hits.append(row)

    for match in KEY_VALUE.finditer(data):
        add("key-value:" + match.group(1).decode("ascii", errors="ignore").lower(), match, match.group(2))
    for kind, pattern in (("jwt", JWT), ("private-key", PRIVATE_KEY), ("cloud-access-key", AWS_KEY), ("email", EMAIL), ("phone", PHONE)):
        for match in pattern.finditer(data):
            add(kind, match, match.group(0))
    return hits


def list_files(device: str, package: str) -> tuple[list[str], list[dict[str, str]]]:
    roots = [
        f"/data/data/{package}/shared_prefs", f"/data/data/{package}/databases",
        f"/data/data/{package}/files", f"/data/data/{package}/cache",
        f"/sdcard/Android/data/{package}",
    ]
    files = []
    root_status = []
    for root in roots:
        quoted = shell_quote(root)
        result = subprocess.run(
            ["adb", "-s", device, "shell", "su", "-c", f"find {quoted} -xdev -type f -print"],
            capture_output=True,
        )
        paths = [line for line in result.stdout.decode("utf-8", errors="replace").splitlines() if line.startswith(root + "/")]
        if result.returncode == 0:
            status = "scanned"
            files.extend(paths)
        else:
            error = result.stderr.decode("utf-8", errors="replace").lower()
            status = "missing" if "no such file" in error else "inaccessible"
        root_status.append({"path": root, "status": status, "files_found": str(len(paths))})
    return sorted(set(files))[:MAX_FILES], root_status


def read_file(device: str, path: str) -> bytes:
    encoded = adb(
        device, "shell", "su", "-c",
        f"head -c {MAX_FILE_BYTES} {shell_quote(path)} 2>/dev/null | base64", check=False,
    )
    try:
        return base64.b64decode(encoded, validate=False)[:MAX_FILE_BYTES]
    except ValueError:
        return b""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    case, _ = authorize(args.scope, "device-file-read", package=args.package, device=args.device)
    files, root_status = list_files(args.device, args.package)
    results = []
    skipped = []
    for path in files:
        suffix = Path(path).suffix.lower()
        if suffix not in TEXT_EXTENSIONS:
            skipped.append({"path": path, "reason": "unsupported-extension"})
            continue
        data = read_file(args.device, path)
        hits = scan_bytes(path, data)
        if hits:
            results.append({"path": path, "size": len(data), "hits": hits})
    report = {
        "schema_version": 2,
        "created_at": utc_now(),
        "package": args.package,
        "device": args.device,
        "limits": {"max_file_bytes": MAX_FILE_BYTES, "max_files": MAX_FILES},
        "root_status": root_status,
        "files_examined": len(files) - len(skipped),
        "files_skipped": len(skipped),
        "files_with_hits": len(results),
        "hit_count": sum(len(row["hits"]) for row in results),
        "results": results,
        "skipped": skipped,
        "redaction": "Raw values are not persisted. Evidence retains type, format/shape, length, entropy, digest prefix and non-value JWT metadata.",
    }
    output = Path(args.out)
    write_json(output, report)
    relative = str(output.resolve().relative_to(case.resolve()))
    record_event(case, "dynamic.sensitive-file-scan", "ok", ["sensitive_file_scan.py", "--package", args.package, "--device", args.device], evidence=[relative])
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
