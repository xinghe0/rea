#!/usr/bin/env python3
"""Shared case, scope, evidence, and finding helpers for game-sec."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import Any, Iterable


SCOPE_FILE = "scope.json"
FINDINGS_FILE = "findings.json"
TIMELINE_FILE = "timeline.jsonl"
VALID_STATUSES = {"confirmed", "likely", "observation", "not-observed", "not-tested"}
VALID_CONFIDENCE = {"high", "medium", "low"}
VALID_REPORT_SECTIONS = {
    "client.code-hardening",
    "client.component-security",
    "client.file-security",
    "client.dynamic-debugging",
    "client.reverse-engineering",
    "application.functional-testing",
    "application.game-security",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: os.PathLike[str] | str, chunk_size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: os.PathLike[str] | str, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(target)


def read_json(path: os.PathLike[str] | str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def init_case(
    case_dir: os.PathLike[str] | str,
    apk: os.PathLike[str] | str,
    package: str,
    environment: str,
    devices: Iterable[str],
    allowed_actions: Iterable[str],
    account_label: str | None,
) -> dict[str, Any]:
    case = Path(case_dir).resolve()
    apk_path = Path(apk).resolve()
    if not apk_path.is_file():
        raise ValueError(f"APK not found: {apk_path}")

    for relative in ("evidence/raw", "evidence/derived", "repro", "tests"):
        (case / relative).mkdir(parents=True, exist_ok=True)

    scope_path = case / SCOPE_FILE
    if scope_path.exists():
        raise ValueError(f"scope already exists: {scope_path}")

    scope = {
        "schema_version": 1,
        "created_at": utc_now(),
        "environment": environment,
        "target": {
            "apk_path": str(apk_path),
            "apk_sha256": sha256_file(apk_path),
            "package": package,
        },
        "devices": sorted(set(filter(None, devices))),
        "allowed_actions": sorted(set(allowed_actions)),
        "account_label": account_label,
        "limits": {
            "max_requests_per_minute": 6,
            "single_variable_mutation": True,
            "real_payment": False,
            "destructive_actions": False,
        },
    }
    write_json(scope_path, scope)
    write_json(case / FINDINGS_FILE, {"schema_version": 2, "findings": []})
    (case / TIMELINE_FILE).touch()
    record_event(case, "case.init", "ok", ["game_sec.py", "init"], evidence=[str(scope_path)])
    return scope


def load_scope(scope_or_case: os.PathLike[str] | str) -> tuple[Path, dict[str, Any]]:
    supplied = Path(scope_or_case).resolve()
    scope_path = supplied if supplied.is_file() else supplied / SCOPE_FILE
    scope = read_json(scope_path)
    return scope_path.parent, scope


def authorize(
    scope_or_case: os.PathLike[str] | str,
    action: str,
    *,
    apk: os.PathLike[str] | str | None = None,
    package: str | None = None,
    device: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    case, scope = load_scope(scope_or_case)
    target = scope.get("target", {})
    errors = []
    if action not in scope.get("allowed_actions", []):
        errors.append(f"action not allowed: {action}")
    if package is not None and package != target.get("package"):
        errors.append(f"package mismatch: expected {target.get('package')}, got {package}")
    if device is not None and device not in scope.get("devices", []):
        errors.append(f"device not allowed: {device}")
    if apk is not None:
        actual = sha256_file(apk)
        if actual != target.get("apk_sha256"):
            errors.append(f"APK hash mismatch: expected {target.get('apk_sha256')}, got {actual}")
    if errors:
        raise PermissionError("; ".join(errors))
    return case, scope


def record_event(
    case_dir: os.PathLike[str] | str,
    event: str,
    status: str,
    command: Iterable[str] | str,
    *,
    return_code: int | None = None,
    evidence: Iterable[str] = (),
    detail: str | None = None,
) -> None:
    case = Path(case_dir)
    rendered = command if isinstance(command, str) else shlex.join(list(command))
    row = {
        "time": utc_now(),
        "event": event,
        "status": status,
        "command": rendered,
        "return_code": return_code,
        "evidence": list(evidence),
    }
    if detail:
        row["detail"] = detail
    with open(case / TIMELINE_FILE, "a", encoding="utf-8") as target:
        target.write(json.dumps(row, ensure_ascii=False) + "\n")


def risk_score(likelihood: int, impact: int) -> tuple[int, str]:
    if not 1 <= likelihood <= 5 or not 1 <= impact <= 5:
        raise ValueError("likelihood and impact must be between 1 and 5")
    score = likelihood * impact
    if score >= 20:
        severity = "critical"
    elif score >= 12:
        severity = "high"
    elif score >= 6:
        severity = "medium"
    elif score >= 3:
        severity = "low"
    else:
        severity = "info"
    return score, severity


def make_finding(
    finding_id: str,
    title: str,
    status: str,
    confidence: str,
    likelihood: int,
    impact: int,
    summary: str,
    evidence: Iterable[str],
    remediation: str,
    retest: str,
    *,
    impact_narrative: str = "",
    reproduction: Iterable[str] = (),
    section: str = "application.game-security",
) -> dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid finding status: {status}")
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"invalid confidence: {confidence}")
    if section not in VALID_REPORT_SECTIONS:
        raise ValueError(f"invalid report section: {section}")
    score, severity = risk_score(likelihood, impact)
    return {
        "id": finding_id,
        "title": title,
        "status": status,
        "confidence": confidence,
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": score,
        "severity": severity,
        "section": section,
        "summary": summary,
        "impact_narrative": impact_narrative,
        "evidence": list(evidence),
        "reproduction": list(reproduction),
        "remediation": remediation,
        "retest": retest,
    }


def replace_findings(case_dir: os.PathLike[str] | str, findings: Iterable[dict[str, Any]]) -> None:
    ordered = sorted(findings, key=lambda item: item["id"])
    write_json(Path(case_dir) / FINDINGS_FILE, {"schema_version": 2, "findings": ordered})


def evidence_manifest(case_dir: os.PathLike[str] | str) -> list[dict[str, Any]]:
    case = Path(case_dir).resolve()
    rows = []
    for root in (case / "evidence/raw", case / "evidence/derived"):
        if not root.exists():
            continue
        ida_work_suffixes = {".id0", ".id1", ".id2", ".nam", ".til"}
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            # IDA work databases can change while auto-analysis is active. Findings
            # cite stable exports (decompile/disasm text), never these mutable files.
            if path.suffix.lower() in ida_work_suffixes:
                continue
            if "evidence/derived/repack" in path.as_posix():
                continue
            rows.append({
                "path": str(path.relative_to(case)),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            })
    write_json(case / "evidence/manifest.json", rows)
    return rows
