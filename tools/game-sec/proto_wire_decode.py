#!/usr/bin/env python3
"""Decode protobuf wire data without a schema and report parse confidence."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


MAX_FIELD = 536_870_911


class DecodeError(ValueError):
    pass


@dataclass
class DecodeResult:
    fields: list[dict[str, Any]]
    complete: bool
    consumed: int
    error: str | None = None


def read_varint(buffer: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if offset >= len(buffer):
            raise DecodeError("truncated varint")
        byte = buffer[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise DecodeError("varint overflow")
        value |= (byte & 0x7f) << (index * 7)
        if byte & 0x80 == 0:
            return value, offset
    raise DecodeError("varint overflow")


def printable_utf8(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and all(character.isprintable() or character in "\r\n\t" for character in text):
        return text
    return None


def decode_message(buffer: bytes, depth: int = 0, max_depth: int = 4) -> DecodeResult:
    fields = []
    offset = 0
    try:
        while offset < len(buffer):
            start = offset
            tag, offset = read_varint(buffer, offset)
            field_number, wire_type = tag >> 3, tag & 7
            if not 1 <= field_number <= MAX_FIELD:
                raise DecodeError(f"invalid field {field_number} at {start}")
            if wire_type == 0:
                value, offset = read_varint(buffer, offset)
                fields.append({"field": field_number, "wire_type": "varint", "value": value})
            elif wire_type == 1:
                end = offset + 8
                if end > len(buffer):
                    raise DecodeError(f"truncated fixed64 at {offset}")
                fields.append({"field": field_number, "wire_type": "fixed64",
                               "value": int.from_bytes(buffer[offset:end], "little")})
                offset = end
            elif wire_type == 2:
                length, offset = read_varint(buffer, offset)
                end = offset + length
                if end > len(buffer):
                    raise DecodeError(f"length {length} exceeds remaining {len(buffer) - offset} at {offset}")
                raw = buffer[offset:end]
                offset = end
                text = printable_utf8(raw)
                if text is not None:
                    fields.append({"field": field_number, "wire_type": "string", "value": text})
                elif depth < max_depth and raw:
                    nested = decode_message(raw, depth + 1, max_depth)
                    if nested.complete and nested.fields and nested.consumed == len(raw):
                        fields.append({"field": field_number, "wire_type": "message", "value": nested.fields})
                    else:
                        fields.append({"field": field_number, "wire_type": "bytes", "value": raw.hex()})
                else:
                    fields.append({"field": field_number, "wire_type": "bytes", "value": raw.hex()})
            elif wire_type == 5:
                end = offset + 4
                if end > len(buffer):
                    raise DecodeError(f"truncated fixed32 at {offset}")
                fields.append({"field": field_number, "wire_type": "fixed32",
                               "value": int.from_bytes(buffer[offset:end], "little")})
                offset = end
            else:
                raise DecodeError(f"unsupported wire type {wire_type} at {start}")
        return DecodeResult(fields, True, offset)
    except DecodeError as exc:
        return DecodeResult(fields, False, offset, str(exc))


def try_frame(data: bytes) -> dict[str, Any]:
    candidates = []
    for length_size, endian in ((2, "big"), (4, "big"), (4, "little")):
        if len(data) <= length_size:
            continue
        declared = int.from_bytes(data[:length_size], endian)
        if declared != len(data) - length_size:
            continue
        rest = data[length_size:]
        try:
            message_id, offset = read_varint(rest, 0)
        except DecodeError:
            continue
        if not 0 < message_id < 10_000_000 or offset >= len(rest):
            continue
        decoded = decode_message(rest[offset:])
        if decoded.complete and decoded.fields:
            candidates.append({"length_size": length_size, "endian": endian,
                               "message_id": message_id, "body": rest[offset:], "decoded": decoded})
    if len(candidates) == 1:
        return candidates[0]
    return {"length_size": None, "endian": None, "message_id": None,
            "body": data, "decoded": decode_message(data), "ambiguous_candidates": len(candidates)}


def decode_hex(value: str, raw: bool = False) -> dict[str, Any]:
    compact = "".join(value.split())
    data = bytes.fromhex(compact)
    frame = {"message_id": None, "body": data, "decoded": decode_message(data)} if raw else try_frame(data)
    return {
        "input_size": len(data), "message_id": frame["message_id"],
        "frame": {key: frame.get(key) for key in ("length_size", "endian", "ambiguous_candidates") if key in frame},
        "decode": asdict(frame["decoded"]),
    }


def render(value: Any, indent: int = 0) -> list[str]:
    lines = []
    pad = "  " * indent
    for field in value:
        if field["wire_type"] == "message":
            lines.append(f"{pad}field {field['field']} message:")
            lines.extend(render(field["value"], indent + 1))
        else:
            lines.append(f"{pad}field {field['field']} {field['wire_type']}: {field['value']}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hex", nargs="?")
    parser.add_argument("-f", "--file")
    parser.add_argument("--raw", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not args.hex and not args.file:
        parser.error("provide a hex value or --file")
    lines = Path(args.file).read_text(encoding="utf-8").splitlines() if args.file else [args.hex]
    exit_code = 0
    for index, line in enumerate(lines):
        candidate = line.split("hex=", 1)[1].split()[0] if "hex=" in line else line.strip()
        if not candidate:
            continue
        try:
            result = decode_hex(candidate, args.raw)
        except ValueError as exc:
            result = {"input": index, "error": f"invalid hex: {exc}"}
            exit_code = 1
        if args.json:
            print(json.dumps(result, ensure_ascii=False))
        else:
            print(f"=== [{index}] {result.get('input_size', 0)} bytes ===")
            if "error" in result:
                print(result["error"])
                continue
            if result["message_id"] is not None:
                print(f"msgId: {result['message_id']}")
            print("\n".join(render(result["decode"]["fields"])))
            if not result["decode"]["complete"]:
                print(f"ERROR: {result['decode']['error']}")
                exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
