"""UnityPy format adapter only. REA owns traversal, budgets, commands and evidence."""
import json
import sys
from pathlib import Path


def main():
    import UnityPy
    source, destination = map(Path, sys.argv[1:3])
    output_limit = int(sys.argv[3])
    output_bytes = 0
    raw = source.read_bytes()
    offset = raw[:65536].find(b"UnityFS\0")
    env = UnityPy.load(raw[offset:] if offset > 0 else raw)
    objects = list(env.objects)
    destination.mkdir(exist_ok=False)
    report = dict(status="suspect" if not objects else "completed", objects=len(objects),
                  exported=0, failed=0, skipped=0, header_offset=offset, output_bytes=0, failures=[])
    for index, obj in enumerate(objects):
        kind = obj.type.name
        # Numeric ownership names avoid collisions and names derived from untrusted objects.
        base = destination / str(index)
        try:
            if kind in ("Texture2D", "Sprite"):
                obj.read().image.save(str(base) + ".png")
            elif kind == "TextAsset":
                data = obj.read()
                value = getattr(data, "m_Script", getattr(data, "script", b""))
                if isinstance(value, str):
                    value = value.encode("utf-8", "surrogateescape")
                value = bytes(value)
                suffix = ".dll" if value[:2] == b"MZ" else ".pyc" if value[2:4] == b"\r\n" else ".luac" if value[:4] == b"\x1bLua" else ".bytes"
                Path(str(base) + suffix).write_bytes(value)
            elif kind == "AudioClip":
                samples = obj.read().samples
                for sample_index, (_, value) in enumerate(samples.items()):
                    Path(str(base) + f"-{sample_index}.audio").write_bytes(value)
                if not samples:
                    raise ValueError("AudioClip has no decoded samples")
            elif kind == "Mesh":
                value = obj.read().export()
                if not value:
                    raise ValueError("Mesh export is empty")
                Path(str(base) + ".obj").write_text(value, encoding="utf-8")
            elif kind in ("MonoBehaviour", "Shader", "Material", "AnimatorController", "AnimationClip", "Font", "VideoClip"):
                # A missing typetree is a per-object failure, never invented configuration.
                Path(str(base) + ".json").write_text(json.dumps(obj.read_typetree(), ensure_ascii=True), encoding="utf-8")
            else:
                report["skipped"] += 1
                continue
            for artifact in destination.glob(str(index) + ".*"):
                output_bytes += artifact.stat().st_size
            for artifact in destination.glob(str(index) + "-*.audio"):
                output_bytes += artifact.stat().st_size
            report["output_bytes"] = output_bytes
            if output_bytes > output_limit:
                raise ValueError("Unity output exceeds caller-selected output budget; partial artifacts retained")
            report["exported"] += 1
        except Exception as error:
            report["failed"] += 1
            report["failures"].append(f"{index}:{kind}:{type(error).__name__}:{error}")
            if output_bytes > output_limit:
                report["skipped"] += len(objects) - index - 1
                break
    if report["failed"]:
        report["status"] = "partial"
    (destination / "objects.json").write_text(json.dumps(report), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
