#!/usr/bin/env python3
"""
通用 Unity 资源提取器（AssetBundle → 可读格式）

用途：将 AssetBundle / APK 内的资源批量转换为人类可读格式。
      解密闭环（scan → decrypt → verify）完成后的下一步——格式转换。
输出：按类型分目录导出到 04_resources/extracted/，含统计 JSON。

用法：
    # 提取目录下所有 AB 文件
    python3 extract_resources.py <bundle_dir> -o <output_dir>

    # 直接从 APK 提取（自动解包 AB 再导出）
    python3 extract_resources.py game.apk -o extracted/

    # 采样模式（大 APK 快速预览，每种子目录取前 N 个）
    python3 extract_resources.py bundles/ -o extracted/ --sample 50

支持类型的转换对照：
    Texture2D / Sprite      → .png
    AudioClip               → .wav / .ogg（原始样本）
    Mesh                    → .obj
    TextAsset               → 原始字节（自动检测 .dll / .pyc / .lua 后缀）
    MonoBehaviour           → .json（typetree）
    Shader / Material /     → .json（typetree）
    AnimationClip / Font /
    VideoClip / Animator

设计要点（实战教训，勿随意删改）：
1. **逐对象容错**。单个 MonoBehaviour 缺类型树是良性报错（spawns 报 traceback
   但不中断）。整个 AB 的提取不能因为一个对象失败而放弃。
2. **静默失败检测**。UnityPy.load 成功但 objects 为 0 = 内容加密/损坏，
   需记录为 suspect 而非 ok。这与 scan_resources.py 的铁律一致。
3. **TextAsset 后缀推断**。游戏把 .dll / .pyc / .lua 伪装成 TextAsset，
   导出时按内容 magic 自动加正确后缀（MZ→.dll, \\x42\\x0d→.pyc 等）。
"""

import sys
import os
import json
import time
import zipfile
import argparse
from collections import defaultdict
from pathlib import Path

# 支持 UnityPy 时才 import（允许无 UnityPy 环境下打印明确错误）
try:
    import UnityPy
except ImportError:
    UnityPy = None

# 导出的资源类型白名单
EXPORT_TYPES = frozenset({
    'Texture2D', 'Sprite', 'AudioClip', 'TextAsset', 'Mesh',
    'MonoBehaviour', 'Shader', 'Material', 'AnimatorController',
    'AnimationClip', 'Font', 'VideoClip',
})

# TextAsset 内容 magic → 正确后缀（游戏常把脚本伪装成 TextAsset）
TEXT_ASSET_MAGIC = [
    (b'MZ',           '.dll'),    # .NET PE / DLL
    (b'\x42\x0d\x0d\x0a', '.pyc'),  # Python 3.7+ bytecode
    (b'\x03\xf3\x0d\x0a', '.pyc'),  # Python 3.x bytecode (old)
    (b'\x1b\x4c\x75\x61', '.luac'), # Lua compiled
]


def _safe_name(name: str) -> str:
    """清理文件名中的非法字符"""
    return name.replace('/', '_').replace('\\', '_').replace('\x00', '')


def _infer_text_asset_ext(raw: bytes, orig_name: str) -> str:
    """根据内容 magic 推断 TextAsset 的真实后缀"""
    for magic, ext in TEXT_ASSET_MAGIC:
        if raw[:len(magic)] == magic:
            return ext
    # 保留原始名后缀（若有），否则 .bytes
    _, ext = os.path.splitext(orig_name)
    return ext if ext else '.bytes'


def export_obj(obj, outdir: str) -> str | None:
    """
    按 Unity 类型分发导出。返回导出文件的相对路径，失败返回 None。

    基于 project/zjcs/analysis/repro/extract_all.py 的 export_obj 验证模式，
    泛化为通用的、逐类型容错的提取器。
    """
    t = obj.type.name
    if t not in EXPORT_TYPES:
        return None

    try:
        if t in ('Texture2D', 'Sprite'):
            d = obj.read()
            img = d.image
            fname = _safe_name(getattr(d, 'm_Name', '') or f'tex_{obj.path_id}') + '.png'
            img.save(os.path.join(outdir, fname))
            return fname

        elif t == 'AudioClip':
            d = obj.read()
            saved = []
            for name, data in d.samples.items():
                fname = _safe_name(name) if name else f'audio_{obj.path_id}.wav'
                with open(os.path.join(outdir, fname), 'wb') as f:
                    f.write(data)
                saved.append(fname)
            return saved[0] if saved else None

        elif t == 'TextAsset':
            d = obj.read()
            raw = d.m_Script if hasattr(d, 'm_Script') else d.script
            if isinstance(raw, str):
                raw = raw.encode('utf-8', 'surrogateescape')
            raw = bytes(raw)
            orig_name = getattr(d, 'm_Name', '') or f'text_{obj.path_id}'
            ext = _infer_text_asset_ext(raw, orig_name)
            fname = _safe_name(orig_name)
            # 避免双重后缀
            if not fname.endswith(ext):
                fname += ext
            with open(os.path.join(outdir, fname), 'wb') as f:
                f.write(raw)
            return fname

        elif t == 'Mesh':
            d = obj.read()
            fname = _safe_name(getattr(d, 'm_Name', '') or f'mesh_{obj.path_id}') + '.obj'
            obj_data = d.export()
            if obj_data:
                with open(os.path.join(outdir, fname), 'w') as f:
                    f.write(obj_data)
                return fname
            return None

        elif t == 'MonoBehaviour':
            # 先读 typetree，失败则退回 read() 的基本字段
            try:
                tree = obj.read_typetree()
            except Exception:
                d = obj.read()
                tree = {'m_Name': getattr(d, 'm_Name', ''), 'm_Script': str(getattr(d, 'm_Script', ''))}
            name = _safe_name(str(tree.get('m_Name', '') or f'mono_{obj.path_id}'))
            fname = name + '.json'
            with open(os.path.join(outdir, fname), 'w', encoding='utf-8') as f:
                json.dump(tree, f, ensure_ascii=False, default=str, indent=2)
            return fname

        elif t in ('Shader', 'Material', 'AnimatorController',
                    'AnimationClip', 'Font', 'VideoClip'):
            try:
                tree = obj.read_typetree()
            except Exception:
                tree = {'type': t, 'path_id': obj.path_id}
            fname = f'{obj.path_id}.{t}.json'
            with open(os.path.join(outdir, fname), 'w', encoding='utf-8') as f:
                json.dump(tree, f, ensure_ascii=False, default=str, indent=2)
            return fname

    except Exception:
        # 逐对象容错：单个失败不中断整个 AB
        return None

    return None


def _find_unityfs_offset(data: bytes) -> int:
    """在数据中查找 UnityFS 头的位置（0 = 标准位置，>0 = 头混淆）"""
    return data.find(b'UnityFS')


def _collect_bundle_files(source: str) -> list[str]:
    """
    从输入源收集所有可能是 AssetBundle 的文件。
    支持目录（递归）和 APK（自动提取 .bundle / .ab / data.unity3d）。

    两种检测策略并用（实测教训）：
    1. 扩展名匹配（.bundle/.ab/.unity3d/.assets）—— 标准命名
    2. UnityFS magic 扫描 —— 游戏可能用非标准扩展名（如 .bin/.dat）
       或无扩展名存储 AssetBundle。对 APK 逐文件读头部检查 UnityFS。
    """
    files = []
    if os.path.isfile(source) and source.lower().endswith('.apk'):
        with zipfile.ZipFile(source, 'r') as z:
            for info in z.infolist():
                name = info.filename
                if name.endswith('/'):
                    continue
                low = name.lower()
                # 策略 1：已知扩展名
                if (low.endswith('.bundle') or low.endswith('.ab')
                        or low.endswith('.unity3d') or low.endswith('.assets')
                        or 'streamingassets' in low):
                    files.append(name)
                    continue
                # 策略 2：对 .bin / .dat / 无扩展名做 UnityFS magic 扫描
                # 实测：很多游戏把 AB 存为 .bin（jmzy: assets/android/normal/buildui/*.bin）
                # 但同目录的配置表也是 .bin，用 magic 区分最可靠
                ext = os.path.splitext(low)[1]
                if ext in ('.bin', '.dat', '.bytes', ''):
                    try:
                        with z.open(name) as f:
                            head = f.read(11)
                        if b'UnityFS' in head:
                            files.append(name)
                    except Exception:
                        pass
    elif os.path.isdir(source):
        for root, _, fs in os.walk(source):
            for f in fs:
                low = f.lower()
                if (low.endswith('.bundle') or low.endswith('.ab')
                        or low.endswith('.unity3d') or low.endswith('.assets')
                        or low.endswith('.dat')):
                    files.append(os.path.join(root, f))
                    continue
                # magic 检测
                try:
                    fp = os.path.join(root, f)
                    with open(fp, 'rb') as fh:
                        head = fh.read(11)
                    if b'UnityFS' in head:
                        files.append(fp)
                except Exception:
                    pass
    return sorted(files)


def _load_bundle_data(source: str, name: str) -> bytes:
    """从 APK 或文件系统读取 bundle 原始字节"""
    if source.lower().endswith('.apk'):
        with zipfile.ZipFile(source, 'r') as z:
            return z.read(name)
    else:
        with open(name, 'rb') as f:
            return f.read()


def extract_bundles(source: str, outdir: str, sample: int = 0) -> dict:
    """
    遍历所有 bundle 文件，用 UnityPy 解析并导出资源。

    Args:
        source: AB 目录或 APK 路径
        outdir: 输出根目录
        sample: 采样数（0=全量）

    Returns:
        统计字典（成功/失败/各类型数量/可疑 bundle 列表）
    """
    if UnityPy is None:
        print('[!] 未安装 UnityPy，请先 pip install UnityPy')
        return {}

    os.makedirs(outdir, exist_ok=True)
    files = _collect_bundle_files(source)

    if sample > 0 and len(files) > sample:
        # 按子目录分组采样，保证覆盖面
        by_dir = defaultdict(list)
        for fp in files:
            reldir = os.path.dirname(fp)
            by_dir[reldir].append(fp)
        sampled = []
        for d, group in by_dir.items():
            n = max(1, sample // max(1, len(by_dir)))
            sampled.extend(group[:n])
        files = sorted(sampled)

    print(f'待提取 bundle 数：{len(files)}')
    if sample > 0:
        print(f'（采样模式：每子目录取前 {max(1, sample // max(1, len(set(os.path.dirname(f) for f in files))))} 个）')

    stats = {
        'total_bundles': len(files),
        'ok_bundles': 0,
        'fail_bundles': 0,
        'suspect_bundles': 0,
        'total_objects': 0,
        'by_type': defaultdict(int),
        'suspect_list': [],
        'fail_list': [],
    }

    t0 = time.time()
    for i, fp in enumerate(files):
        # 输出子目录：保留 bundle 的相对路径结构
        if source.lower().endswith('.apk'):
            rel = fp.replace('assets/', '').replace('assets/bin/Data/', 'binData/')
        else:
            rel = os.path.relpath(fp, source)
        # 去掉 .bundle/.ab 后缀作为输出目录名
        bundle_out = os.path.join(outdir, os.path.dirname(rel),
                                  os.path.basename(rel).rsplit('.', 1)[0])

        try:
            raw = _load_bundle_data(source, fp)
            # 头混淆处理：如果 UnityFS 不在 offset 0，尝试 strip
            offset = _find_unityfs_offset(raw)
            load_data = raw[offset:] if offset > 0 else raw

            env = UnityPy.load(load_data)
            objs = list(env.objects)
            obj_count = len(objs)

            if obj_count == 0:
                # 静默失败：load 成功但 0 对象 = 加密/损坏
                stats['suspect_bundles'] += 1
                stats['suspect_list'].append({'path': fp, 'reason': '0 objects (silent fail)'})
                continue

            exported = 0
            for obj in objs:
                if obj.type.name not in EXPORT_TYPES:
                    continue
                if exported == 0:
                    os.makedirs(bundle_out, exist_ok=True)
                result = export_obj(obj, bundle_out)
                if result:
                    exported += 1
                    stats['by_type'][obj.type.name] += 1

            stats['ok_bundles'] += 1
            stats['total_objects'] += exported

        except Exception as e:
            stats['fail_bundles'] += 1
            stats['fail_list'].append({'path': fp, 'error': f'{type(e).__name__}: {e}'})

        if (i + 1) % 500 == 0:
            elapsed = time.time() - t0
            print(f'  {i+1}/{len(files)} bundles, objs={stats["total_objects"]}, '
                  f'fail={stats["fail_bundles"]}, suspect={stats["suspect_bundles"]}, '
                  f'{elapsed:.0f}s')

    stats['elapsed_sec'] = round(time.time() - t0, 1)
    stats['by_type'] = dict(stats['by_type'])
    return stats


def main():
    parser = argparse.ArgumentParser(description='通用 Unity 资源提取器（AssetBundle → 可读格式）')
    parser.add_argument('source', help='AssetBundle 目录或 APK 文件路径')
    parser.add_argument('-o', '--output', required=True,
                        help='输出目录（如 04_resources/extracted/）')
    parser.add_argument('-s', '--sample', type=int, default=0,
                        help='采样数（0=全量；大 APK 可先采样 50 快速预览）')
    parser.add_argument('--report', default=None,
                        help='统计 JSON 输出路径（默认 output_dir/extract_report.json）')

    args = parser.parse_args()

    if not os.path.exists(args.source):
        print(f'错误：输入路径不存在：{args.source}')
        sys.exit(1)

    print(f'资源提取\n  输入：{args.source}\n  输出：{args.output}')
    stats = extract_bundles(args.source, args.output, args.sample)

    if not stats:
        sys.exit(1)

    # 打印汇总
    print(f"\n{'='*60}")
    print('资源提取汇总')
    print('=' * 60)
    print(f"Bundle 总数：{stats['total_bundles']}")
    print(f"  成功：{stats['ok_bundles']}")
    print(f"  失败：{stats['fail_bundles']}")
    print(f"  可疑（0 对象）：{stats['suspect_bundles']}")
    print(f"导出对象总数：{stats['total_objects']}")
    print(f"耗时：{stats['elapsed_sec']}s")
    if stats['by_type']:
        print(f"\n{'─'*40}")
        print(f"{'类型':<25} {'数量':>8}")
        print(f"{'─'*40}")
        for t, n in sorted(stats['by_type'].items(), key=lambda x: -x[1]):
            print(f'{t:<25} {n:>8}')
    if stats['suspect_list']:
        print(f"\n⚠️ 可疑 bundle（可能加密/损坏，需解密后重试）：")
        for s in stats['suspect_list'][:10]:
            print(f"  {s['path']}: {s['reason']}")

    # 写统计报告
    report_path = args.report or os.path.join(args.output, 'extract_report.json')
    os.makedirs(os.path.dirname(report_path) or '.', exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n统计报告：{report_path}")


if __name__ == '__main__':
    main()
