#!/usr/bin/env python3
"""
APK 资源加密扫描器（增强版）

用途：扫描 APK 内所有资源文件，判定加密状态，生成资源清单。
输出：JSON 格式的资源加密分析报告。

用法：
    python3 scan_resources.py <path/to/target.apk>                # 全量扫描（默认）
    python3 scan_resources.py target.apk --verify-unity           # 附加 UnityPy 解析验证
    python3 scan_resources.py target.apk --xor-restore <dir>      # 将 XOR 弱加密文件还原到目录

设计要点（实战教训，勿随意删改）：
1. **默认全量扫描**。按扩展名抽样会漏掉"同目录 99% 明文 + 1% 加密"的真实形态
   （实测案例：6706 个 bundle 中仅 7 个整文件 XOR 0x40，抽样 50 个必然漏报）。
2. **单字节 XOR 检测**。对无法识别的文件头做全密钥（0x01-0xFF）XOR 扫描，
   还原后出现已知 magic 即判定为弱加密，并给出密钥。
3. **UnityPy 静默失败检测**（--verify-unity）。UnityPy 对加密/损坏的 bundle
   不抛异常、静默返回 0 个对象——"load 不报错"不等于"解析成功"，
   必须以对象数 > 0 作为解析成功的判据。
4. **解密闭环**（--xor-restore）。凡是判定可加密的文件，必须产出三件套：
   解密方法（密钥/脚本）→ 解密后文件落盘目录 → 重新解析验证通过。
   报告中的"已解密"结论必须对应磁盘上可复验的产物，否则视为未验证。
"""

import sys
import os
import json
import zipfile
import argparse
from collections import defaultdict

# Magic numbers
MAGIC = {
    'png':      b'\x89PNG\r\n\x1a\n',
    'jpg':      b'\xff\xd8\xff',
    'gif':      b'GIF87a',
    'bmp':      b'BM',
    'webp':     b'RIFF',
    'mp4':      b'',
    'ogg':      b'OggS',
    'wav':      b'RIFF',
    'unityfs':  b'UnityFS',
    'il2cpp':   b'\xaf\x1b\xb1\xfa',
    'dex':      b'dex\n',
    'elf':      b'\x7fELF',
    'zip':      b'PK\x03\x04',
    'pdf':      b'%PDF',
    'pe':       b'MZ\x90\x00',
    'akpk':     b'AKPK',
    'axml':     b'\x03\x00\x08\x00',
}

# 用于 XOR 还原探测的 magic 子集（值 -> 名称）。
# 只保留 >= 3 字节的 magic：2 字节 magic（如 BMP 的 'BM'）在短文件上误报率极高
XOR_MAGICS = {v: k for k, v in MAGIC.items() if len(v) >= 3}


def check_magic(data, magic):
    return data[:len(magic)] == magic


def printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


def is_plaintext(data):
    """判定明文文本：先尝试严格 UTF-8 解码（允许截断在多字节字符中间），
    再退回可打印字符比例判定（覆盖无扩展名的 ASCII 内容如 .hash/.version）"""
    for n in (len(data), len(data) - 1, len(data) - 2, len(data) - 3):
        if n <= 0:
            break
        try:
            data[:n].decode('utf-8')
            return True
        except UnicodeDecodeError:
            continue
    return printable_ratio(data) > 0.9


def detect_xor_key(head):
    """对无法识别的文件头做全单字节 XOR 扫描，命中已知 magic 返回 (key, 格式名)"""
    for k in range(1, 256):
        x = bytes(c ^ k for c in head[:16])
        for magic, name in XOR_MAGICS.items():
            if x.startswith(magic):
                return k, name
    return None, None


def classify_file(filepath, data):
    """根据文件名和头部数据判定类型和加密状态"""
    ext = os.path.splitext(filepath)[1].lower()
    fname = os.path.basename(filepath).lower()

    result = {
        'path': filepath,
        'extension': ext,
        'head_hex': data[:16].hex(),
        'type': 'unknown',
        'encrypted': None,
        'note': ''
    }

    if check_magic(data, MAGIC['png']):
        result.update(type='image_png', encrypted=False, note='标准 PNG，无加密')
    elif check_magic(data, MAGIC['jpg']):
        result.update(type='image_jpg', encrypted=False, note='标准 JPG，无加密')
    elif check_magic(data, MAGIC['ogg']):
        result.update(type='audio_ogg', encrypted=False, note='标准 OGG，无加密')
    elif check_magic(data, MAGIC['il2cpp']):
        result.update(type='il2cpp_metadata', encrypted=False,
                      note='标准 global-metadata.dat，Il2CppDumper 可直接导出')
    elif check_magic(data, MAGIC['unityfs']):
        result.update(type='assetbundle', encrypted=False, note='标准 UnityFS 头（仍需解析验证，见 --verify-unity）')
    # 有头混淆的 AssetBundle（UnityFS 不在 offset 0）
    elif data[4:11] == MAGIC['unityfs'] or data[8:15] == MAGIC['unityfs'] or data[12:19] == MAGIC['unityfs']:
        offset = data.find(MAGIC['unityfs'])
        result.update(type='assetbundle_obfuscated', encrypted=True,
                      note=f'UnityFS 头在 offset {offset}，前 {offset} 字节为混淆头')
    elif check_magic(data, MAGIC['elf']):
        result.update(type='native_lib', encrypted=False, note='ELF 共享库（代码段是否加密需另判）')
    elif check_magic(data, MAGIC['pe']):
        result.update(type='dotnet_pe', encrypted=False, note='标准 .NET PE（DLL 明文，ILSpy/dnSpy 可反编译）')
    elif check_magic(data, MAGIC['akpk']):
        result.update(type='wwise_akpk', encrypted=False, note='标准 Wwise 音频包')
    elif check_magic(data, MAGIC['axml']):
        result.update(type='android_axml', encrypted=False, note='Android 二进制 XML')
    elif b'ftyp' in data[:12]:
        result.update(type='video_mp4', encrypted=False, note='标准 MP4，无加密')
    elif ext in ('.json', '.txt', '.xml', '.csv', '.cfg', '.ini'):
        if is_plaintext(data):
            result.update(type='config_text', encrypted=False, note='明文配置文件')
        else:
            result.update(type='config_encrypted', encrypted=True, note='加密的配置文件')
    elif 'lua' in fname and ext in ('.bytes', '.unity3d'):
        result.update(type='lua_in_ab', encrypted=True, note='Lua 脚本打包在 AB 内，可能有 XOR 加密')
    elif ext in ('.ttf', '.otf', '.ttc'):
        result.update(type='font', encrypted=False, note='字体文件')
    elif ext == '.dis':
        if is_plaintext(data):
            result.update(type='dis_config', encrypted=False, note='明文 DIS 配置文件')
        else:
            result.update(type='dis_encrypted', encrypted=True)
    else:
        # 先做 XOR 弱加密探测，再做明文兜底——顺序不能反：
        # XOR 0x40 后的 UnityFS 头会变成 '@@@@8un8n' 这类高可打印内容，
        # 若先判明文会把加密 bundle 误报为 text
        key, fmt = detect_xor_key(data)
        if key is not None:
            result.update(type=f'xor_weak({fmt})', encrypted=True,
                          note=f'整文件 XOR 0x{key:02X} 弱加密，还原后为 {fmt}')
        elif is_plaintext(data):
            # 无扩展名/非常见扩展名的明文文本（.hash/.version 等）
            result.update(type=f'text{ext}', encrypted=False, note='明文文本')
        else:
            result.update(type=f'unknown{ext}', encrypted=None, note='未识别格式（可能自定义加密/压缩，需人工复核熵值）')

    return result


def scan_apk(apk_path, sample_size=0):
    """
    扫描 APK 内所有文件，返回资源清单

    Args:
        apk_path: APK 文件路径
        sample_size: 每种扩展名采样数，0=全量（默认全量；抽样可能漏报部分加密，不推荐）
    """
    results = []
    type_stats = defaultdict(lambda: {'count': 0, 'size': 0, 'encrypted_count': 0})

    with zipfile.ZipFile(apk_path, 'r') as zf:
        all_files = zf.namelist()

        by_ext = defaultdict(list)
        for name in all_files:
            if name.endswith('/'):
                continue
            ext = os.path.splitext(name)[1].lower()
            by_ext[ext].append(name)

        for ext, files in by_ext.items():
            if sample_size > 0 and len(files) > sample_size:
                sample = files[:sample_size//3] + \
                         files[len(files)//2 - sample_size//6 : len(files)//2 + sample_size//6] + \
                         files[-sample_size//3:]
                sample = list(dict.fromkeys(sample))
            else:
                sample = files

            for fname in sample:
                try:
                    with zf.open(fname) as f:
                        data = f.read(64)
                    if len(data) < 4:
                        continue
                    info = zf.getinfo(fname)
                    result = classify_file(fname, data)
                    result['size'] = info.file_size
                    results.append(result)
                    type_stats[result['type']]['count'] += 1
                    type_stats[result['type']]['size'] += info.file_size
                    if result['encrypted']:
                        type_stats[result['type']]['encrypted_count'] += 1
                except Exception:
                    pass

    return results, dict(type_stats)


def verify_unity_bundles(apk_path, results):
    """UnityPy 逐包解析验证：对象数 <= 0 判为可疑（静默失败检测）。
    会更新 results 中 assetbundle 条目的 note。"""
    try:
        import UnityPy
    except ImportError:
        print('[!] 未安装 UnityPy，跳过解析验证（pip install UnityPy）')
        return results

    with zipfile.ZipFile(apk_path, 'r') as zf:
        for r in results:
            if r['type'] not in ('assetbundle', 'assetbundle_obfuscated'):
                continue
            try:
                env = UnityPy.load(zf.read(r['path']))
                n = len(list(env.objects))
                if n <= 0:
                    r['encrypted'] = True
                    r['type'] = 'assetbundle_suspect'
                    r['note'] = 'UnityPy 解析返回 0 对象（静默失败），疑似内容加密，需二次判定'
                else:
                    r['note'] += f'；UnityPy 解析验证通过（{n} 个对象）'
            except Exception as e:
                r['encrypted'] = True
                r['type'] = 'assetbundle_suspect'
                r['note'] = f'UnityPy 解析异常：{type(e).__name__}，疑似内容加密'
    return results


def xor_restore(apk_path, results, outdir):
    """将判定为单字节 XOR 弱加密的文件还原到 outdir，并对 bundle 做解析复验（解密闭环）。"""
    os.makedirs(outdir, exist_ok=True)
    restored = []
    with zipfile.ZipFile(apk_path, 'r') as zf:
        for r in results:
            if not r['type'].startswith('xor_weak'):
                continue
            # 从 note 中提取密钥
            key = int(r['note'].split('XOR ')[1].split(' ')[0], 16)
            data = zf.read(r['path'])
            dec = bytes(c ^ key for c in data)
            dst = os.path.join(outdir, r['path'])
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, 'wb') as f:
                f.write(dec)
            entry = {'path': r['path'], 'key': f'0x{key:02X}', 'restored_to': dst, 'verified': None}
            # 闭环验证：还原后的 bundle 必须能被 UnityPy 解析且对象数 > 0
            if 'unityfs' in r['type']:
                try:
                    import UnityPy
                    n = len(list(UnityPy.load(dec).objects))
                    entry['verified'] = n > 0
                    entry['objects'] = n
                except ImportError:
                    entry['verified'] = 'skipped(no UnityPy)'
            restored.append(entry)
    return restored


def generate_report(results, type_stats, apk_path):
    total_files = len(results)
    total_size = sum(r.get('size', 0) for r in results)
    encrypted_files = sum(1 for r in results if r['encrypted'] is True)
    plaintext_files = sum(1 for r in results if r['encrypted'] is False)

    type_summary = []
    for rtype, stats in sorted(type_stats.items(), key=lambda x: -x[1]['size']):
        type_summary.append({
            'type': rtype,
            'count': stats['count'],
            'total_size_mb': round(stats['size'] / 1048576, 2),
            'encrypted': stats['encrypted_count'] > 0,
            'encrypted_count': stats['encrypted_count'],
        })

    return {
        'apk_path': apk_path,
        'total_files_scanned': total_files,
        'total_size_mb': round(total_size / 1048576, 2),
        'encrypted_files': encrypted_files,
        'plaintext_files': plaintext_files,
        'encryption_coverage': f"{encrypted_files}/{encrypted_files + plaintext_files}",
        'type_summary': type_summary,
        'encrypted_details': [r for r in results if r['encrypted'] is True],
        'unknown_details': [r for r in results if r['encrypted'] is None][:100],
    }


def print_summary(report):
    print(f"\n{'='*60}")
    print("APK 资源加密扫描报告")
    print(f"{'='*60}")
    print(f"APK: {report['apk_path']}")
    print(f"扫描文件数: {report['total_files_scanned']}（全量）")
    print(f"总大小: {report['total_size_mb']} MB")
    print(f"加密文件: {report['encrypted_files']}")
    print(f"明文文件: {report['plaintext_files']}")
    print(f"\n{'─'*60}")
    print(f"{'类型':<30} {'数量':>6} {'大小(MB)':>10} {'加密':>6}")
    print(f"{'─'*60}")
    for item in report['type_summary']:
        enc = f"{'是' if item['encrypted'] else '否':>6}"
        print(f"{item['type']:<30} {item['count']:>6} {item['total_size_mb']:>10.2f} {enc}")
    print(f"{'─'*60}")
    if report['encrypted_details']:
        print('\n加密文件明细：')
        for r in report['encrypted_details'][:50]:
            print(f"  {r['path']}\n    -> {r['note']}")


def main():
    parser = argparse.ArgumentParser(description='APK 资源加密扫描器（增强版）')
    parser.add_argument('apk', help='APK 文件路径')
    parser.add_argument('-o', '--output', default=None, help='输出 JSON 文件路径')
    parser.add_argument('-s', '--sample', type=int, default=0,
                        help='每种扩展名采样数（默认 0=全量；抽样可能漏报部分加密，不推荐）')
    parser.add_argument('--verify-unity', action='store_true',
                        help='对 AssetBundle 逐个做 UnityPy 解析验证（慢，可发现静默失败）')
    parser.add_argument('--xor-restore', metavar='DIR',
                        help='将单字节 XOR 弱加密文件还原到指定目录并做解析复验')

    args = parser.parse_args()

    if not os.path.exists(args.apk):
        print(f"错误: APK 文件不存在: {args.apk}")
        sys.exit(1)

    print(f"扫描 APK: {args.apk}")
    results, type_stats = scan_apk(args.apk, args.sample)

    if args.verify_unity:
        print('执行 UnityPy 解析验证（静默失败检测）...')
        results = verify_unity_bundles(args.apk, results)
        # 重建统计
        type_stats = defaultdict(lambda: {'count': 0, 'size': 0, 'encrypted_count': 0})
        for r in results:
            type_stats[r['type']]['count'] += 1
            type_stats[r['type']]['size'] += r.get('size', 0)
            if r['encrypted']:
                type_stats[r['type']]['encrypted_count'] += 1
        type_stats = dict(type_stats)

    report = generate_report(results, type_stats, args.apk)

    if args.xor_restore:
        print(f'还原 XOR 弱加密文件到 {args.xor_restore} ...')
        restored = xor_restore(args.apk, results, args.xor_restore)
        report['xor_restored'] = restored
        for e in restored:
            print(f"  {e['path']} (key={e['key']}) -> {e['restored_to']} verified={e['verified']}")

    print_summary(report)

    output_path = args.output or os.path.splitext(args.apk)[0] + '_resource_scan.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\nJSON 报告: {output_path}")


if __name__ == '__main__':
    main()
