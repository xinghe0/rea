#!/usr/bin/env python3
"""
游戏二进制配置表解析器（.bin → .json）

用途：将游戏自定义二进制序列化的配置表（如装备表、技能表、关卡表）
      转换为人类可读的 JSON。
输出：批量 .bin → .json，保留原文件名。

用法：
    # 解析目录下所有 .bin
    python3 parse_bin_config.py <bin_dir> -o <json_out>

    # 从 APK 内的 excel 目录提取并解析
    python3 parse_bin_config.py game.apk -o excel_json/

    # 从设备拉取 excel 目录再解析
    python3 parse_bin_config.py --pull com.game.pkg -o excel_json/

支持的二进制协议：
    1. Pack.py 协议（flag 字节标记 + 高频小整数优化）
       —— jmzy / 多款使用 Python 后端的游戏通用格式
    2. MessagePack（自动检测，需 msgpack 库）
    3. 纯 JSON 的 .bin（直接读取）

设计要点（实战教训，勿随意删改）：
1. **Pack.py 协议特征**。第一个字节是有符号 int8：正数直接是 int 值
   （高频小整数优化），负数（-100 ~ -120）是类型 flag（None/True/False/
   list/dict/string/class...）。这与 pickle 不同，是自定义的。
2. **自动协议探测**。先尝试 Pack.py（检查首字节是否在合法 flag 范围），
   不行再试 msgpack / JSON，最大兼容性。
3. **CLASS_OBJ 字段名读取**。Pack.py 的 class 序列化先写类名再写字段 dict，
   字段值可能嵌套任意类型（包括另一个 class），递归 unpack。
"""

import sys
import os
import json
import struct
import argparse
from pathlib import Path


# ── Pack.py 协议 flag 定义 ─────────────────────────────────

NONE_FLAG = -100
TRUE_FLAG = -101
FALSE_FLAG = -102
SMALL_TUPLE_FLAG = -103
BIG_TUPLE_FLAG = -104
SMALL_LIST_FLAG = -105
BIG_LIST_FLAG = -106
SMALL_SET_FLAG = -107
BIG_SET_FLAG = -108
SMALL_DICT_FLAG = -109
BIG_DICT_FLAG = -110
SMALL_STRING_FLAG = -111
BIG_STRING_FLAG = -112
SUPER_BIG_STRING_FLAG = -113
DATETIME_FLAG = -114
SIGNED_INT8_FLAG = -115
SIGNED_INT16_FLAG = -116
SIGNED_INT32_FLAG = -117
SIGNED_INT64_FLAG = -118
CLASS_OBJ_FLAG = -119
CLASS_BIN_FLAG = -120

# 合法 flag 范围（首字节在此范围内 = 可能是 Pack.py 格式）
PACK_FLAG_RANGE = range(-120, 0)


class PackReader:
    """Pack.py 自定义二进制序列化协议读取器。

    协议特征：
    - 小端字节序
    - 首字节为有符号 int8：正数 = 直接 int 值（高频小整数优化），
      负数 = 类型 flag
    - 字符串/列表/字典的长度用 ui8（small）/ ui16（big）/ i32（super big）
    - class 对象先写类名（string），再写字段数，最后是 key-value dict
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_i8(self):
        v = struct.unpack_from('<b', self.data, self.pos)[0]
        self.pos += 1
        return v

    def read_ui8(self):
        v = self.data[self.pos]
        self.pos += 1
        return v

    def read_i16(self):
        v = struct.unpack_from('<h', self.data, self.pos)[0]
        self.pos += 2
        return v

    def read_ui16(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return v

    def read_i32(self):
        v = struct.unpack_from('<i', self.data, self.pos)[0]
        self.pos += 4
        return v

    def read_i64(self):
        v = struct.unpack_from('<q', self.data, self.pos)[0]
        self.pos += 8
        return v

    def read_string(self, size: int) -> str:
        s = self.data[self.pos:self.pos + size].decode('utf-8', errors='replace')
        self.pos += size
        return s

    def unpack_obj(self):
        """递归解包一个对象。"""
        flag = self.read_i8()

        # 正数直接是 int 值（高频小整数优化）
        if flag > NONE_FLAG:
            return flag

        if flag == NONE_FLAG:
            return None
        elif flag == TRUE_FLAG:
            return True
        elif flag == FALSE_FLAG:
            return False
        elif flag == SIGNED_INT8_FLAG:
            return self.read_i8()
        elif flag == SIGNED_INT16_FLAG:
            return self.read_i16()
        elif flag == SIGNED_INT32_FLAG:
            return self.read_i32()
        elif flag == SIGNED_INT64_FLAG:
            return self.read_i64()
        elif flag == SMALL_STRING_FLAG:
            return self.read_string(self.read_ui8())
        elif flag == BIG_STRING_FLAG:
            return self.read_string(self.read_ui16())
        elif flag == SUPER_BIG_STRING_FLAG:
            return self.read_string(self.read_i32())
        elif flag == SMALL_LIST_FLAG:
            n = self.read_ui8()
            return [self.unpack_obj() for _ in range(n)]
        elif flag == BIG_LIST_FLAG:
            n = self.read_ui16()
            return [self.unpack_obj() for _ in range(n)]
        elif flag == SMALL_TUPLE_FLAG:
            n = self.read_ui8()
            return [self.unpack_obj() for _ in range(n)]
        elif flag == BIG_TUPLE_FLAG:
            n = self.read_ui16()
            return [self.unpack_obj() for _ in range(n)]
        elif flag == SMALL_SET_FLAG:
            n = self.read_ui8()
            return [self.unpack_obj() for _ in range(n)]
        elif flag == BIG_SET_FLAG:
            n = self.read_ui16()
            return [self.unpack_obj() for _ in range(n)]
        elif flag == SMALL_DICT_FLAG:
            n = self.read_ui8()
            return {self.unpack_obj(): self.unpack_obj() for _ in range(n)}
        elif flag == BIG_DICT_FLAG:
            n = self.read_ui16()
            return {self.unpack_obj(): self.unpack_obj() for _ in range(n)}
        elif flag == DATETIME_FLAG:
            # ISO 格式字符串
            return self.unpack_obj()
        elif flag in (CLASS_OBJ_FLAG, CLASS_BIN_FLAG):
            return self._unpack_class()
        else:
            return f'<unknown_flag:{flag}>'

    def _unpack_class(self) -> dict:
        """解包 class 对象：类名 + 字段数 + key-value dict"""
        # 读类名
        class_flag = self.read_i8()
        if class_flag == SMALL_STRING_FLAG:
            clen = self.read_ui8()
        elif class_flag == BIG_STRING_FLAG:
            clen = self.read_ui16()
        elif class_flag > NONE_FLAG:
            clen = class_flag
        else:
            clen = 0
        classname = self.read_string(clen) if clen > 0 else ''

        # 读字段数
        field_count_flag = self.read_i8()
        if field_count_flag == NONE_FLAG:
            field_count = 0
        elif field_count_flag > NONE_FLAG:
            field_count = field_count_flag
        else:
            field_count = self.read_ui8()

        # 读字段 dict
        obj = {'__class__': classname}
        for _ in range(field_count):
            k = self.unpack_obj()
            v = self.unpack_obj()
            obj[str(k)] = v
        return obj


# ── 协议探测 ────────────────────────────────────────────────

def looks_like_pack(data: bytes) -> bool:
    """检测是否像 Pack.py 格式：首字节在合法 flag 范围内"""
    if not data:
        return False
    first_byte = struct.unpack_from('<b', data, 0)[0]
    return first_byte in PACK_FLAG_RANGE or first_byte >= 0


def try_parse_pack(data: bytes) -> dict | None:
    """尝试用 Pack.py 协议解析，失败返回 None。

    Pack.py 配置表文件通常存多个顶层对象（表头行 + 数据行），
    每个对象都是独立序列化的。解析时只取第一个对象即可得到表头/结构。
    只要首字节是合法 flag 且 unpack 不抛异常，就视为成功。
    """
    if not looks_like_pack(data):
        return None
    try:
        reader = PackReader(data)
        return reader.unpack_obj()
    except Exception:
        return None


def try_parse_msgpack(data: bytes) -> dict | None:
    """尝试用 MessagePack 解析"""
    try:
        import msgpack
        result = msgpack.unpackb(data, raw=False)
        return result
    except Exception:
        return None


def try_parse_json(data: bytes) -> dict | None:
    """尝试直接当 JSON 解析"""
    try:
        return json.loads(data)
    except Exception:
        return None


def parse_bin_file(filepath: str) -> tuple[dict | None, str]:
    """
    自动探测协议并解析 .bin 文件。

    Returns:
        (result, protocol): 解析结果和使用的协议名
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    # 按可能性排序尝试
    for parser, name in [
        (try_parse_pack, 'Pack.py'),
        (try_parse_json, 'JSON'),
        (try_parse_msgpack, 'MessagePack'),
    ]:
        result = parser(data)
        if result is not None:
            return result, name

    return None, 'unknown'


# ── 批量处理 ────────────────────────────────────────────────

def parse_bin_dir(src_dir: str, dst_dir: str) -> dict:
    """批量解析目录下所有 .bin → .json"""
    stats = {'total': 0, 'success': 0, 'fail': 0,
             'by_protocol': {}, 'fail_list': []}
    os.makedirs(dst_dir, exist_ok=True)

    bin_files = []
    for root, _, files in os.walk(src_dir):
        for f in files:
            if f.endswith('.bin') or f.endswith('.bytes'):
                bin_files.append(os.path.join(root, f))

    stats['total'] = len(bin_files)
    print(f'配置表解析：{len(bin_files)} 个文件')

    for i, binfile in enumerate(bin_files):
        basename = os.path.basename(binfile)
        outname = basename.rsplit('.', 1)[0] + '.json'
        outfile = os.path.join(dst_dir, outname)

        result, protocol = parse_bin_file(binfile)
        if result is not None:
            with open(outfile, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2, default=str)
            stats['success'] += 1
            stats['by_protocol'][protocol] = stats['by_protocol'].get(protocol, 0) + 1
        else:
            stats['fail'] += 1
            stats['fail_list'].append(basename)

        if (i + 1) % 100 == 0:
            print(f'  {i+1}/{stats["total"]}, success={stats["success"]}, fail={stats["fail"]}')

    return stats


# ── APK 提取 ────────────────────────────────────────────────

def extract_and_parse_from_apk(apk_path: str, dst_dir: str) -> dict:
    """从 APK 内提取 .bin/.bytes 配置并解析"""
    import zipfile
    tmp_dir = os.path.join(dst_dir, '_bin_raw')
    os.makedirs(tmp_dir, exist_ok=True)

    config_dirs = ['assets/excel/', 'assets/config/', 'assets/bin/Data/',
                   'assets/TextAsset/', 'assets/StreamingAssets/']

    with zipfile.ZipFile(apk_path, 'r') as z:
        for name in z.namelist():
            if not (name.endswith('.bin') or name.endswith('.bytes')):
                continue
            if any(cd in name for cd in config_dirs):
                dst = os.path.join(tmp_dir, os.path.basename(name))
                with open(dst, 'wb') as f:
                    f.write(z.read(name))

    return parse_bin_dir(tmp_dir, dst_dir)


# ── 设备拉取 ────────────────────────────────────────────────

def pull_device_configs(package: str, out_dir: str) -> str | None:
    """从设备拉取 excel / config 目录"""
    import subprocess
    base = f'/sdcard/Android/data/{package}/files'
    for target in ['excel', 'config', 'configs', 'table', 'tables']:
        r = subprocess.run(['adb', 'shell', 'ls', f'{base}/{target}/'],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and 'No such file' not in r.stderr:
            dst = os.path.join(out_dir, target)
            subprocess.run(['adb', 'pull', f'{base}/{target}/', dst],
                           capture_output=True, timeout=300)
            if os.path.isdir(dst):
                return dst
    return None


def main():
    parser = argparse.ArgumentParser(description='游戏二进制配置表解析器（.bin → .json）')
    parser.add_argument('input', nargs='?', default=None,
                        help='输入目录（含 .bin 文件）或 APK 路径')
    parser.add_argument('-o', '--output', required=True,
                        help='输出目录（JSON 文件）')
    parser.add_argument('--pull', metavar='PACKAGE',
                        help='从设备拉取 excel 目录（需 adb + 包名）')
    parser.add_argument('--report', default=None,
                        help='统计 JSON 输出路径')

    args = parser.parse_args()

    # 设备拉取模式
    if args.pull:
        print(f'从设备拉取 {args.pull} 的配置目录...')
        pulled = pull_device_configs(args.pull, args.output)
        if not pulled:
            print('[!] 未拉取到配置目录')
            sys.exit(1)
        args.input = pulled
        print(f'拉取完成：{pulled}')

    if not args.input:
        parser.error('需要输入目录或 APK 文件（或用 --pull）')

    # APK 模式
    if args.input.lower().endswith('.apk'):
        stats = extract_and_parse_from_apk(args.input, args.output)
    elif os.path.isdir(args.input):
        stats = parse_bin_dir(args.input, args.output)
    else:
        print(f'错误：输入不存在：{args.input}')
        sys.exit(1)

    # 汇总
    print(f"\n{'='*60}")
    print('配置表解析汇总')
    print('=' * 60)
    print(f"总计：{stats['total']}")
    print(f"成功：{stats['success']}")
    print(f"失败：{stats['fail']}")
    rate = (stats['success'] / stats['total'] * 100) if stats['total'] else 0
    print(f"成功率：{rate:.1f}%")
    if stats['by_protocol']:
        print(f"\n协议分布：")
        for proto, count in stats['by_protocol'].items():
            print(f"  {proto}: {count}")
    if stats['fail_list']:
        print(f"\n⚠️ 解析失败（前 10 个）：")
        for f in stats['fail_list'][:10]:
            print(f"  {f}")

    report_path = args.report or os.path.join(args.output, 'parse_report.json')
    os.makedirs(os.path.dirname(report_path) or '.', exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"\n统计报告：{report_path}")


if __name__ == '__main__':
    main()
