#!/usr/bin/env python3
"""
游戏脚本反编译编排器（pyc → py / DLL → cs）

用途：将 extract_resources.py 导出的 TextAsset（脚本类）反编译为源码。
      自动检测文件类型，选择对应工具链，处理整个目录。
输出：反编译源码到 <output>/_decompiled/，含统计 JSON。

用法：
    # 自动检测 + 全量反编译（pyc 和 DLL 混合目录）
    python3 decompile_scripts.py <input_dir> -o <output_dir>

    # 只反编译 pyc
    python3 decompile_scripts.py pycode/ -o pycode_decompiled/ --pyc-only

    # 只反编译 DLL（HybridCLR 热更）
    python3 decompile_scripts.py dlls/ -o decompiled/ --dll-only

    # 从设备拉取脚本目录（需 adb + 包名）
    python3 decompile_scripts.py --pull com.game.pkg -o device_scripts/

工具链依赖：
    pycdc (C++): https://github.com/zrax/pycdc （支持 Python 3.12 bytecode）
        pip 装的 pycdc 是无关包，必须从源码编译：
        git clone https://github.com/zrax/pycdc /tmp/pycdc_src &&
        cd /tmp/pycdc_src && cmake . && make
    ilspycmd: dotnet tool install -g ilspycmd
        需设置 DOTNET_ROLL_FORWARD=Major（dotnet 10 跑 net8 工具）

设计要点（实战教训，勿随意删改）：
1. **pycdc 必须用 C++ 编译版**。pip 的 pycdc 包是完全无关的 CLI 工具。
   本脚本自动检测 /tmp/pycdc_src/build/pycdc，找不到则 clone+cmake+make。
2. **ilspycmd 需要环境变量**。dotnet 10 运行 net8 工具时必须
   DOTNET_ROLL_FORWARD=Major，否则报 framework not found。
3. **逐文件容错**。某些 pyc 可能因版本不兼容反编译失败（如 MATCH 伪指令），
   记录失败列表但不中断。
"""

import sys
import os
import json
import shutil
import subprocess
import argparse
from pathlib import Path


# ── pycdc 管理 ──────────────────────────────────────────────

PYCDC_PATH = '/tmp/pycdc_src/build/pycdc'
PYCDC_SRC = '/tmp/pycdc_src'


def find_pycdc() -> str | None:
    """查找已编译的 pycdc 二进制"""
    # 1. 标准编译路径
    if os.path.isfile(PYCDC_PATH) and os.access(PYCDC_PATH, os.X_OK):
        return PYCDC_PATH
    # 2. PATH 中
    found = shutil.which('pycdc')
    if found:
        return found
    return None


def ensure_pycdc() -> str | None:
    """确保 pycdc 可用，如未编译则自动 clone+cmake+make"""
    existing = find_pycdc()
    if existing:
        return existing

    print('[*] pycdc 未找到，正在从源码编译...')
    if not os.path.isdir(PYCDC_SRC):
        r = subprocess.run(
            ['git', 'clone', '--depth=1', 'https://github.com/zrax/pycdc', PYCDC_SRC],
            capture_output=True, timeout=120)
        if r.returncode != 0:
            print(f'[!] git clone 失败：{r.stderr.decode()}')
            return None

    cmake = shutil.which('cmake')
    make = shutil.which('make')
    if not cmake or not make:
        print('[!] 缺少 cmake 或 make，请先安装（brew install cmake）')
        return None

    r = subprocess.run([cmake, '.'], cwd=PYCDC_SRC, capture_output=True, timeout=120)
    if r.returncode != 0:
        print(f'[!] cmake 失败：{r.stderr.decode()}')
        return None
    r = subprocess.run([make, '-j4'], cwd=PYCDC_SRC, capture_output=True, timeout=300)
    if r.returncode != 0:
        print(f'[!] make 失败：{r.stderr.decode()}')
        return None

    if os.path.isfile(PYCDC_PATH):
        print(f'[✓] pycdc 编译成功：{PYCDC_PATH}')
        return PYCDC_PATH
    print(f'[!] 编译完成但未找到 {PYCDC_PATH}')
    return None


def decompile_pyc_dir(src_dir: str, dst_dir: str, pycdc: str) -> dict:
    """批量反编译 .pyc → .py，保留目录结构"""
    stats = {'total': 0, 'success': 0, 'fail': 0, 'fail_list': []}
    os.makedirs(dst_dir, exist_ok=True)

    pyc_files = []
    for root, _, files in os.walk(src_dir):
        for f in files:
            if f.endswith('.pyc'):
                pyc_files.append(os.path.join(root, f))

    stats['total'] = len(pyc_files)
    print(f'pyc 反编译：{len(pyc_files)} 个文件')

    for i, pycfile in enumerate(pyc_files):
        reldir = os.path.dirname(pycfile[len(src_dir):].lstrip('/'))
        out_subdir = os.path.join(dst_dir, reldir)
        os.makedirs(out_subdir, exist_ok=True)
        basename = os.path.basename(pycfile)
        outfile = os.path.join(out_subdir, basename.replace('.pyc', '.py'))

        try:
            r = subprocess.run([pycdc, pycfile], capture_output=True, timeout=30)
            if r.returncode == 0 and r.stdout:
                with open(outfile, 'wb') as f:
                    f.write(r.stdout)
                if os.path.getsize(outfile) > 0:
                    stats['success'] += 1
                else:
                    stats['fail'] += 1
                    stats['fail_list'].append(pycfile)
            else:
                stats['fail'] += 1
                stats['fail_list'].append(pycfile)
        except Exception:
            stats['fail'] += 1
            stats['fail_list'].append(pycfile)

        if (i + 1) % 200 == 0:
            print(f'  {i+1}/{stats["total"]}, success={stats["success"]}, fail={stats["fail"]}')

    return stats


# ── ilspycmd 管理 ───────────────────────────────────────────

def find_ilspycmd() -> str | None:
    """查找 ilspycmd（dotnet global tool）"""
    # 1. PATH
    found = shutil.which('ilspycmd')
    if found:
        return found
    # 2. dotnet tools 目录
    dotnet_tools = os.path.expanduser('~/.dotnet/tools')
    candidate = os.path.join(dotnet_tools, 'ilspycmd')
    if os.path.isfile(candidate):
        return candidate
    return None


def find_ilspycmd_dll() -> str | None:
    """查找 ilspycmd.dll（用于 dotnet exec 回退模式）"""
    base = os.path.expanduser('~/.dotnet/tools/.store/ilspycmd')
    if not os.path.isdir(base):
        return None
    # 遍历版本目录找 ilspycmd.dll
    for root, _, files in os.walk(base):
        for f in files:
            if f == 'ilspycmd.dll':
                return os.path.join(root, f)
    return None


def _run_ilspycmd(dllfile: str, out_subdir: str) -> bool:
    """
    运行 ilspycmd 反编译单个 DLL。
    先试直接调用，失败则用 dotnet exec 回退（apphost 不读 DOTNET_ROLL_FORWARD）。
    """
    ilspy = find_ilspycmd()
    env = {**os.environ, 'DOTNET_ROLL_FORWARD': 'Major'}

    # 策略 1：直接调用 ilspycmd（apphost）
    if ilspy:
        r = subprocess.run([ilspy, dllfile, '-p', '-o', out_subdir],
                           capture_output=True, timeout=120, env=env)
        if r.returncode == 0:
            return True

    # 策略 2：dotnet exec ilspycmd.dll（DOTNET_ROLL_FORWARD 生效）
    ilspy_dll = find_ilspycmd_dll()
    dotnet = shutil.which('dotnet')
    if ilspy_dll and dotnet:
        r = subprocess.run([dotnet, 'exec', ilspy_dll, dllfile, '-p', '-o', out_subdir],
                           capture_output=True, timeout=120, env=env)
        return r.returncode == 0

    return False


def decompile_dll_dir(src_dir: str, dst_dir: str) -> dict:
    """批量反编译 .dll → .cs（每个 DLL 输出到独立子目录）"""
    stats = {'total': 0, 'success': 0, 'fail': 0, 'fail_list': []}

    ilspy = find_ilspycmd() or find_ilspycmd_dll()
    if not ilspy:
        print('[!] ilspycmd 未找到。请安装：dotnet tool install -g ilspycmd')
        print('    并设置 PATH="$PATH:$HOME/.dotnet/tools"')
        return stats

    dll_files = []
    for root, _, files in os.walk(src_dir):
        for f in files:
            if f.endswith('.dll'):
                dll_files.append(os.path.join(root, f))

    stats['total'] = len(dll_files)
    print(f'DLL 反编译：{len(dll_files)} 个文件')

    for i, dllfile in enumerate(dll_files):
        basename = os.path.splitext(os.path.basename(dllfile))[0]
        out_subdir = os.path.join(dst_dir, basename)
        os.makedirs(out_subdir, exist_ok=True)

        try:
            ok = _run_ilspycmd(dllfile, out_subdir)
            if ok:
                cs_count = sum(1 for _, _, fs in os.walk(out_subdir) for f in fs if f.endswith('.cs'))
                if cs_count > 0:
                    stats['success'] += 1
                else:
                    stats['fail'] += 1
                    stats['fail_list'].append(dllfile)
            else:
                stats['fail'] += 1
                stats['fail_list'].append(dllfile)
        except Exception:
            stats['fail'] += 1
            stats['fail_list'].append(dllfile)

        if (i + 1) % 10 == 0:
            print(f'  {i+1}/{stats["total"]}, success={stats["success"]}, fail={stats["fail"]}')

    return stats


# ── 设备拉取 ────────────────────────────────────────────────

def pull_device_scripts(package: str, out_dir: str) -> list[str]:
    """从设备拉取游戏脚本目录（pycode / excel / HybridCLR）"""
    base = f'/sdcard/Android/data/{package}/files'
    targets = ['pycode', 'excel', 'HybridCLR', 'hotupdate', 'scripts']
    pulled = []

    os.makedirs(out_dir, exist_ok=True)
    for target in targets:
        # 先检查目录是否存在
        r = subprocess.run(['adb', 'shell', 'ls', f'{base}/{target}/'],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0 or 'No such file' in r.stderr:
            continue
        dst = os.path.join(out_dir, target)
        print(f'  拉取 {base}/{target}/ → {dst}')
        subprocess.run(['adb', 'pull', f'{base}/{target}/', dst],
                       capture_output=True, timeout=300)
        if os.path.isdir(dst):
            pulled.append(dst)

    return pulled


# ── 文件类型检测 ────────────────────────────────────────────

def is_pe_dll(filepath: str) -> bool:
    """检测是否为 .NET PE (MZ header)"""
    try:
        with open(filepath, 'rb') as f:
            return f.read(2) == b'MZ'
    except Exception:
        return False


def is_pyc(filepath: str) -> bool:
    """检测是否为 Python bytecode"""
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            # Python 3.7+: 0x420d0d0a (LE), 3.x older variants
            return magic in (b'\x42\x0d\x0d\x0a', b'\x03\xf3\x0d\x0a',
                             b'\x55\x0d\x0d\x0a', b'\x61\x0d\x0d\x0a',
                             b'\x6f\x0d\x0d\x0a', b'\x42\x0d\x0d\x0a')
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description='游戏脚本反编译编排器（pyc → py / DLL → cs）')
    parser.add_argument('input', nargs='?', default=None,
                        help='输入目录（含 .pyc / .dll 文件）')
    parser.add_argument('-o', '--output', required=True,
                        help='输出目录')
    parser.add_argument('--pyc-only', action='store_true', help='只反编译 pyc')
    parser.add_argument('--dll-only', action='store_true', help='只反编译 DLL')
    parser.add_argument('--pull', metavar='PACKAGE',
                        help='从设备拉取脚本目录（需 adb + 包名）')
    parser.add_argument('--report', default=None,
                        help='统计 JSON 输出路径')

    args = parser.parse_args()

    # 设备拉取模式
    if args.pull:
        print(f'从设备拉取 {args.pull} 的脚本目录...')
        pulled = pull_device_scripts(args.pull, args.output)
        if not pulled:
            print('[!] 未拉取到任何脚本目录，可能游戏未运行或路径不同')
            sys.exit(1)
        # 将拉取的目录作为输入
        args.input = args.output
        print(f'拉取完成，继续反编译：{pulled}')

    if not args.input:
        parser.error('需要输入目录（或用 --pull 从设备拉取）')

    if not os.path.isdir(args.input):
        print(f'错误：输入目录不存在：{args.input}')
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)
    all_stats = {}

    # pyc 反编译
    if not args.dll_only:
        pycdc = ensure_pycdc()
        if pycdc:
            pyc_out = os.path.join(args.output, 'pycode_decompiled')
            all_stats['pyc'] = decompile_pyc_dir(args.input, pyc_out, pycdc)
        else:
            print('[!] pycdc 不可用，跳过 pyc 反编译')

    # DLL 反编译
    if not args.pyc_only:
        dll_out = os.path.join(args.output, 'decompiled')
        all_stats['dll'] = decompile_dll_dir(args.input, dll_out)

    # 汇总
    print(f"\n{'='*60}")
    print('脚本反编译汇总')
    print('=' * 60)
    for kind, s in all_stats.items():
        print(f"\n[{kind.upper()}]")
        print(f"  总计：{s['total']}")
        print(f"  成功：{s['success']}")
        print(f"  失败：{s['fail']}")
        rate = (s['success'] / s['total'] * 100) if s['total'] else 0
        print(f"  成功率：{rate:.1f}%")

    report_path = args.report or os.path.join(args.output, 'decompile_report.json')
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(all_stats, f, ensure_ascii=False, indent=2)
    print(f"\n统计报告：{report_path}")


if __name__ == '__main__':
    main()
