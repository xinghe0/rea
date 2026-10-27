# Unity IL2CPP 逆向分析

## 概述

Unity IL2CPP 将 C# 编译为 C++ 再编译为原生 SO，不直接包含 .NET IL。但元数据（类名、方法签名、字段偏移、字符串常量）保存在 `global-metadata.dat` 中，可通过 Il2CppDumper 还原。

## Step 1: 元数据导出

```bash
# Il2CppDumper 命令行
Il2CppDumper \
  /path/to/libil2cpp.so \
  /path/to/global-metadata.dat \
  /output/dir/

# 产出文件：
# - dump.cs      : 全量 C# 定义（类/方法/字段，含 RVA 地址）
# - script.json  : 方法地址映射
# - il2cpp.h     : C 头文件
# - stringliteral.json : 字符串常量表
# - ida.py       : IDA Pro 符号恢复脚本
```

## Step 2: dump.cs 搜索技巧

dump.cs 通常 10-100MB。用 grep 精准定位：

```bash
# 搜索加密相关
grep -n "class.*Encryption\|class.*Decrypt\|class.*Crypt" dump.cs

# 搜索密钥常量
grep -n "const string.*KEY\|const.*byte\[\].*KEY\|readonly.*KEY" dump.cs

# 搜索热更新
grep -n "HotUpdate\|HybridCLR\|LoadDll\|LoadMetadata" dump.cs

# 搜索反调试
grep -n "ptrace\|Debugger\|TracerPid\|anti.*debug\|AntiCheat" dump.cs

# 搜索充值/支付
grep -n "class.*Pay\|class.*Order\|class.*Recharge\|class.*Purchase\|class.*IAP" dump.cs

# 搜索抽卡/随机
grep -n "class.*Gacha\|class.*Draw\|class.*Lottery\|class.*Random\|class.*Lucky" dump.cs

# 搜索指定类
grep -n "class ClassName" dump.cs
```

## Step 3: IDA Pro 分析

1. 用 IDA Pro 打开 `libil2cpp.so`
2. 运行 `ida.py`（Il2CppDumper 产出）恢复函数名和类型
3. 通过 dump.cs 中的 RVA 定位目标函数
4. F5 反编译查看伪代码

### 通过 MCP 自动化分析

如果有 ida-pro-mcp 插件，可以编程化分析：

```python
# 打开二进制
idb_open(input_path="/path/to/libil2cpp.so")

# 反编译指定地址的函数
decompile(addr="0x4432264", database=session_id)

# 查看函数调用关系
analyze_function(addr="0x4432264", database=session_id)

# 搜索字符串
find_regex(pattern="m72-2024", database=session_id)

# 追踪数据流
trace_data_flow(addr="0x4432264", direction="backward", database=session_id)
```

## Step 4: global-metadata.dat 加密处理

如果 `global-metadata.dat` 被加密（头部不是 `AF 1B B1 FA`）：

1. 在 IDA 中搜索 `il2cpp_init` 或 `MetadataLoader::LoadMetadataFile`
2. 跟踪 metadata 读取后的处理函数
3. 常见手法：XOR / AES / 整体异或 + 头部变换
4. 找到解密函数后，dump 解密后的 metadata 再跑 Il2CppDumper

## 常见模式速查

### AssetBundle 头部偏移
```
搜索：GetHeadOffset / headSize / HEAD_SIZE / LoadAssetBundle
偏移值通常返回 12 或 16
```

### Lua 脚本加密
```
搜索：LuaEncryption / LuaDecrypt / XLuaDecrypt
密钥通常：const string KEY = "xxx" 或 static readonly byte[] KEY = {...}
```

### HybridCLR 热更
```
搜索：HotUpdateHybridCLR / LoadDifferentialHybridAssembly / LoadMetadataForAOTAssembly
关键判断：LoadDll 链路中是否有 byte[] 变换操作
```

### 反调试检测
```
搜索：ptrace / kill(0, 0) / TracerPid / /proc/self/status / isDebuggerConnected
常见位置：libnative.so 或加固 SO（不在游戏自身代码中）
```
