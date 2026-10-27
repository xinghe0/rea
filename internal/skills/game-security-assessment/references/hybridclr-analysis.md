# HybridCLR 热更新分析

## 概述

HybridCLR（又名 huatuo / DHE）是 Unity IL2CPP 的 C# 热更新方案。它不使用 Lua 或 ILRuntime，而是直接加载 .NET DLL 进行原生执行。理解其加载链路是判断 DLL 加密状态的关键。

## 判定游戏使用 HybridCLR

在 dump.cs 中搜索以下任一特征：

```bash
# HybridCLR 核心 API
grep -n "HybridCLR.RuntimeApi" dump.cs
grep -n "LoadDifferentialHybridAssembly" dump.cs
grep -n "LoadMetadataForAOTAssembly" dump.cs
grep -n "HomologousImageMode" dump.cs

# 热更清单文件
grep -n "BS_HotUpdateDlls\|HotUpdateDlls\|hotupdateDllInfoFile" dump.cs

# DHAO 差分数据
grep -n "GetDhaoData\|DHAO\|DifferentialHybridAssembly" dump.cs
```

## 三条加载路径

HybridCLR 有三条 DLL 加载路径，需要逐一验证是否有加密：

### 路径 1: LoadDifferentialHybridAssembly
```csharp
// 差分热更（DHE 模式）
HybridCLR.RuntimeApi.LoadDifferentialHybridAssembly(byte[] dll, byte[] dhao, byte[] pdb)
```
- DLL 原始字节 + DHAO 差分数据 + 可选 PDB
- 需检查：dll bytes 是否有变换，dhao 数据来源

### 路径 2: LoadOriginalDifferentialHybridAssembly
```csharp
// 原始差分加载
HybridCLR.RuntimeApi.LoadOriginalDifferentialHybridAssembly(string dllName)
```
- 仅传 DLL 名字，引擎自行从 AOT 中加载
- 需检查：是否存在前置的文件解密步骤

### 路径 3: LoadMetadataForAOTAssembly
```csharp
// AOT 元数据补充加载
HybridCLR.RuntimeApi.LoadMetadataForAOTAssembly(byte[] dll, HomologousImageMode mode)
```
- 用于补充 AOT 程序集的泛型元数据
- HomologousImageMode: Consistent=0, SuperSet=1

## 静态逆向分析流程

### Step 1: 定位 LoadDll 入口

```bash
# 在 dump.cs 中找 LoadDll 方法
grep -n "LoadDll" dump.cs
# 记录 RVA 地址
```

### Step 2: IDA 反编译 LoadDll

```
LoadDll(string dll) 的典型结构：
  1. 检查 _LoadedDlls 是否已加载
  2. 读取 DLL 文件 → GetRawBytes(dllPath)
  3. 读取 DHAO 数据 → GetDhaoData(dll)
  4. 调用 HybridCLR API
```

### Step 3: 追踪文件读取链

关键判断点：文件读取后、传入 HybridCLR API 前，是否有 byte[] 变换操作。

```
LoadDll
  └─ GetRawBytes(dllPath)
       └─ File.OpenRead / File.ReadAllBytes
            └─ [这里可能有 Decrypt(bytes) 调用]
  └─ GetDhaoData(dll)
       └─ File.ReadAllBytes(dhaoPath)
  └─ LoadDifferentialHybridAssembly(rawBytes, dhaoBytes, pdb)
```

如果读取链是纯文件 I/O（`FileStream.Read`），没有 XOR/AES/RC4 等密码学调用 → **DLL 是明文**。

### Step 4: 验证 API wrapper

反编译三个 HybridCLR RuntimeApi 的 wrapper 函数：
- 检查是否直接 P/Invoke 转发
- 检查中间是否有 buffer 变换

## 动态验证（Frida）

如果静态分析不确定，可用 Frida hook 验证：

```javascript
// Hook LoadDifferentialHybridAssembly 验证传入的 byte[]
Interceptor.attach(Module.findExportByName("libil2cpp.so", "il2cpp_runtime_invoke"), {
    onEnter: function(args) {
        // 检查 byte[] 参数的前 4 字节
        // 明文 DLL: 4D 5A (MZ header)
        // 加密 DLL: 其他值
    }
});
```

**注意**：游戏启动慢时 Frida attach 时机是个问题。建议用 spawn 模式 + early hook，或 hook `il2cpp_init` 完成后再继续。

## 安全评估要点

| 检查项 | 明文 DLL | 加密 DLL |
|--------|----------|----------|
| 文件头 | `4D 5A`（MZ） | 非 MZ |
| 反编译 | dnSpy/ILSpy 直接打开 | 需先逆向解密逻辑 |
| 代码保护 | 无 | 取决于加密强度 |
| 签名校验 | 通常无 | 可能有 |

## 热更 DLL 分发分析

- APK 内通常只有清单文件（如 `BS_HotUpdateDlls.txt`），不含实际 DLL
- DLL 通过 streaming patch 从 CDN 下载到 `persistentDataPath`
- 检查 CDN 地址：通常在 `client.json` 或 `.dis` 配置文件中
- 检查下载是否签名校验：搜索 `VerifySignature` / `CheckMD5` / `ValidateDll`
