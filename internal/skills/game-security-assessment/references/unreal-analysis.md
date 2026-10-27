# Unreal Engine 分析

## 概述

Unreal Engine 编译为 `libUE4.so` / `libUE5.so`。由于 UE 的反射系统（UProperty / UFunction），可以通过 SDK 生成工具还原大部分游戏逻辑。

## 判定 Unreal

```bash
unzip -l target.apk | grep -iE "libUE4|libUE5|Unreal"
# 同时检查 assets 中的 UE 资源
unzip -l target.apk | grep -iE "\.pak$|\.ucas$|\.utoc$"
```

## 分析路径

### Step 1: SDK Dump

- 使用 `UE4SS` / `UnrealPakTool` / `Blueprint SDK Dumper`
- 或从 `libUE4.so` 中提取 GUObjectArray 和名称表
- 产出 `.h` 头文件 + 类/方法定义

### Step 2: PAK 资源解包

```bash
# UnrealPakTool 解包 .pak
UnrealPakTool target.pak -extract output_dir/

# 检查 PAK 是否加密
# 加密的 PAK 头部不是标准签名
```

### Step 3: 关键目标

- RPC 协议（UNetConnection）
- 充值验证（Purchase / IAP 回调）
- 反作弊（EasyAntiCheat / BattlEye 集成）
