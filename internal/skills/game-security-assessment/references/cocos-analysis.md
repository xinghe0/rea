# Cocos2d-x 引擎分析

## 概述

Cocos2d-x 使用 C++ 引擎 + Lua/JS 脚本层。与 Unity IL2CPP 不同，脚本文件通常以明文或简单加密形式存在。

## 判定 Cocos2d-x

```bash
# APK 内搜索 Cocos SO
unzip -l target.apk | grep -iE "cocos2d|libcocos"

# 搜索 Lua 脚本
unzip -l target.apk | grep -iE "\.lua|\.luac|\.lua\.bytes"

# 搜索 JS 脚本
unzip -l target.apk | grep -iE "\.js$|\.jsc|\.js\.bytes"
```

## Lua 脚本加密分析

### 常见加密方式

| 方式 | 特征 | 密钥位置 |
|------|------|----------|
| XXTEA | `xxtea_decrypt` 函数 | dump 中搜索 `XXTEA` / `KEY` |
| XOR | 简单循环异或 | dump 中搜索 `XOR` / 常量 byte 数组 |
| 自定义 | 压缩 + 加密 | 需逆向 `luaLoadBuffer` / `setXXTEAKey` |

### 定位解密入口

在 IDA 中搜索以下函数：
- `cocos2d::LuaEngine::executeScriptFile`
- `cocos2d::ScriptStack::executeScript`
- `luaLoadBuffer` / `lua_dobuffer`
- `xxtea_decrypt` / `XXTeaDecrypt`

### 解密脚本模板

```python
# XOR 解密
def decrypt_xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# XXTEA 解密
import xxtea
def decrypt_xxtea(data, key):
    return xxtea.decrypt(data, key)
```

## C++ 层分析

- 用 IDA Pro 加载 `libcocos2dcpp.so`
- Cocos2d-x 开源，可对照源码恢复符号
- 关键目标：充值回调、内购验证、网络协议序列化/反序列化
