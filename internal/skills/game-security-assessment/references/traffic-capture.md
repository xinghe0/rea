# 游戏流量抓包

## 概述

游戏流量抓包与普通 App 不同，主要挑战：
1. Unity 的 UnityWebRequest 和 OkHttp 默认不走系统代理
2. 游戏可能有 SSL Pinning
3. 游戏可能使用非 HTTP 协议（TCP socket / WebSocket）

## 工具选择

| 工具 | 模式 | 适用场景 |
|------|------|----------|
| mitmproxy (mitmdump) | HTTP/SOCKS/透明代理 | 通用，支持脚本自动化分析 |
| Burp Suite | HTTP 代理 | 手动分析 + Repeater 重放 |
| Charles | HTTP 代理 | 轻量级快速查看 |
| tcpdump | 网络层 | 非 HTTP 协议 / 底层分析 |
| Wireshark | 网络层 | 协议逆向 |

**推荐 mitmproxy**：可编程、支持透明代理模式、Python addon 脚本自动化。

## 环境搭建

### 方案选择

| 方案 | 适用场景 | 备注 |
|------|----------|------|
| **adb reverse + iptables**（推荐首选） | WiFi 网段不互通 / 仅 USB 连接 | 通过 USB 隧道转发，不需要 WiFi |
| mitmproxy 透明代理 | WiFi 网段互通 | iptables DNAT 到电脑 IP |
| 系统代理 | 仅 OkHttp 类库 | Unity 无效，优先尝试上面两种 |

### Step 1: 安装 mitmproxy

```bash
brew install mitmproxy  # macOS
# 或 pip install mitmproxy
```

### Step 2: 生成并安装 CA 证书

```bash
# 首次运行生成证书
mitmdump --listen-port 8888 &
sleep 3 && kill %1

# 证书位置: ~/.mitmproxy/mitmproxy-ca-cert.pem

# 计算 Android 系统证书文件名（需要 root）
HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)

# 推送到设备系统证书目录
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /sdcard/mitmproxy-ca-cert.pem
adb shell "su -c 'cp /sdcard/mitmproxy-ca-cert.pem /system/etc/security/cacerts/${HASH}.0 && chmod 644 /system/etc/security/cacerts/${HASH}.0'"
```

### Step 3: 配置代理

#### 方式 A: adb reverse + iptables（推荐，WiFi 不通时首选）

通过 USB 端口转发绕过 WiFi 网段隔离，设备流量经 USB 隧道到电脑的 mitmproxy：

```bash
# 1. 建立 adb reverse 隧道（设备 localhost:8888 → 电脑 localhost:8888）
adb reverse tcp:8888 tcp:8888

# 2. 启动 mitmproxy（普通模式即可，adb reverse 已把流量送到本地）
mitmdump --listen-port 8888 -s save_flows.py --set block_global=false -q &

# 3. 设置 iptables：设备上 80/443 重定向到设备自身 localhost:8888
adb shell "su -c '
  iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8888
  iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8888
'"

# 清理（测试完成后必须执行）
adb shell "su -c 'iptables -t nat -F OUTPUT'"
adb reverse --remove-all
pkill mitmdump
```

**为什么有效**：`adb reverse` 把设备的 `127.0.0.1:8888` 映射到电脑的 `localhost:8888`，iptables 把游戏出站的 80/443 全部重定向到设备本地 8888，形成 `游戏 → iptables → 设备localhost:8888 → USB隧道 → 电脑mitmproxy` 的完整通路。不依赖 WiFi 连通性。

#### 方式 B: iptables 透明代理（WiFi 网段互通时）
```bash
# 启动 mitmproxy 透明模式（在电脑端）
mitmdump --mode transparent --listen-port 8888 --showhost &

# 设置 iptables（在设备端，需要 root）
adb shell "su -c '
  iptables -t nat -F OUTPUT
  iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <电脑IP>:8888
  iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <电脑IP>:8888
'"

# 清除规则
adb shell "su -c 'iptables -t nat -F OUTPUT'"
```

### Step 4: 抓包脚本

```python
# save_flows.py — mitmproxy addon，保存请求/响应到 JSON
import json, os
from datetime import datetime
from mitmproxy import http

LOG_FILE = "/path/to/capture/flows.jsonl"
flow_count = 0

def request(flow: http.HTTPFlow) -> None:
    global flow_count
    flow_count += 1
    entry = {
        "id": flow_count,
        "timestamp": datetime.now().isoformat(),
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "host": flow.request.pretty_host,
        "path": flow.request.path,
        "request_headers": dict(flow.request.headers),
        "request_body": None,
    }
    if flow.request.content:
        entry["request_body"] = flow.request.content.decode('utf-8', errors='replace')[:5000]
    flow.metadata["capture_entry"] = entry

def response(flow: http.HTTPFlow) -> None:
    entry = flow.metadata.get("capture_entry", {})
    entry["status_code"] = flow.response.status_code
    entry["response_headers"] = dict(flow.response.headers)
    if flow.response.content:
        entry["response_body"] = flow.response.content.decode('utf-8', errors='replace')[:10000]
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
```

启动命令：
```bash
mitmdump --mode transparent --listen-port 8888 --showhost \
  -s save_flows.py --set block_global=false -q
```

## SSL Pinning 处理

如果 mitmproxy 能看到 TLS 握手但后续无数据，说明有 SSL Pinning。

### 方案 1: Frida 绕过（推荐）

```bash
# 安装 objection（封装了 Frida SSL pinning bypass）
pip install objection
objection -g com.target.package explore -P
# 在 objection shell 中执行：
android sslpinning disable
```

### 方案 2: 手动 Frida hook

```javascript
// hook OkHttp CertificatePinner
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
});

// hook TrustAllCerts
Java.perform(function() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    // ... 自定义 TrustManager
});
```

### 方案 3: Unity TLS 绕过

Unity 2020+ 使用系统证书库，系统证书安装正确时通常不需要额外处理。如果仍有 pinning，hook `libil2cpp.so` 中的 SSL 验证函数。

## 流量分析要点

### HTTP JSON 协议
- 检查认证字段：token / session / uid / sign / timestamp
- 检查签名算法：MD5(params + secret) / HMAC-SHA256
- 检查是否有 request replay 防护：nonce / timestamp + 过期检查

### Protobuf 协议
- 抓包看到的是二进制数据
- 从 dump.cs / DLL 中提取 .proto 定义
- 用 `protoc --decode_raw` 粗略解析

### WebSocket
- mitmproxy 自动处理 WebSocket upgrade
- 检查消息格式和心跳机制

## 常见问题

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 无流量捕获 | App 不走系统代理 | 用 iptables 透明代理 |
| TLS 握手失败 | 证书未安装或 SSL Pinning | 安装系统证书 / Frida bypass |
| 游戏启动后卡住 | 代理连接超时 | 检查网络连通性、防火墙 |
| 只有部分流量 | 非 HTTP 协议（TCP socket） | 用 tcpdump 抓全量 |
| 游戏闪退 | 反代理检测 | 检查是否有代理检测代码 |

## 流量分析实战经验

### 抓到的流量怎么分析

1. **按域名分组统计**：区分游戏核心 API、CDN、第三方 SDK
2. **识别协议格式**：明文 JSON / Gzip+Base64（`H4sI` 头）/ AES 加密 / MessagePack 二进制
3. **提取签名参数**：搜索 sign / token / timestamp，判定算法和拼接顺序
4. **检查 SSL Pinning**：如果零 TLS 错误 = 无 Pinning

### "不是漏洞"的判定标准

抓到明文接口不代表就是漏洞。根据实际影响面分级：

| 接口特征 | 判定 | 理由 |
|----------|------|------|
| 游戏核心协议（战斗/充值/抽卡）无加密 | 🔴 高危漏洞 | 可篡改数值 |
| 认证签名密钥可从客户端还原 | 🔴 高危漏洞 | 可伪造身份 |
| 埋点上报明文传输设备指纹 | 🟢 非漏洞 | 行业通用做法，无操作权限 |
| CDN 公开文件（配置/补丁）明文 | 🟢 非漏洞 | 本来就是给客户端下载的 |
| 配置下发 AES-ECB 弱加密 | 🟡 加固建议 | 内容非敏感，ECB 仅理论风险 |
| IP 地区检测签名可伪造 | 🟡 加固建议 | 接口只返回地区信息，无收益 |
| 数据上报含设备ID/账号ID | 🟢 非漏洞 | 埋点 SDK 标准行为 |

**核心原则**：漏洞的判定标准是"能否造成实际危害"（数值篡改、付费绕过、越权操作），不是"有没有加密"。如果一轮抓包下来，游戏核心业务接口没抓到或抓到了但确实有服务端校验，那就如实写"本轮未发现可利用漏洞"。

### 常见的"看起来有问题但其实不是"的场景

- **SDK 配置 ECB 加密**：配置文件内容不敏感（开关、URL 列表），ECB 弱点无实际收益
- **版本/热更文件明文**：CDN 公开文件，客户端本来就要下载，无授权要求
- **sync_data 明文上报**：埋点 SDK 的标准做法，数据只有上报没有操作
- **sign = MD5(timestamp + appkey)**：如果接口只做查询返回非敏感数据，签名可伪造也无收益
