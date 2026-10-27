# 报告模板

## 飞书文档报告结构

以下是用 XML 格式（lark-doc skill）生成游戏安全评估报告的标准结构。按需裁剪章节。

```xml
<title>{{游戏名称}} 安全评估报告</title>

<!-- ====== 风险概览 ====== -->
<h1>风险概览</h1>
<callout emoji="⚠️" background-color="rgb(254,243,199)" border-color="rgb(252,211,77)">
<p>本次评估发现 <b>{{高危数}}</b> 个高危、<b>{{中危数}}</b> 个中危、<b>{{低危数}}</b> 个低危安全问题。{{一句话总结}}</p>
</callout>
<table>
<thead><tr>
<th background-color="rgb(242,243,245)">等级</th>
<th background-color="rgb(242,243,245)">数量</th>
<th background-color="rgb(242,243,245)">主要风险点</th>
</tr></thead>
<tbody>
<tr><td><b><span text-color="rgb(216,57,49)">高危</span></b></td><td>{{N}}</td><td>{{高危摘要}}</td></tr>
<tr><td><b><span text-color="rgb(222,120,2)">中危</span></b></td><td>{{N}}</td><td>{{中危摘要}}</td></tr>
<tr><td><b><span text-color="rgb(45,156,76)">低危</span></b></td><td>{{N}}</td><td>{{低危摘要}}</td></tr>
</tbody>
</table>

<!-- ====== 一、客户端安全 ====== -->
<h1>一、客户端安全</h1>

<h2>1.1 代码加固</h2>
<p>{{加固判定结论}}</p>

<h2>1.2 组件安全</h2>
<p>{{暴露组件分析}}</p>

<h2>1.3 文件安全</h2>
<p>{{资源加密扫描结论 + 格式转换覆盖率}}</p>
<!-- 资源加密对照表（含可读格式转换） -->
<table>
<thead><tr>
<th background-color="rgb(242,243,245)">资源类型</th>
<th background-color="rgb(242,243,245)">体量</th>
<th background-color="rgb(242,243,245)">加密状态</th>
<th background-color="rgb(242,243,245)">可读格式</th>
<th background-color="rgb(242,243,245)">转换产物路径</th>
<th background-color="rgb(242,243,245)">实测验证</th>
</tr></thead>
<tbody>
<!-- 示例行（按实际发现填写）：
<tr><td>AssetBundle</td><td>13826 个</td><td>明文（头混淆）</td><td>PNG/WAV/JSON</td><td>04_resources/extracted/art/</td><td>采样提取 136 个，302 纹理 + 24 精灵</td></tr>
<tr><td>Python 脚本 (pyc)</td><td>2100 个</td><td>明文</td><td>.py 源码</td><td>04_resources/extracted/pycode_decompiled/</td><td>2077/2100 反编译成功（99%）</td></tr>
<tr><td>配置表 (.bin)</td><td>967 个</td><td>明文（Pack.py 协议）</td><td>.json</td><td>04_resources/extracted/excel_json/</td><td>967/967 解析成功（100%）</td></tr>
<tr><td>HybridCLR DLL</td><td>7 个</td><td>明文</td><td>.cs 源码</td><td>04_resources/extracted/decompiled/</td><td>624 个 .cs 文件</td></tr>
-->
</tbody>
</table>

<h2>1.4 动态调试</h2>
<p>{{反调试检测结论}}</p>

<h2>1.5 逆向破解</h2>
<p>{{IL2CPP/DLL/Lua 可读性分析}}</p>

<!-- ====== 二、应用层安全 ====== -->
<h1>二、应用层安全</h1>

<h2>2.1 协议加密</h2>
<p>{{协议格式、签名、重放防护分析}}</p>

<h2>2.2 后端强校验</h2>
<p>{{服务端权威验证结论}}</p>

<!-- ====== 三、总结与建议 ====== -->
<h1>三、总结与建议</h1>
<ol>
<li>{{按优先级排序的修复建议}}</li>
</ol>
```

## 风险等级定义

| 等级 | 判定标准 |
|------|----------|
| 🔴 高危 | 可直接导致客户端被完全控制、数值被篡改、付费绕过 |
| 🟡 中危 | 需要特定条件（root / 中间人）才能利用，或信息泄露到有价值程度 |
| 🟢 低危 | 需要极高技术门槛，或影响范围有限 |

## 报告风格要求

- 高亮块（callout）全文控制在 2-3 个以内
- 用表格做对照总结，不要用大段文字
- 每个发现附证据（文件路径、RVA、hex dump、代码片段）
- 风险等级用颜色标记：🔴rgb(216,57,49) 🟡rgb(222,120,2) 🟢rgb(45,156,76)

## 如实报告"未发现漏洞"

一轮测试下来，某些层面可能确实没有可利用的漏洞。**不要为了凑数而把非漏洞包装成漏洞**。如实报告测试范围、方法和结论：

- **测了什么**：列出抓到的流量数量、覆盖的域名、测试的操作
- **怎么测的**：抓包方式（mitmproxy/adb reverse）、参数篡改尝试、重放测试
- **发现了什么**：接口协议格式、加密方式、签名机制
- **结论**：核心业务接口有服务端校验 / 签名机制有效 / 未发现可利用漏洞

示例写法（协议层未发现漏洞时）：

```xml
<h3>HTTPS API 流量分析</h3>
<p>通过 adb reverse + iptables 透明代理，捕获 97 条 HTTPS 请求，
覆盖 20+ 域名。实测确认游戏全部 HTTPS 接口无 Certificate Pinning，
MITM 证书安装后可解密全部加密通信。</p>
<p>对各接口进行协议分析和参数篡改测试后，结论如下：</p>
<table>
<thead><tr>
<th>接口类别</th><th>格式</th><th>安全状态</th>
</tr></thead>
<tbody>
<tr><td>游戏主协议</td><td>自定义二进制</td><td>有签名校验</td></tr>
<tr><td>SDK 配置</td><td>AES + Base64</td><td>有加密（加固建议：ECB→CBC）</td></tr>
<tr><td>埋点上报</td><td>明文 JSON</td><td>非漏洞（行业通用做法）</td></tr>
</tbody>
</table>
<p>本轮测试<b>未发现可利用的协议层漏洞</b>。核心业务接口的签名机制有效，
关键数值由服务端校验。建议将 SDK 配置加密从 ECB 升级为 CBC/GCM 模式作为加固。</p>
```

**核心原则**：漏洞的判定标准是"能否造成实际危害"（数值篡改、付费绕过、越权操作），不是"有没有加密"。明文传输非敏感配置不构成漏洞。
