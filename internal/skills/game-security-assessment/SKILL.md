---
name: game-security-assessment
description: |
  对已授权的 Android 游戏 APK 和测试设备执行可复现的静态或被动安全评估，复用 REA 的 Android、APK、IL2CPP、ADB 和证据工作流。
---

# 游戏安全评估

REA 的 TypeScript 服务负责案件、输入身份、阶段状态、超时、清理和 Evidence。UnityPy 仅作为格式解析 helper；`tools/game-sec/` 是历史兼容参考，不是默认调用路径。

默认流程只执行静态或被动观察：APK 分诊、Manifest/组件、签名、引擎识别、资源扫描、IL2CPP metadata 路由、ADB 设备基线；已有抓包可通过 `--capture` / `capture_path` 接入。每次评估都要记录 APK 的绝对路径、SHA-256、工具版本、输入来源和结果覆盖范围。

没有明确授权时，不执行协议篡改或重放、内存写入、Frida 注入、重打包安装、反调试/反作弊绕过、密钥恢复、DRM/许可证绕过或面向线上服务的主动测试。无法完成的阶段必须写明 `not-tested` 和原因。

建议使用 `rea assess-mobile-game <apk> <name> --case-root <dir>`。案件产物应位于调用者指定的 case root 下，避免把 APK、设备 dump、抓包和反编译结果提交到 REA 仓库。

## 阶段

1. `01_baseline`：输入哈希、APK 分诊、引擎/架构/加固指标和签名事实。
2. `02_extract`：Manifest、组件和静态代码/资源索引。
3. `03_il2cpp`：IL2CPP metadata 路由及可用性。
4. `04_resources`：APK 资源头部、文本候选、配置转换、Unity 对象导出、脚本反编译及显式选择的设备热更采集。
5. `05_traffic`：只分析已有的授权抓包。
6. `06_frida`、`07_repack`：默认记录为 `not-tested`；只有范围和授权明确时才单独启用。

报告必须区分 observed、derived、inferred 和 unknown，并保留每个结论对应的输入和工具证据。

## 按需参考

- Unity IL2CPP：[metadata 与二进制分析](references/il2cpp-reversing.md)。
- HybridCLR：[热更新代码分析](references/hybridclr-analysis.md)。
- Cocos：[引擎专用流程](references/cocos-analysis.md)。
- Unreal：[引擎专用流程](references/unreal-analysis.md)。
- 抓包：[被动流量流程](references/traffic-capture.md)。
- 报告：[报告模板](assets/report-template.md)。

## 工具与流程

1. 建案评估：`rea assess-mobile-game <apk> <name> --case-root <dir>`。通过 `--resource-options` 提供 JSON（MCP 字段 `resources`），例如 `{"convert_configs":true,"extract_apk":true,"unity_python":"/path/to/python3","pycdc":{"command":"pycdc"},"ilspy":{"command":"ilspycmd"}}`。这些引擎必须已安装，REA 不会下载或升级。
2. 热更采集：显式给出 `--serial <serial> --device-package <package>`，只读取该包的 `/sdcard/Android/data/<package>/files/`，每个拉取文件保留 ADB Evidence。设备目录使用行列表；含换行文件名不能完整表示，不能声称全量覆盖。应用尚未运行/权限不足时应记录失败。
3. 独立转换：`convert_game_resources` / `rea convert-game-resources '<JSON>'`，输入 `apk` 或 `options.roots`，输出到新的 `output_directory`。每个输入采用独立编号目录避免同名覆盖，`manifest.json` 保留原路径、哈希和逐转换结果。可对 Unity 导出的 DLL/pyc/bytes 继续转换。
4. 协议：`decode_game_protocol` / `rea decode-game-protocol <path>` 解码原始 protobuf，保留局部字段与失败偏移；已有 pcap 仍走 REA 抓包 provider。不要从字节长度猜测签名算法。
5. 验收：`inspect_game_case` / `rea check-game-case <analysis-dir>` 重新读证据与哈希；`evidence-present` 不等于测试完成。
6. 报告：自动评估写 `report.md`；后续 `report_game_case` / `rea report-game-case <analysis-dir>` 写入新的 `report.generated.md`，不覆盖分析师修改。必须保留后端强校验章节及未测原因。

`check.json` 是自动评估实际覆盖的记录，转换清单记录格式输出。Pack.py/MessagePack 没有可靠 magic，保留多个完整解释为歧义；禁止首对象成功就忽略剩余字节。Unity 对象数为零标 suspect；对象导出错误不能伪装为空配置成功。外部反编译输出只确认退出状态和产物，尚未证明运行语义等价。

Cocos Lua/JS、Unreal pak、HybridCLR DLL 的专用分析按参考路由与现有 REA provider 执行。加密/损坏/不支持格式要保留 unknown 或 unsupported，不能当成已解密。Frida、apktool、ADB、抓包等已有 REA 契约按用户选定范围单独使用，默认 APK 评估不会自动执行注入、协议变异、安装或保护恢复。

设备交互通过 `observe_scrcpy_device` 和 `control_scrcpy_device` 单独调用。后者仅接受显式 serial 与 tap、swipe、key_event 类型动作；安装、文件传输和应用启停复用 REA 已有 ADB 工具。
