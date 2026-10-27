# game-sec - Android 游戏安全自动化工具

工具适用于 Unity IL2CPP、Cocos 和通用 Android 游戏安全评估。静态候选不会自动升级为漏洞，UI 改值不会被当作服务端修改成功。

## 统一案件目录规范（推荐，`gs.py`）

为保证不同大模型/会话的**测试工具、测试流程、报告结果**三者产出统一可复现，每个游戏一个案件目录，根为 `project/<game>/analysis/`，**目录编号即评估流程顺序**：

```text
project/<game>/analysis/
├── README.md          # 基线卡片（包名/版本/SHA256/引擎/加固/设备/授权）
├── 01_baseline/       # APK 分诊 + 签名 + 设备基线
├── 02_extract/        # 解包（unzip/apktool/jadx）+ 组件分析
├── 03_il2cpp/         # Il2CppDumper 输出（dump.cs 或 metadata 加密说明）
├── 04_resources/      # 资源/Lua 解密产物 + 敏感文件扫描
├── 05_traffic/        # 抓包（mitmproxy flows/pcap）
├── 06_frida/          # frida 脚本与日志（反调试检测）
├── 07_repack/         # 重打包验证
├── report.md          # 最终报告（唯一模板）
└── repro/             # 本案可复现脚本汇总（禁止 v2/v3 命名）
```

配套脚手架（只做「建目录 + 基线 + 自检 + 迁移」，不做重计算）：

```bash
python3 tools/game-sec/gs.py run <apk> --game <项目名> [--device S] [--repack]   # 一键流水线（推荐首选）
python3 tools/game-sec/gs.py init <apk> --game <项目名>   # 仅建目录（run 会自动建案）
python3 tools/game-sec/gs.py check <项目名>               # 自检必测项清单 + 报告完整性
python3 tools/game-sec/gs.py report <项目名>              # 校验报告章节
python3 tools/game-sec/migrate.py --dry-run               # 预览历史产物迁移
python3 tools/game-sec/migrate.py --apply                 # 执行迁移（可追溯，不删文件）
```

### `gs run` 一键流水线（静态分析全自动）

`gs run` 自动串起可自动化的测试，结尾显式列出需人工/授权的项：

| 阶段 | 自动执行 | 产出 |
|-|-|-|
| 建案 | ✅ 建目录 + README 基线 | README.md |
| APK 分诊 | ✅ apk_triage.py | 01_baseline/*_triage.json |
| 解包 | ✅ unzip 关键内容 | 02_extract/unpacked/ |
| 组件分析 | ✅ 从 triage 自动生成 | 02_extract/component_analysis.md |
| 资源扫描 | ✅ scan_resources.py | 04_resources/scan_report.json |
| metadata 检测 | ✅ 魔数判定加密/明文 | 03_il2cpp/README.md |
| 设备基线 | ⚠️ 需 --device | 01_baseline/device/ |
| 重打包构建 | ⚠️ 需 --repack | 07_repack/ |
| 登录/后端/游戏协议 | ❌ 需账号，人工 | 报告显式标注 |

> **「一次性」的边界**：静态分析（分诊/解包/组件/资源/metadata）可全自动；设备测试（基线/抓包/Frida）需授权设备；登录/后端强校验/游戏协议正文**必须有测试账号**，无法自动完成——`gs run` 会在结尾明确列出这些人工项，模型补完后再 `check` 验收。

### 必测项清单（`gs.py check` 验收依据）

`check` 不只验证"目录非空"，而是**逐项核对方法论 7 层的完成证据**，漏一项即标 ❌：

| 必测项 | 证据 | 强制 |
|-|-|-|
| APK 分诊（包名/版本/引擎/加固/签名） | `01_baseline/` 有 triage/baseline | ✅ |
| 设备基线（型号/Android/root） | `01_baseline/` 有 device 产物 | 条件 |
| 组件安全（exported/WebView/flag） | `02_extract/` 有独立分析 md | ✅ |
| 资源加密全量扫描 | `04_resources/` 有产物 | ✅ |
| IL2CPP 逆向（dump.cs 或加密说明） | `03_il2cpp/` 有产物 | ✅ |
| 动态调试/反调试检测 | `06_frida/` 有产物 | 条件（需设备） |
| 协议抓包 | `05_traffic/` 有 flows | 条件 |
| 重打包验证 | `07_repack/` 有产物 | 条件 |
| 后端强校验结论 | `report.md` 含后端章节 | ✅ |

**条件项**（无设备/无账号）无法完成时，必须在 `report.md` 显式写"未测 + 原因"，不能静默跳过。

规范已写入 skill 的 `SKILL.md`「案件目录规范（强制）」章节；报告统一走 skill 的 `assets/report-template.md` 模板。

## 旧版 scope 机制（`game_sec.py`，可选）

以下 `game_sec.py` 采用 scope 门禁、证据清单和五态 finding，与新规范并存（`gs.py` 更简）。

```bash
CASE=project/<game>/security
APK=project/<game>/<sample>.apk
PKG=com.example.game
DEVICE=<authorized-serial>

python3 tools/game-sec/game_sec.py init "$APK" --case "$CASE" \
  --package "$PKG" --environment test --device "$DEVICE" \
  --allow static --allow device-read --allow frida-observe \
  --allow repack-build --account-label authorized-test-account

python3 tools/game-sec/game_sec.py triage "$APK" --scope "$CASE/scope.json"
python3 tools/game-sec/game_sec.py unity "$APK" --scope "$CASE/scope.json" \
  --dumper /path/to/Il2CppDumper.dll --run-dumper
python3 tools/game-sec/game_sec.py device --scope "$CASE/scope.json" \
  --package "$PKG" --device "$DEVICE"
python3 tools/game-sec/game_sec.py manifest --scope "$CASE/scope.json"
python3 tools/game-sec/game_sec.py report --scope "$CASE/scope.json"
```

## 输出布局

```text
project/<game>/security/
├── scope.json
├── findings.json
├── timeline.jsonl
├── report.md
└── evidence/
    ├── raw/
    ├── derived/
    └── manifest.json
```

`scope.json` 固定 APK SHA-256、包名、环境、设备和允许动作，不存储密码或 token。动态、重签和写操作必须匹配 scope；重签默认只构建，安装需 `repack-install`、设备和 `INSTALL-AUTHORIZED-REPACK` 确认令牌，且脚本拒绝替换已安装原包。

## 引擎路由

- Unity IL2CPP：`unity_il2cpp.py` 提取最小输入并生成 metadata/方法候选；使用 `dump.cs`、`script.json` 和 native 工具核实 socket、序列化、热更、资源、账号、支付和防护边界。
- Cocos：保留 JS/JSC、XXTEA、WebSocket/SSL 和 protobuf 路径。`cocos_proto_dump.js` 与 `xxtea_key_capture.js` 只用于已授权环境。
- 公共检查：签名、manifest、exported 组件、WebView、备份、本地文件、TLS、重打包、运行时保护和服务端权威。

## 工具清单

- `game_sec.py`：统一 CLI 和 scope 校验。
- `apk_triage.py`：流式 APK 分诊、签名、manifest、引擎和静态观察。
- `unity_il2cpp.py`：IL2CPP 输入、metadata 版本、Dumper 和候选面。
- `device_baseline.sh`：只读、脱敏设备基线，不执行 `adb root`。
- `run_probe.py`：有界 Frida JSONL 驱动。
- `repack_sign_test.sh`：默认 build-only 的重签验证。
- `proto_wire_decode.py`：严格边界的 protobuf wire 解码。
- `report_gen.py`：验证证据路径后生成 Markdown 报告。
- `skill_eval.py`：离线检查 Skill 结构、授权门禁和三类路由契约；自动触发仍需新会话 smoke test。

## 结果语义

- `confirmed`：可复现并明确影响。
- `likely`：强证据但缺关键复核。
- `observation`：真实事实，需要上下文判断。
- `not-observed`：本次未观察到，不代表安全。
- `not-tested`：范围或能力未覆盖。

风险为可能性 1-5 × 影响 1-5，置信度单列。动态能力不足时保留 `not-tested`，不得用静态推断填补。

## 质量检查

```bash
python3 -m unittest discover -s tools/game-sec/tests -v
python3 -m compileall -q tools/game-sec
python3 tools/game-sec/skill_eval.py --skill .agents/skills/game-security-testing \
  --out project/<game>/security/tests/skill_eval.json
bash -n tools/game-sec/device_baseline.sh tools/game-sec/repack_sign_test.sh
for f in tools/game-sec/frida/*.js; do node --check "$f"; done
```

依赖：Python 标准库、Android SDK build-tools、adb；Unity Dumper、JADX、IDA 和 Frida 按分析深度可选。动态测试只在明确授权的测试设备和测试环境执行。
