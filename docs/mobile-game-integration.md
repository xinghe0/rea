# Mobile game and scrcpy integration

The mobile game workflow has four owners:

1. `src/domain/mobileGame` owns input and result vocabulary.
2. `src/application/mobileGame` owns case creation, stage ordering, Evidence provenance, coverage and `not-tested` states.
3. Existing REA providers own APK signature, Android/JADX, IL2CPP and ADB observations.
4. CLI and MCP adapters expose the same application workflow.

`tools/game-sec` is a compatibility/helper area. A helper never chooses the case directory, authorization, timeout, cleanup owner or Evidence identity. New default behavior belongs in TypeScript under `src/application/mobileGame`.

The default assessment is static and passive. It creates `scope.json`, `01_baseline`, `02_extract`, `03_il2cpp`, `04_resources`, `report.md` and `check.json`. Dynamic injection, traffic mutation/replay, repackaging/install, protection bypass and key recovery remain explicit `not-tested` stages until a separate contract declares scope, authority and effects.

scrcpy is an optional external MCP boundary. Construction is inert. Every operation owns its own lazy connection, closes it after execution, and retains failed cleanup for retry at server shutdown. Observation uses the exact allowlist `device_list`, `device_info`, `screenshot`. Typed `tap`, `swipe`, `key_event` actions are exposed separately through `control_scrcpy_device`; they require a serial and never run during APK assessment. Application installation, file transfer and app lifecycle use existing REA ADB tools. Arbitrary upstream shell forwarding is not exposed.

The default command uses REA's Node executable and the locked `scrcpy-mcp@0.2.1` dependency installed with this fork; no separate checkout or runtime download is required. Set `REA_SCRCPY_MCP_COMMAND=node` and `REA_SCRCPY_MCP_ARGS='["/absolute/path/to/scrcpy-mcp/dist/index.js"]'` to use a local checkout. The upstream server remains a version-pinned package dependency; the REA adapter and typed contracts live in this fork. REA does not auto-start persistent scrcpy sessions; these observation/control tools use the upstream ADB fallback.

The fork skill source is `internal/skills/game-security-assessment`. The skill generator includes it under the main REA skill's `references/game-security/` and adds a routing link. `rea setup --client <client-id>` therefore installs and updates it through the existing planned/approved, backed-up skill publication mechanism. It is a discoverable subworkflow of the main skill, not a separately registered top-level skill.

Verification uses `npm run check:fast`, the mobile-game workflow tests, and provider boundary tests with a fake MCP connection. A live scrcpy or Android device is required for real-provider verification and is reported separately.

## Implemented public entry points

- `assess_mobile_game` shares the CLI `assess-mobile-game` service. Signature and JADX services are injected by composition. A unique `global-metadata.dat` member is extracted to a fixed case-owned output with a digest and passed to REA IL2CPP; explicit metadata/binary inputs take precedence. Multiple candidates are not silently selected.
- `inspect_scrcpy_client` discovers exact observation tool names.
- `observe_scrcpy_device` supports `device_list`, `device_info`, `screenshot`.
- `control_scrcpy_device` has a separate device-mutating effect declaration and typed tap/swipe/key_event actions. It requires a serial and is never part of automatic APK assessment.

Current limits: pattern scans inspect at most 512 KiB per text member; header recognition does not prove unencrypted contents. Case checks preserve partial status. Optional `capture_path` (CLI `--capture`) reuses REA passive pcap analysis and writes `05_traffic.json`; host/tool limitations remain those of the pcap provider. `convert_game_resources` performs per-file offline conversion with a new output tree, hashes and explicit budgets. Native TS supports full JSON/MessagePack/Pack.py interpretation candidates. A bundled UnityPy format helper exports PNG/audio/OBJ/TextAsset/typetree objects and records individual failures; selected pycdc/ILSpy engines decompile script artifacts. No dependencies are installed by the converters. `resources` / `--resource-options` enables conversion during assessment; unique native IL2CPP binary selection also links the metadata analysis. Explicit `serial` plus `device_package` / `--device-package` acquires game hot-update files using inventory and existing per-file ADB Evidence. Line-based device inventory cannot establish newline-containing filename coverage.

`inspect_game_case` checks saved coverage and hashes, `report_game_case` writes a new generated report, and `decode_game_protocol` reuses REA's protobuf wire decoder. All have CLI equivalents and retained MCP Evidence.

Protection recovery, injection and online protocol mutation are not silently enabled by this migration. The existing REA Frida, apktool, ADB and capture contracts remain separate scope-controlled operations. Engine references document analyst decisions; unsupported/encrypted formats retain unknowns. No real-device or real-game behavior is established by fixture tests.
