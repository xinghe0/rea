# scrcpy MCP

REA connects lazily to the operator-selected stdio server. It does not install scrcpy or platform tools.

The default uses the running Node executable and locked `scrcpy-mcp@0.2.1` dependency installed with this fork. No separate repository or runtime download is required. Configure `REA_SCRCPY_MCP_COMMAND` (e.g. `node`), `REA_SCRCPY_MCP_ARGS` (a JSON array of arguments), optional `SCRCPY_SERVER_PATH`, and `REA_SCRCPY_MCP_TIMEOUT_MS` (default 30000).

Public CLI/MCP operations:

- `inspect-scrcpy-client` / `inspect_scrcpy_client`: discover the catalog.
- `observe-scrcpy-device` / `observe_scrcpy_device`: `device_list`, `device_info`, `screenshot`. Information and screenshot requests require an explicit serial.

Images remain upstream MCP image blocks inside retained Evidence. Device control is separate from observation. Tap, swipe and key events use the typed control contract below. Installation, file transfer and app lifecycle use existing REA ADB contracts. Arbitrary shell forwarding is not exposed.

- `control-scrcpy-device` / `control_scrcpy_device`: explicit serial plus a typed `tap`, `swipe` or `key_event` action. These actions change device/UI state; they are never run by the static assessment.

Example MCP input:

```json
{ "serial": "emulator-5554", "action": { "kind": "tap", "x": 100, "y": 200 } }
```
