import { scrcpyControlInputSchema } from "../../domain/scrcpy/scrcpyInput.js";
import { z } from "zod";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { toolContractMetadata } from "../toolEffects.js";

const resultSchema = z.object({
  tools: z.array(z.string()),
  provider: z.object({
    id: z.string(),
    name: z.string(),
    version: z.string().nullable(),
  }),
  read_only: z.literal(true),
});

export const SCRCPY_TOOL_CONTRACTS = [
  {
    name: "control_scrcpy_device",
    ...toolContractMetadata("control_scrcpy_device"),
    description:
      "Execute one caller-selected tap, swipe or key event on an explicit Android serial. Changes UI/device state and may activate target behavior. Returns upstream response evidence; a successful input acknowledgement does not prove the intended UI outcome. Does not install software or execute arbitrary shell commands.",
    kind: "scrcpy-provider",
    inputSchema: scrcpyControlInputSchema,
    outputSchema: evidenceResultOf(
      z.object({ upstream_tool: z.string(), response: jsonValueSchema }),
    ),
    examples: [
      {
        title: "Tap a test device",
        input: {
          serial: "emulator-5554",
          action: { kind: "tap", x: 10, y: 20 },
        },
      },
    ],
  },
  {
    name: "observe_scrcpy_device",
    ...toolContractMetadata("observe_scrcpy_device"),
    description:
      "Observe an explicitly selected device through scrcpy MCP: device list, device information or screenshot. Preserves upstream content including image blocks; never invokes input, shell or package operations.",
    kind: "scrcpy-provider",
    inputSchema: z.strictObject({
      operation: z.enum(["device_list", "device_info", "screenshot"]),
      serial: z.string().min(1).optional(),
    }),
    outputSchema: evidenceResultOf(
      z.object({ upstream_tool: z.string(), response: jsonValueSchema }),
    ),
    examples: [{ title: "List devices", input: { operation: "device_list" } }],
  },
  {
    name: "inspect_scrcpy_client",
    ...toolContractMetadata("inspect_scrcpy_client"),
    description:
      "Inspect an explicitly configured scrcpy MCP server and return only its read-only device/screen observation tools. REA does not start it until this tool is called; device-mutating upstream tools are withheld.",
    kind: "scrcpy-provider",
    inputSchema: z.object({}),
    outputSchema: evidenceResultOf(resultSchema),
    examples: [{ title: "Inspect configured scrcpy MCP", input: {} }],
  },
] as const satisfies readonly ToolContract[];
