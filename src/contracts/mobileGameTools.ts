import {
  gameCaseInputSchema,
  gameProtocolInputSchema,
  gameResourceInputSchema,
} from "../domain/mobileGame/gameResourceInput.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";

export const MOBILE_GAME_TOOL_CONTRACTS = [
  {
    name: "convert_game_resources",
    ...toolContractMetadata("convert_game_resources"),
    kind: "application",
    description:
      "Convert caller-selected offline APK or local game resources. Native TypeScript decodes full JSON/MessagePack/Pack.py candidates; selected UnityPy/pycdc/ILSpy engines export objects/source without launching the target. Requires a new output directory. Saves per-file hashes, conversion failures, ambiguity and budget limits in manifest.json. No tools are installed. Unity parsing uses a bundled format helper, not Python workflow orchestration.",
    inputSchema: gameResourceInputSchema,
    outputSchema: evidenceResultOf(jsonValueSchema),
    examples: [
      {
        title: "Convert local configurations",
        input: {
          output_directory: "/tmp/game-converted",
          options: { roots: ["/tmp/game-config"] },
        },
      },
    ],
  },
  {
    name: "inspect_game_case",
    ...toolContractMetadata("inspect_game_case"),
    kind: "application",
    description:
      "Re-observe an existing game case's scope, file hashes and stage evidence. Presence means evidence-present, never completed testing. Refuses symlink evidence. Does not modify the case.",
    inputSchema: gameCaseInputSchema,
    outputSchema: evidenceResultOf(jsonValueSchema),
    examples: [
      {
        title: "Check game evidence",
        input: { case_directory: "/tmp/cases/game/analysis" },
      },
    ],
  },
  {
    name: "report_game_case",
    ...toolContractMetadata("report_game_case"),
    kind: "application",
    description:
      "Generate report.generated.md from an existing game's saved evidence, preserving the analyst's report.md. Includes backend authority unknowns and stage limitations; refuses existing generated output.",
    inputSchema: gameCaseInputSchema,
    outputSchema: evidenceResultOf(jsonValueSchema),
    examples: [
      {
        title: "Generate game report",
        input: { case_directory: "/tmp/cases/game/analysis" },
      },
    ],
  },
  {
    name: "decode_game_protocol",
    ...toolContractMetadata("decode_game_protocol"),
    kind: "application",
    description:
      "Decode one caller-selected raw protobuf message using REA's shared wire decoder. Retains exact offsets, uint64 strings, partial fields and malformed-input reasons. No guessing transport framing, schema field names or cryptographic algorithms. Input budget 16 MiB.",
    inputSchema: gameProtocolInputSchema,
    outputSchema: evidenceResultOf(jsonValueSchema),
    examples: [
      {
        title: "Decode captured raw message",
        input: { path: "/tmp/message.bin" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
