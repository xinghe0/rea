import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { readRegularFile } from "../RegularFileRead.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import { analysisOperationInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  gameCaseInputSchema,
  gameProtocolInputSchema,
  gameResourceInputSchema,
} from "../../domain/mobileGame/gameResourceInput.js";
import {
  ProtobufBudget,
  decodeProtobufWire,
} from "../../browser/history/protobuf/ProtobufWire.js";
import type { GameResourceProvider } from "../../mobileGame/GameResourceProvider.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { inspectGameCase, writeGameCaseReport } from "./GameCaseService.js";

const schemas = {
  convert_game_resources: gameResourceInputSchema,
  inspect_game_case: gameCaseInputSchema,
  report_game_case: gameCaseInputSchema,
  decode_game_protocol: gameProtocolInputSchema,
} as const;
export type GameAnalysisOperation = keyof typeof schemas;
/** One workflow and Evidence boundary for public CLI and MCP operations. */
export class GameAnalysisService {
  constructor(private readonly resources: GameResourceProvider) {}
  close(): Promise<void> {
    return this.resources.close();
  }
  async execute(
    operation: GameAnalysisOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    try {
      options?.signal?.throwIfAborted();
      const request = schemas[operation].safeParse(input);
      if (!request.success)
        return err(
          analysisOperationInputErrorFromIssues(
            operation,
            request.error.issues,
            input,
            request.error,
          ),
        );
      let result: unknown;
      let target: { path: string; sha256: string; format: "file" } | undefined;
      if (operation === "convert_game_resources")
        result = await this.resources.convert(
          gameResourceInputSchema.parse(request.data),
          options?.signal,
        );
      else if (operation === "inspect_game_case")
        result = await inspectGameCase(
          gameCaseInputSchema.parse(request.data).case_directory,
          options?.signal,
        );
      else if (operation === "report_game_case")
        result = await writeGameCaseReport(
          gameCaseInputSchema.parse(request.data).case_directory,
          options?.signal,
        );
      else {
        const path = resolve(gameProtocolInputSchema.parse(request.data).path);
        const bytes = await readRegularFile(path, {
          signal: options?.signal,
          symlinks: "reject",
          admit: (state) => {
            if (state.size > 16 * 1024 * 1024)
              throw new AnalysisResourceConstraintError(
                operation,
                "file-size",
                "Protocol input exceeds 16 MiB",
                { max_bytes: 16 * 1024 * 1024 },
              );
          },
        });
        target = {
          path,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          format: "file",
        };
        result = await decodeProtobufWire(
          bytes,
          0,
          bytes.length,
          0,
          new ProtobufBudget(options?.signal),
          (text) => text,
        );
      }
      options?.signal?.throwIfAborted();
      return ok(
        createEvidence(
          target,
          {
            id: "rea-game-analysis",
            name: "REA offline game analysis",
            version: "1",
          },
          {
            operation,
            parameters: request.data,
            result,
            confidence: "derived",
            limitations: [
              "Decoded candidates and converter outputs do not establish vulnerabilities or runtime equivalence.",
            ],
          },
        ),
      );
    } catch (cause) {
      return err(
        cause instanceof AnalysisError
          ? cause
          : options?.signal?.aborted
            ? new AnalysisCancelledError(operation, {
                cause: options.signal.reason,
              })
            : new AnalysisOutputError(
                operation,
                cause instanceof Error ? cause.message : String(cause),
                { cause },
              ),
      );
    }
  }
}
