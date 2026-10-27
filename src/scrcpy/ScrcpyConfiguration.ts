import { createRequire } from "node:module";
import { z } from "zod";
import { err, ok, type Result } from "../domain/result.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";

export const scrcpyConfigurationSchema = z.object({
  command: z.string().min(1).default(process.execPath),
  args: z
    .array(z.string())
    .default([createRequire(import.meta.url).resolve("scrcpy-mcp")]),
  serverPath: z.string().min(1).optional(),
  timeoutMs: z.number().int().positive().max(120_000).default(30_000),
});
export type ScrcpyConfiguration = z.infer<typeof scrcpyConfigurationSchema>;

export const parseScrcpyConfiguration = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): Result<ScrcpyConfiguration, AnalysisInputError> => {
  let args: unknown;
  try {
    args =
      environment.REA_SCRCPY_MCP_ARGS === undefined
        ? undefined
        : JSON.parse(environment.REA_SCRCPY_MCP_ARGS);
  } catch (cause) {
    return err(new AnalysisInputError("scrcpy_configuration", { cause }));
  }
  const parsed = scrcpyConfigurationSchema.safeParse({
    ...(environment.REA_SCRCPY_MCP_COMMAND === undefined
      ? {}
      : { command: environment.REA_SCRCPY_MCP_COMMAND }),
    ...(environment.REA_SCRCPY_MCP_ARGS === undefined
      ? environment.REA_SCRCPY_MCP_COMMAND === undefined
        ? {}
        : { args: [] }
      : { args }),
    ...(environment.SCRCPY_SERVER_PATH === undefined
      ? {}
      : { serverPath: environment.SCRCPY_SERVER_PATH }),
    ...(environment.REA_SCRCPY_MCP_TIMEOUT_MS === undefined
      ? {}
      : { timeoutMs: Number(environment.REA_SCRCPY_MCP_TIMEOUT_MS) }),
  });
  return parsed.success
    ? ok(parsed.data)
    : err(
        new AnalysisInputError("scrcpy_configuration", { cause: parsed.error }),
      );
};
