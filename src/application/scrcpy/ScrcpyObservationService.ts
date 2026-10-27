import { scrcpyControlInputSchema } from "../../domain/scrcpy/scrcpyInput.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { z } from "zod";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { AnalysisError as BaseAnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
} from "../../domain/analysisErrorCore.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { ScrcpyProvider } from "../../scrcpy/ScrcpyProvider.js";

const IDENTITY = {
  id: "scrcpy-mcp",
  name: "scrcpy MCP",
  version: null,
} as const;
export class ScrcpyObservationService {
  private readonly active = new Set<ScrcpyProvider>();
  constructor(private readonly createProvider: () => ScrcpyProvider) {}
  async execute(
    operation:
      | "inspect_scrcpy_client"
      | "observe_scrcpy_device"
      | "control_scrcpy_device",
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    let provider: ScrcpyProvider | undefined;
    let result: Result<Evidence, AnalysisError>;
    try {
      provider = this.createProvider();
      this.active.add(provider);
      result = await this.executeWithProvider(
        provider,
        operation,
        input,
        options,
      );
    } catch (cause) {
      result = err(
        cause instanceof BaseAnalysisError
          ? cause
          : new AnalysisProtocolError("scrcpy provider failed", { cause }),
      );
    }
    if (provider !== undefined) {
      try {
        await provider.close();
        this.active.delete(provider);
      } catch (cause) {
        return err(
          new AnalysisProtocolError(
            "scrcpy cleanup failed; ownership retained for retry",
            {
              cause,
              diagnostics: {
                operation_result: result.ok
                  ? result.value
                  : { error: result.error.message },
              },
            },
          ),
        );
      }
    }
    return result;
  }
  private async executeWithProvider(
    provider: ScrcpyProvider,
    operation:
      | "inspect_scrcpy_client"
      | "observe_scrcpy_device"
      | "control_scrcpy_device",
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    try {
      if (operation === "control_scrcpy_device") {
        const parsed = scrcpyControlInputSchema.parse(input);
        const response = await provider.control(parsed, options?.signal);
        return ok(
          createEvidence(undefined, IDENTITY, {
            operation,
            parameters: parsed,
            result: { upstream_tool: parsed.action.kind, response },
            authority: "external-service",
            confidence: "observed",
            limitations: [
              "Input acknowledgement does not establish the resulting UI state.",
            ],
          }),
        );
      }
      if (operation === "observe_scrcpy_device") {
        const parsed = z
          .strictObject({
            operation: z.enum(["device_list", "device_info", "screenshot"]),
            serial: z.string().min(1).optional(),
          })
          .parse(input);
        if (parsed.operation !== "device_list" && parsed.serial === undefined)
          return err(
            new AnalysisInputError(operation, {
              cause: "Explicit serial is required",
            }),
          );
        const response = jsonValueSchema.parse(
          await provider.callReadOnly(
            parsed.operation,
            parsed.serial === undefined ? {} : { serial: parsed.serial },
            options?.signal,
          ),
        );
        return ok(
          createEvidence(undefined, IDENTITY, {
            operation,
            parameters: parsed,
            result: { upstream_tool: parsed.operation, response },
            authority: "external-service",
            confidence: "observed",
          }),
        );
      }
      const observed = await provider.inspect(options?.signal);
      return ok(
        createEvidence(undefined, IDENTITY, {
          operation,
          parameters: {},
          result: { ...observed, provider: IDENTITY, read_only: true },
          authority: "external-service",
          confidence: "observed",
          limitations: [
            "Only catalog names were observed; no device mutation was invoked.",
          ],
        }),
      );
    } catch (cause) {
      if (options?.signal?.aborted)
        return err(
          new AnalysisCancelledError(operation, {
            cause: options.signal.reason,
          }),
        );
      return err(
        cause instanceof BaseAnalysisError
          ? cause
          : new AnalysisProtocolError("scrcpy observation failed", { cause }),
      );
    }
  }
  async close(): Promise<void> {
    const failures: unknown[] = [];
    for (const provider of this.active) {
      try {
        await provider.close();
        this.active.delete(provider);
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length > 0)
      throw new AggregateError(failures, "scrcpy cleanup failed");
  }
}
