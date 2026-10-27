import { resolve } from "node:path";
import { analysisOperationInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { MobileGameAssessmentService } from "./MobileGameAssessmentService.js";
import { createEvidence } from "../../domain/evidence.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";
import type { Evidence } from "../../domain/evidence.js";
import { AnalysisError as BaseAnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { mobileGameAssessmentInputSchema } from "../../domain/mobileGame/mobileGameAssessment.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";

export class MobileGameToolService {
  constructor(private readonly service: MobileGameAssessmentService) {}
  async execute(
    _operation: "assess_mobile_game",
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    try {
      const request = mobileGameAssessmentInputSchema.safeParse(input);
      if (!request.success)
        return {
          ok: false,
          error: analysisOperationInputErrorFromIssues(
            "assess_mobile_game",
            request.error.issues,
            input,
            request.error,
          ),
        };
      const parsed = request.data;
      const result = await this.service.assess(parsed, options?.signal);
      return {
        ok: true,
        value: createEvidence(
          {
            path: resolve(parsed.apk),
            sha256: result.input_sha256,
            format: "apk",
          },
          {
            id: "rea-mobile-game",
            name: "REA mobile game workflow",
            version: null,
          },
          {
            operation: "assess_mobile_game",
            parameters: parsed,
            result,
            confidence: "derived",
            limitations: [
              ...result.not_tested,
              `Assessment coverage: ${result.status}; inspect ${result.check_json}`,
            ],
          },
        ),
      };
    } catch (cause: unknown) {
      if (options?.signal?.aborted)
        return {
          ok: false,
          error: new AnalysisCancelledError("assess_mobile_game", {
            cause: options.signal.reason,
          }),
        };
      return {
        ok: false,
        error:
          cause instanceof BaseAnalysisError
            ? cause
            : new AnalysisOutputError(
                "assess_mobile_game",
                cause instanceof Error ? cause.message : String(cause),
                { cause },
              ),
      };
    }
  }
}
