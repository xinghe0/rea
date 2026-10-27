import { gameResourceOptionsSchema } from "./gameResourceInput.js";
import { z } from "zod";

export const mobileGameAssessmentInputSchema = z.object({
  apk: z.string().min(1),
  game: z
    .string()
    .min(1)
    .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/u),
  case_root: z.string().min(1),
  resources: gameResourceOptionsSchema.default({
    roots: [],
    convert_configs: true,
    extract_apk: false,
    max_file_bytes: 16 * 1024 * 1024,
    max_total_bytes: 1024 * 1024 * 1024,
  }),
  device_package: z
    .string()
    .regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$/u)
    .optional(),
  capture_path: z.string().min(1).optional(),
  metadata_path: z.string().min(1).optional(),
  binary_path: z.string().min(1).optional(),
  serial: z.string().min(1).optional(),
  timeout_ms: z.number().int().positive().max(600_000).optional(),
});

export type MobileGameAssessmentInput = z.infer<
  typeof mobileGameAssessmentInputSchema
>;

export const mobileGameAssessmentResultSchema = z.object({
  case_directory: z.string(),
  input_sha256: z.string(),
  triage_json: z.string(),
  triage_markdown: z.string(),
  status: z.enum(["partial", "failed"]),
  check_json: z.string(),
  report_markdown: z.string(),
  stages: z.array(z.string()),
  not_tested: z.array(z.string()),
});

export type MobileGameAssessmentResult = z.infer<
  typeof mobileGameAssessmentResultSchema
>;
