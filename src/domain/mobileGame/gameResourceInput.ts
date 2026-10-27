import { z } from "zod";

const command = z.strictObject({
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
});
/** Caller-selected offline conversion engines. No downloads or target-code execution. */
export const gameResourceOptionsSchema = z.strictObject({
  roots: z.array(z.string().min(1)).default([]),
  convert_configs: z.boolean().default(true),
  extract_apk: z.boolean().default(false),
  unity_python: z.string().min(1).optional(),
  pycdc: command.optional(),
  ilspy: command.optional(),
  max_file_bytes: z
    .number()
    .int()
    .positive()
    .max(256 * 1024 * 1024)
    .default(16 * 1024 * 1024),
  max_total_bytes: z
    .number()
    .int()
    .positive()
    .max(16 * 1024 * 1024 * 1024)
    .default(1024 * 1024 * 1024),
});
export const gameResourceInputSchema = z
  .strictObject({
    apk: z.string().min(1).optional(),
    output_directory: z.string().min(1),
    options: gameResourceOptionsSchema.default({
      roots: [],
      convert_configs: true,
      extract_apk: false,
      max_file_bytes: 16 * 1024 * 1024,
      max_total_bytes: 1024 * 1024 * 1024,
    }),
  })
  .refine(
    (input) => input.apk !== undefined || input.options.roots.length > 0,
    "An APK or local resource root is required",
  );
export type GameResourceInput = z.infer<typeof gameResourceInputSchema>;
export type GameResourceOptions = z.infer<typeof gameResourceOptionsSchema>;
export const gameCaseInputSchema = z.strictObject({
  case_directory: z.string().min(1),
});
export const gameProtocolInputSchema = z.strictObject({
  path: z.string().min(1),
});
