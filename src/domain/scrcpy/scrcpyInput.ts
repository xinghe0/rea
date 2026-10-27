import { z } from "zod";
const serial = z
  .string()
  .min(1)
  .regex(/^[^\x00\s]+$/u);
export const scrcpyControlInputSchema = z.strictObject({
  serial,
  action: z.discriminatedUnion("kind", [
    z.strictObject({
      kind: z.literal("tap"),
      x: z.number().int().nonnegative(),
      y: z.number().int().nonnegative(),
    }),
    z.strictObject({
      kind: z.literal("swipe"),
      x1: z.number().int().nonnegative(),
      y1: z.number().int().nonnegative(),
      x2: z.number().int().nonnegative(),
      y2: z.number().int().nonnegative(),
      duration: z.number().int().positive().default(300),
    }),
    z.strictObject({
      kind: z.literal("key_event"),
      keycode: z.union([
        z.string().regex(/^(?:KEYCODE_)?[A-Z0-9_]+$/u),
        z.number().int().nonnegative(),
      ]),
    }),
  ]),
});
