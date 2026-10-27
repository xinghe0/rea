import { scrcpyControlInputSchema } from "../domain/scrcpy/scrcpyInput.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { ScrcpyMcpConnection } from "./ScrcpyMcpConnection.js";

export const SCRCPY_READ_TOOLS = new Set([
  "device_list",
  "device_info",
  "screenshot",
]);

/** Exact observation allowlist and separately validated device input actions. */
export class ScrcpyProvider {
  constructor(private readonly connection: ScrcpyMcpConnection) {}
  async inspect(
    signal?: AbortSignal,
  ): Promise<Readonly<{ tools: readonly string[] }>> {
    const tools = await this.connection.connect(signal);
    return { tools: tools.filter((name) => SCRCPY_READ_TOOLS.has(name)) };
  }
  async callReadOnly(
    name: string,
    args: Readonly<Record<string, JsonValue>> = {},
    signal?: AbortSignal,
  ): Promise<JsonValue> {
    if (!SCRCPY_READ_TOOLS.has(name))
      throw new Error(
        `scrcpy tool is outside the read-only allowlist: ${name}`,
      );
    return this.connection.call(name, args, signal);
  }
  async control(input: unknown, signal?: AbortSignal): Promise<JsonValue> {
    const parsed = scrcpyControlInputSchema.parse(input);
    const { kind, ...parameters } = parsed.action;
    return this.connection.call(
      kind,
      { ...parameters, serial: parsed.serial },
      signal,
    );
  }
  close(): Promise<void> {
    return this.connection.close();
  }
}
