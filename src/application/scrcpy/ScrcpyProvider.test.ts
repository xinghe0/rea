import { describe, expect, it, vi } from "vitest";
import type { JsonValue } from "../../domain/jsonValue.js";
import { ScrcpyProvider } from "../../scrcpy/ScrcpyProvider.js";

describe("ScrcpyProvider", () => {
  it("filters catalog and refuses device mutation before upstream invocation", async () => {
    const connection = {
      connect: vi.fn(async () => [
        "device_list",
        "screenshot",
        "tap",
        "shell_exec",
      ]),
      call: vi.fn(
        async (_name: string, _args: Readonly<Record<string, JsonValue>>) =>
          ({ ok: true }) as JsonValue,
      ),
      close: vi.fn(async () => undefined),
    };
    const provider = new ScrcpyProvider(connection);
    await expect(provider.inspect()).resolves.toEqual({
      tools: ["device_list", "screenshot"],
    });
    await expect(provider.callReadOnly("tap", {})).rejects.toThrow(
      "read-only allowlist",
    );
    expect(connection.call).not.toHaveBeenCalled();
    await expect(provider.callReadOnly("screenshot", {})).resolves.toEqual({
      ok: true,
    });
  });
});

it("routes typed control actions and rejects missing serial before execution", async () => {
  const call = vi.fn(async () => ({
    content: [{ type: "text", text: "Tapped" }],
  }));
  const provider = new ScrcpyProvider({
    connect: async () => ["tap"],
    call,
    close: async () => undefined,
  });
  await expect(
    provider.control({ action: { kind: "tap", x: 1, y: 2 } }),
  ).rejects.toThrow();
  expect(call).not.toHaveBeenCalled();
  await provider.control({
    serial: "emulator-5554",
    action: { kind: "tap", x: 1, y: 2 },
  });
  expect(call).toHaveBeenCalledWith(
    "tap",
    { serial: "emulator-5554", x: 1, y: 2 },
    undefined,
  );
  await expect(
    provider.control({
      serial: "emulator-5554",
      action: { kind: "shell_exec", command: "id" },
    }),
  ).rejects.toThrow();
  expect(call).toHaveBeenCalledTimes(1);
});
