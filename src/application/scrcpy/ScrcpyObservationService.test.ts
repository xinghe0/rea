import { expect, it, vi } from "vitest";
import { ScrcpyObservationService } from "./ScrcpyObservationService.js";
import { ScrcpyProvider } from "../../scrcpy/ScrcpyProvider.js";

it("gives concurrent requests separate connection owners", async () => {
  const connections: { close: ReturnType<typeof vi.fn> }[] = [];
  const service = new ScrcpyObservationService(() => {
    const connection = {
      connect: async () => ["device_list"],
      call: async () => ({ content: [] }),
      close: vi.fn(async () => undefined),
    };
    connections.push(connection);
    return new ScrcpyProvider(connection);
  });
  const results = await Promise.all([
    service.execute("inspect_scrcpy_client", {}),
    service.execute("observe_scrcpy_device", { operation: "device_list" }),
  ]);
  expect(results.every((result) => result.ok)).toBe(true);
  expect(connections).toHaveLength(2);
  for (const connection of connections)
    expect(connection.close).toHaveBeenCalledTimes(1);
});

it("retains completed evidence when cleanup fails and retries owned cleanup", async () => {
  const close = vi
    .fn()
    .mockRejectedValueOnce(new Error("cleanup failed"))
    .mockResolvedValue(undefined);
  const service = new ScrcpyObservationService(
    () =>
      new ScrcpyProvider({
        connect: async () => ["device_list"],
        call: async () => ({ content: [] }),
        close,
      }),
  );
  const result = await service.execute("inspect_scrcpy_client", {});
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.error.message).toContain("cleanup failed");
    expect(JSON.stringify(result.error)).toContain("operation_result");
  }
  await service.close();
  expect(close).toHaveBeenCalledTimes(2);
  await service.close();
  expect(close).toHaveBeenCalledTimes(2);
});
