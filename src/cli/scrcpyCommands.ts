import { z } from "incur";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import type { CliInstance } from "./types.js";
import { createScrcpyMcpProvider } from "../composition/scrcpy.js";
import { ScrcpyObservationService } from "../application/scrcpy/ScrcpyObservationService.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { withCommandCancellation } from "./commandCancellation.js";

export const registerScrcpyCommands = (
  cli: CliInstance,
  environment: Readonly<Record<string, string | undefined>>,
): void => {
  const execute = (
    operation:
      | "inspect_scrcpy_client"
      | "observe_scrcpy_device"
      | "control_scrcpy_device",
    input: unknown,
  ) =>
    withCommandCancellation(async (signal) => {
      const provider = createScrcpyMcpProvider(environment);
      if (!provider.ok) return projectAnalysisError(provider.error);
      const result = await new ScrcpyObservationService(
        () => provider.value.provider,
      ).execute(operation, input, { signal });
      return result.ok ? result.value : projectAnalysisError(result.error);
    });
  cli.command(CLI_COMMANDS.controlScrcpyDevice, {
    description:
      "Send one typed tap, swipe or key event to an explicit Android serial",
    args: z.object({
      serial: z.string(),
      action: z
        .string()
        .describe(
          "JSON action: kind tap/swipe/key_event and its named parameters",
        ),
    }),
    run: ({ args }) =>
      execute("control_scrcpy_device", {
        serial: args.serial,
        action: JSON.parse(args.action),
      }),
  });
  cli.command(CLI_COMMANDS.inspectScrcpyClient, {
    description: "Inspect the configured scrcpy MCP catalog",
    args: z.object({}),
    run: () => execute("inspect_scrcpy_client", {}),
  });
  cli.command(CLI_COMMANDS.observeScrcpyDevice, {
    description:
      "List devices, inspect a selected device or capture its screen",
    args: z.object({
      operation: z.enum(["device_list", "device_info", "screenshot"]),
    }),
    options: z.object({ serial: z.string().optional() }),
    run: ({ args, options }) =>
      execute("observe_scrcpy_device", {
        ...args,
        ...(options.serial === undefined ? {} : { serial: options.serial }),
      }),
  });
};
