import { z } from "incur";
import {
  GameAnalysisService,
  type GameAnalysisOperation,
} from "../application/mobileGame/GameAnalysisService.js";
import { GameResourceProvider } from "../mobileGame/GameResourceProvider.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import type { CliInstance } from "./types.js";

export const registerGameAnalysisCommands = (cli: CliInstance): void => {
  const execute = (operation: GameAnalysisOperation, input: unknown) =>
    withCommandCancellation(async (signal) => {
      const service = new GameAnalysisService(new GameResourceProvider());
      try {
        const result = await service.execute(operation, input, { signal });
        return result.ok ? result.value : projectAnalysisError(result.error);
      } finally {
        await service.close();
      }
    });
  cli.command(CLI_COMMANDS.convertGameResources, {
    description:
      "Convert offline game configurations, Unity objects and selected scripts into a new output tree",
    args: z.object({
      input: z.string().describe("JSON convert_game_resources input"),
    }),
    run: ({ args }) =>
      execute("convert_game_resources", JSON.parse(args.input)),
  });
  cli.command(CLI_COMMANDS.checkGameCase, {
    description: "Check saved game evidence identity and stage coverage",
    args: z.object({ caseDirectory: z.string() }),
    run: ({ args }) =>
      execute("inspect_game_case", { case_directory: args.caseDirectory }),
  });
  cli.command(CLI_COMMANDS.reportGameCase, {
    description:
      "Generate report.generated.md without overwriting the analyst's report",
    args: z.object({ caseDirectory: z.string() }),
    run: ({ args }) =>
      execute("report_game_case", { case_directory: args.caseDirectory }),
  });
  cli.command(CLI_COMMANDS.decodeGameProtocol, {
    description:
      "Decode one offline raw protobuf message with exact wire offsets and partial facts",
    args: z.object({ path: z.string() }),
    run: ({ args }) => execute("decode_game_protocol", { path: args.path }),
  });
};
