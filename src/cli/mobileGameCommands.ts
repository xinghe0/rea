import { GameResourceProvider } from "../mobileGame/GameResourceProvider.js";
import { gameResourceOptionsSchema } from "../domain/mobileGame/gameResourceInput.js";
import { createAdbDeviceAnalysisProvider } from "../composition/adb.js";
import { AdbDeviceAnalysisService } from "../application/adb/AdbDeviceAnalysisService.js";
import { createPcapAnalysisProvider } from "../composition/pcap.js";
import { PcapAnalysisService } from "../application/pcap/PcapAnalysisService.js";
import { createAndroidAnalysisProvider } from "../composition/android.js";
import { AndroidAnalysisService } from "../application/android/AndroidAnalysisService.js";
import { createIl2cppMetadataService } from "../composition/il2cpp.js";
import { createApkSignatureService } from "../composition/apkSignature.js";
import { MobileGameToolService } from "../application/mobileGame/MobileGameToolService.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { z } from "incur";
import { resolve } from "node:path";
import { MobileGameAssessmentService } from "../application/mobileGame/MobileGameAssessmentService.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import type { CliInstance } from "./types.js";
import type { Logger } from "pino";
import { logCliCommand } from "../cliLogging.js";
import { withCommandCancellation } from "./commandCancellation.js";

export const registerMobileGameCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.assessMobileGame, {
    description:
      "Run a bounded static and passive assessment for an authorized Android game APK",
    args: z.object({ apk: z.string().min(1), game: z.string().min(1) }),
    options: z.object({
      resourceOptions: z
        .string()
        .optional()
        .describe("JSON resource conversion options"),
      devicePackage: z.string().optional(),
      capture: z.string().optional(),
      metadata: z.string().optional(),
      binary: z.string().optional(),
      serial: z.string().optional(),
      caseRoot: z.string().min(1),
      timeoutMs: z.number().int().positive().optional(),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.assessMobileGame, async () => {
          const signatures = createApkSignatureService();
          const il2cpp = createIl2cppMetadataService();
          const android = createAndroidAnalysisProvider();
          const pcap = createPcapAnalysisProvider();
          const resources = new GameResourceProvider();
          const adb = createAdbDeviceAnalysisProvider();
          try {
            const result = await new MobileGameToolService(
              new MobileGameAssessmentService(
                signatures,
                il2cpp,
                new AndroidAnalysisService(android),
                new PcapAnalysisService(pcap),
                resources,
                new AdbDeviceAnalysisService(adb),
              ),
            ).execute(
              "assess_mobile_game",
              {
                apk: resolve(args.apk),
                ...(options.resourceOptions === undefined
                  ? {}
                  : {
                      resources: gameResourceOptionsSchema.parse(
                        JSON.parse(options.resourceOptions),
                      ),
                    }),
                ...(options.devicePackage === undefined
                  ? {}
                  : { device_package: options.devicePackage }),
                ...(options.capture === undefined
                  ? {}
                  : { capture_path: resolve(options.capture) }),
                ...(options.metadata === undefined
                  ? {}
                  : { metadata_path: resolve(options.metadata) }),
                ...(options.binary === undefined
                  ? {}
                  : { binary_path: resolve(options.binary) }),
                game: args.game,
                case_root: resolve(options.caseRoot),
                ...(options.serial === undefined
                  ? {}
                  : { serial: options.serial }),
                ...(options.timeoutMs === undefined
                  ? {}
                  : { timeout_ms: options.timeoutMs }),
              },
              { signal },
            );
            return result.ok
              ? result.value
              : projectAnalysisError(result.error);
          } finally {
            const outcomes = await Promise.allSettled([
              signatures.close(),
              il2cpp.close(),
              android.close(),
              pcap.close(),
              resources.close(),
              adb.close(),
            ]);
            const failures = outcomes.filter(
              (outcome) => outcome.status === "rejected",
            );
            if (failures.length > 0)
              throw new AggregateError(
                failures.map((failure) => failure.reason),
                "Mobile assessment provider cleanup failed",
              );
          }
        }),
      ),
  });
};
