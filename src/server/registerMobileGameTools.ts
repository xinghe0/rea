import { GameAnalysisService } from "../application/mobileGame/GameAnalysisService.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { MobileGameAssessmentService } from "../application/mobileGame/MobileGameAssessmentService.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolContract } from "../contracts/toolContracts.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { MobileGameToolService } from "../application/mobileGame/MobileGameToolService.js";

export const registerMobileGameTools = (
  server: EvidenceMcpServer,
  service: MobileGameAssessmentService,
  gameAnalysis: GameAnalysisService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  for (const name of [
    "convert_game_resources",
    "inspect_game_case",
    "report_game_case",
    "decode_game_protocol",
  ] as const) {
    const contract = toolContract(name);
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      createContractToolHandler(
        server,
        gameAnalysis,
        logger,
        recordEvidence,
        withAdmittedAnalysis,
      )(contract),
    );
  }
  const contract = toolContract("assess_mobile_game");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    createContractToolHandler(
      server,
      new MobileGameToolService(service),
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    )(contract),
  );
};
