import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { ScrcpyObservationService } from "../application/scrcpy/ScrcpyObservationService.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolContract } from "../contracts/toolContracts.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export const registerScrcpyTools = (
  server: EvidenceMcpServer,
  service: ScrcpyObservationService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  for (const contract of [
    toolContract("inspect_scrcpy_client"),
    toolContract("observe_scrcpy_device"),
    toolContract("control_scrcpy_device"),
  ] as const) {
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      createContractToolHandler(
        server,
        service,
        logger,
        recordEvidence,
        withAdmittedAnalysis,
      )(contract),
    );
  }
};
