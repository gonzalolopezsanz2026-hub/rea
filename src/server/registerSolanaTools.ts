import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

import type { SolanaProgramService } from "../application/solana/SolanaProgramService.js";
import type { SolanaProgramBatchService } from "../application/solana/SolanaProgramBatchService.js";
import type { SolanaReceiptsService } from "../application/solana/SolanaReceiptsService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { EvidenceLookup } from "../application/EvidenceInputResolver.js";
import {
  solanaProgramBatchModule,
  solanaProgramModule,
  solanaReceiptsModule,
} from "../composition/solana.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { applicationToolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the named Solana contracts to shared validation and session Evidence recording. */
export const registerSolanaTools = (
  server: EvidenceMcpServer,
  service: SolanaProgramService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
  evidenceById?: EvidenceLookup,
  batchService?: SolanaProgramBatchService,
  receiptsService?: SolanaReceiptsService,
): void => {
  const contract = solanaProgramModule.contract;
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.inspect(input, options),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    applicationToolRegistrationOptions(contract),
    handler(contract),
  );
  if (batchService !== undefined) {
    const batchContract = solanaProgramBatchModule.contract;
    const batchHandler = createEvidenceToolHandler(
      server,
      (input, options) => batchService.inspectBatch(input, options),
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    );
    server.registerTool(
      batchContract.name,
      applicationToolRegistrationOptions(batchContract),
      batchHandler(batchContract),
    );
  }
  if (receiptsService !== undefined) {
    const receiptsContract = solanaReceiptsModule.contract;
    const receiptsHandler = createEvidenceToolHandler(
      server,
      (input, options) => receiptsService.buildReceipts(input, options),
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    );
    server.registerTool(
      receiptsContract.name,
      applicationToolRegistrationOptions(receiptsContract),
      receiptsHandler(receiptsContract),
    );
  }
};
