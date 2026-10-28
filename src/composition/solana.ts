import { SolanaProgramService } from "../application/solana/SolanaProgramService.js";
import { SolanaProgramBatchService } from "../application/solana/SolanaProgramBatchService.js";
import { SolanaReceiptsService } from "../application/solana/SolanaReceiptsService.js";
import { SolanaProgramProvider } from "../solana/SolanaProgramProvider.js";
import { SolanaReceiptsProvider } from "../solana/SolanaReceiptsProvider.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import {
  ANALYZE_SOLANA_PROGRAM_CONTRACT,
  ANALYZE_SOLANA_PROGRAMS_CONTRACT,
  SOLANA_RECEIPTS_CONTRACT,
} from "../contracts/solana/solanaToolContracts.js";

/**
 * Compose the in-process Solana analyzer without import-time I/O. The
 * optional REA_SOLANA_RPC_URL environment value only defaults the endpoint
 * for program-id intake; each call may override it with rpc_url.
 */
export const createSolanaProgramService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): SolanaProgramService =>
  new SolanaProgramService(
    new SolanaProgramProvider(
      environment.REA_SOLANA_RPC_URL === undefined
        ? {}
        : { rpcUrl: environment.REA_SOLANA_RPC_URL },
    ),
  );

/** Compose the batch workflow over a fresh single-program service. */
export const createSolanaProgramBatchService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): SolanaProgramBatchService =>
  new SolanaProgramBatchService(createSolanaProgramService(environment));

/**
 * Static binding of the operation, command and fresh service factory.
 * Construction performs no acquisition, target I/O or import-time execution.
 */
export const solanaProgramModule = {
  contract: ANALYZE_SOLANA_PROGRAM_CONTRACT,
  cliCommand: CLI_COMMANDS.analyzeSolanaProgram,
  create: createSolanaProgramService,
} as const;

/** Static binding for the batch operation over the same provider stack. */
export const solanaProgramBatchModule = {
  contract: ANALYZE_SOLANA_PROGRAMS_CONTRACT,
  cliCommand: CLI_COMMANDS.analyzeSolanaPrograms,
  create: createSolanaProgramBatchService,
} as const;

/** Compose the receipts workflow: a pure join over caller-selected files. */
export const createSolanaReceiptsService = (): SolanaReceiptsService =>
  new SolanaReceiptsService(new SolanaReceiptsProvider());

/** Static binding for the receipts operation. */
export const solanaReceiptsModule = {
  contract: SOLANA_RECEIPTS_CONTRACT,
  cliCommand: CLI_COMMANDS.solanaReceipts,
  create: createSolanaReceiptsService,
} as const;
