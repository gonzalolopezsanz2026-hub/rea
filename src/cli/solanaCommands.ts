import { readdir } from "node:fs/promises";
import { join } from "node:path";

import { z } from "incur";
import {
  solanaProgramBatchModule,
  solanaProgramModule,
  solanaReceiptsModule,
} from "../composition/solana.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import {
  analysisEvidenceDeliveryOptions,
  deliverCliAnalysisEvidence,
} from "./analysisEvidenceDelivery.js";
import { localPathStringSchema } from "../domain/localPath.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";

/** Resolve caller paths and analyze one Solana program through the shared workflow. */
export const registerSolanaCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const service = solanaProgramModule.create(environment);
  cli.command(solanaProgramModule.cliCommand, {
    description:
      "Analyze a Solana sBPF program from a local ELF or by program id via read-only RPC",
    args: z.object({}),
    options: z.object({
      elf: localPathStringSchema
        .optional()
        .describe("Local sBPF ELF to analyze"),
      program: z
        .string()
        .optional()
        .describe("Program id (base58) to fetch through Solana JSON-RPC"),
      rpcUrl: z
        .string()
        .optional()
        .describe(
          "Solana JSON-RPC URL; defaults to REA_SOLANA_RPC_URL or public mainnet",
        ),
      out: localPathStringSchema
        .optional()
        .describe(
          "Output directory for fetched ELF and analysis artifacts; required with --program",
        ),
      handoff: z
        .boolean()
        .optional()
        .describe(
          "Write the deep-decompiler handoff artifact under <out>/handoff",
        ),
      names: z
        .string()
        .optional()
        .describe(
          "Comma-separated Anchor instruction names (e.g. from an IDL) to confirm against handler discriminators",
        ),
      evidence_output: analysisEvidenceDeliveryOptions.evidence_output,
    }),
    run: ({ options }) =>
      withCommandCancellation(async (signal) =>
        logCliCommand(logger, solanaProgramModule.cliCommand, async () =>
          deliverCliAnalysisEvidence({
            run: () =>
              service.inspect(
                {
                  ...(options.elf === undefined
                    ? {}
                    : { path: absoluteCallerPath(options.elf) }),
                  ...(options.program === undefined
                    ? {}
                    : { program_id: options.program }),
                  ...(options.rpcUrl === undefined
                    ? {}
                    : { rpc_url: options.rpcUrl }),
                  ...(options.out === undefined
                    ? {}
                    : { out_dir: absoluteCallerPath(options.out) }),
                  ...(options.handoff === undefined
                    ? {}
                    : { handoff: options.handoff }),
                  ...(options.names === undefined
                    ? {}
                    : {
                        instruction_names: options.names
                          .split(",")
                          .map((name) => name.trim())
                          .filter((name) => name.length > 0),
                      }),
                },
                { signal },
              ),
            service,
            providerId: "solana-sbpf",
            operation: "analyze_solana_program",
            signal,
            detail: "complete",
            evidenceOutput: options.evidence_output,
          }),
        ),
      ),
  });

  const batchService = solanaProgramBatchModule.create(environment);
  cli.command(solanaProgramBatchModule.cliCommand, {
    description:
      "Analyze a batch of Solana sBPF programs (local ELFs and/or program ids) with per-item outputs and an index",
    args: z.object({}),
    options: z.object({
      elf: z
        .array(localPathStringSchema)
        .optional()
        .describe("Local sBPF ELF to analyze (repeatable)"),
      program: z
        .array(z.string())
        .optional()
        .describe(
          "Program id (base58) to fetch through Solana JSON-RPC (repeatable)",
        ),
      dir: localPathStringSchema
        .optional()
        .describe("Directory whose .so files join the batch"),
      rpcUrl: z
        .string()
        .optional()
        .describe(
          "Solana JSON-RPC URL for program items; defaults to REA_SOLANA_RPC_URL or public mainnet",
        ),
      out: localPathStringSchema
        .optional()
        .describe(
          "Output directory receiving one subdirectory per item plus index.json (required)",
        ),
      concurrency: z
        .number()
        .int()
        .min(1)
        .max(8)
        .optional()
        .describe("Maximum items analyzed at once (default 4, cap 8)"),
      handoff: z
        .boolean()
        .optional()
        .describe(
          "Write the deep-decompiler handoff artifact into every item directory",
        ),
      names: z
        .string()
        .optional()
        .describe(
          "Comma-separated Anchor instruction names to confirm against handler discriminators for every item",
        ),
      evidence_output: analysisEvidenceDeliveryOptions.evidence_output,
    }),
    run: ({ options }) =>
      withCommandCancellation(async (signal) =>
        logCliCommand(logger, solanaProgramBatchModule.cliCommand, async () => {
          const items: Record<string, string>[] = [];
          for (const elf of options.elf ?? [])
            items.push({ path: absoluteCallerPath(elf) });
          for (const program of options.program ?? [])
            items.push({
              program_id: program,
              ...(options.rpcUrl === undefined
                ? {}
                : { rpc_url: options.rpcUrl }),
            });
          if (options.dir !== undefined) {
            const dir = absoluteCallerPath(options.dir);
            const names = (await readdir(dir))
              .filter((name) => name.toLowerCase().endsWith(".so"))
              .sort();
            for (const name of names) items.push({ path: join(dir, name) });
          }
          return deliverCliAnalysisEvidence({
            run: () =>
              batchService.inspectBatch(
                {
                  items,
                  ...(options.out === undefined
                    ? {}
                    : { out_dir: absoluteCallerPath(options.out) }),
                  ...(options.concurrency === undefined
                    ? {}
                    : { concurrency: options.concurrency }),
                  ...(options.handoff === undefined
                    ? {}
                    : { handoff: options.handoff }),
                  ...(options.names === undefined
                    ? {}
                    : {
                        instruction_names: options.names
                          .split(",")
                          .map((name) => name.trim())
                          .filter((name) => name.length > 0),
                      }),
                },
                { signal },
              ),
            service: batchService,
            providerId: "solana-sbpf",
            operation: "analyze_solana_programs",
            signal,
            detail: "complete",
            evidenceOutput: options.evidence_output,
          });
        }),
      ),
  });

  const receiptsService = solanaReceiptsModule.create();
  cli.command(solanaReceiptsModule.cliCommand, {
    description:
      "Build differential-verification receipts for Solana program analyses from a caller-supplied evidence JSON",
    args: z.object({}),
    options: z.object({
      analysis: localPathStringSchema
        .optional()
        .describe("Path to one solana-analysis.json to receipt"),
      out: localPathStringSchema
        .optional()
        .describe(
          "Output directory of a single or batch analysis run; receipts are written into it",
        ),
      evidence: localPathStringSchema
        .optional()
        .describe(
          "Differential evidence JSON: one program document, or an array of documents for a batch",
        ),
      evidence_output: analysisEvidenceDeliveryOptions.evidence_output,
    }),
    run: ({ options }) =>
      withCommandCancellation(async (signal) =>
        logCliCommand(logger, solanaReceiptsModule.cliCommand, async () =>
          deliverCliAnalysisEvidence({
            run: () =>
              receiptsService.buildReceipts(
                {
                  ...(options.analysis === undefined
                    ? {}
                    : { analysis_path: absoluteCallerPath(options.analysis) }),
                  ...(options.out === undefined
                    ? {}
                    : { out_dir: absoluteCallerPath(options.out) }),
                  ...(options.evidence === undefined
                    ? {}
                    : { evidence_path: absoluteCallerPath(options.evidence) }),
                },
                { signal },
              ),
            service: receiptsService,
            providerId: "solana-sbpf",
            operation: "solana_receipts",
            signal,
            detail: "complete",
            evidenceOutput: options.evidence_output,
          }),
        ),
      ),
  });
};
