import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { SolanaReceiptsPort } from "../application/solana/SolanaReceiptsPort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import { solanaProgramAnalysisSchema } from "../domain/solana/solanaProgram.js";
import {
  solanaReceiptEvidenceFileSchema,
  type SolanaProgramReceipts,
  type SolanaReceiptEvidence,
  type SolanaReceiptsInput,
  type SolanaReceiptsResult,
} from "../domain/solana/solanaReceipts.js";
import { SOLANA_PROGRAM_PROVIDER_IDENTITY } from "./SolanaProgramProvider.js";
import {
  buildProgramReceipts,
  SolanaReceiptsFailure,
} from "./SolanaReceipts.js";

const OPERATION = "solana_receipts";
/** Receipt inputs are REA-written JSON or a hand-built evidence file; both are small. */
const MAX_JSON_BYTES = 64 * 1024 * 1024;

const inputIssue = (path: string, message: string): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    { path: [path], reason: "invalid_value", message },
  ]);

/** Read and JSON-parse one caller-selected file with the intake error taxonomy. */
const readJsonFile = async (
  path: string,
  field: string,
  signal: AbortSignal | undefined,
): Promise<Result<unknown, AnalysisError>> => {
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    info = await stat(path);
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === "EACCES" || code === "EPERM")
      return err(
        new AnalysisAccessDeniedError(OPERATION, path, code, { cause }),
      );
    if (
      code === "ENOENT" ||
      code === "ENOTDIR" ||
      code === "ELOOP" ||
      code === "ENAMETOOLONG"
    )
      return err(
        inputIssue(
          field,
          `Selected file cannot be resolved: ${path} (${code}).`,
        ),
      );
    return err(
      new ProviderAdapterError(SOLANA_PROGRAM_PROVIDER_IDENTITY.id, OPERATION, {
        cause,
      }),
    );
  }
  if (!info.isFile())
    return err(
      inputIssue(field, `Selected path is not a regular file: ${path}.`),
    );
  if (info.size > MAX_JSON_BYTES)
    return err(
      new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        `Selected file ${path} is ${String(info.size)} bytes, above the ${String(MAX_JSON_BYTES)}-byte intake allowance.`,
        { maximum_bytes: MAX_JSON_BYTES },
      ),
    );
  let text: string;
  try {
    text = await readFile(path, { encoding: "utf8", signal });
  } catch (cause) {
    return err(
      new ProviderAdapterError(SOLANA_PROGRAM_PROVIDER_IDENTITY.id, OPERATION, {
        cause,
      }),
    );
  }
  try {
    return ok(JSON.parse(text) as unknown);
  } catch {
    return err(inputIssue(field, `Selected file is not valid JSON: ${path}.`));
  }
};

const fileExists = async (path: string): Promise<boolean> => {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
};

interface ReceiptTarget {
  readonly name: string;
  readonly analysisPath: string;
  readonly receiptsPath: string;
}

/**
 * Filesystem receipts builder. Reads the selected analysis (a file, a
 * single-run out_dir, or a batch out_dir with its index) plus the caller's
 * evidence file, joins them by artifact SHA-256, and writes one
 * receipts.json per program (plus the aggregate at a batch root). It never
 * runs a differential itself; verdicts derive solely from the evidence the
 * caller supplies.
 */
export class SolanaReceiptsProvider implements SolanaReceiptsPort {
  readonly identity = SOLANA_PROGRAM_PROVIDER_IDENTITY;

  async build(
    input: SolanaReceiptsInput,
    options?: ExecutionOptions,
  ): Promise<Result<SolanaReceiptsResult, AnalysisError>> {
    const signal = options?.signal;
    const evidenceRead = await readJsonFile(
      input.evidence_path,
      "evidence_path",
      signal,
    );
    if (!evidenceRead.ok) return evidenceRead;
    const evidenceParsed = solanaReceiptEvidenceFileSchema.safeParse(
      evidenceRead.value,
    );
    if (!evidenceParsed.success)
      return err(
        inputIssue(
          "evidence_path",
          `Evidence file does not match the receipts evidence schema: ${evidenceParsed.error.issues
            .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
            .join("; ")}`,
        ),
      );
    const documents: readonly SolanaReceiptEvidence[] = Array.isArray(
      evidenceParsed.data,
    )
      ? evidenceParsed.data
      : [evidenceParsed.data];

    let mode: "single" | "batch";
    let targets: ReceiptTarget[];
    let batchRoot: string | undefined;
    if (input.analysis_path !== undefined) {
      mode = "single";
      targets = [
        {
          name: basename(dirname(input.analysis_path)),
          analysisPath: input.analysis_path,
          receiptsPath: join(dirname(input.analysis_path), "receipts.json"),
        },
      ];
    } else {
      const outDir = input.out_dir as string;
      const singleAnalysis = join(outDir, "solana-analysis.json");
      if (await fileExists(singleAnalysis)) {
        mode = "single";
        targets = [
          {
            name: basename(outDir),
            analysisPath: singleAnalysis,
            receiptsPath: join(outDir, "receipts.json"),
          },
        ];
      } else {
        const indexPath = join(outDir, "index.json");
        if (!(await fileExists(indexPath)))
          return err(
            inputIssue(
              "out_dir",
              `Directory holds neither a solana-analysis.json nor a batch index.json: ${outDir}.`,
            ),
          );
        mode = "batch";
        batchRoot = outDir;
        const indexRead = await readJsonFile(indexPath, "out_dir", signal);
        if (!indexRead.ok) return indexRead;
        if (!Array.isArray(indexRead.value))
          return err(
            inputIssue(
              "out_dir",
              `Batch index is not a JSON array: ${indexPath}.`,
            ),
          );
        targets = [];
        for (const entry of indexRead.value) {
          if (typeof entry !== "object" || entry === null) continue;
          const record = entry as Record<string, unknown>;
          if (
            typeof record["name"] === "string" &&
            typeof record["analysis_path"] === "string"
          )
            targets.push({
              name: record["name"],
              analysisPath: record["analysis_path"],
              receiptsPath: join(
                dirname(record["analysis_path"]),
                "receipts.json",
              ),
            });
        }
        if (targets.length === 0)
          return err(
            inputIssue(
              "out_dir",
              `Batch index names no analyzed items: ${indexPath}.`,
            ),
          );
      }
    }

    const programs: SolanaProgramReceipts[] = [];
    const skipped: SolanaReceiptsResult["skipped_items"] = [];
    const usedShas = new Set<string>();
    let singleReceiptBytes: string | undefined;
    for (const target of targets) {
      const fail = (
        message: string,
      ): Result<SolanaReceiptsResult, AnalysisError> | undefined => {
        if (mode === "batch") {
          skipped.push({ name: target.name, reason: message });
          return undefined;
        }
        return err(inputIssue("analysis_path", message));
      };
      const analysisRead = await readJsonFile(
        target.analysisPath,
        "analysis_path",
        signal,
      );
      if (!analysisRead.ok) {
        const failed = fail(
          `Analysis cannot be read: ${target.analysisPath} (${analysisRead.error.message}).`,
        );
        if (failed !== undefined) return failed;
        continue;
      }
      const analysisParsed = solanaProgramAnalysisSchema.safeParse(
        analysisRead.value,
      );
      if (!analysisParsed.success) {
        const failed = fail(
          `File is not a solana program analysis: ${target.analysisPath}.`,
        );
        if (failed !== undefined) return failed;
        continue;
      }
      const analysis = analysisParsed.data;
      usedShas.add(analysis.artifact.sha256);
      const document = documents.find(
        (candidate) =>
          candidate.program.elf_sha256 === analysis.artifact.sha256,
      );
      if (document === undefined && mode === "single")
        return err(
          inputIssue(
            "evidence_path",
            `Evidence covers ${documents
              .map((candidate) => candidate.program.elf_sha256)
              .join(
                ", ",
              )}, but the analysis covers artifact ${analysis.artifact.sha256}; refusing to emit receipts across artifacts.`,
          ),
        );
      let program: SolanaProgramReceipts;
      try {
        program = buildProgramReceipts(
          analysis,
          document,
          target.analysisPath,
          target.receiptsPath,
        );
      } catch (cause) {
        if (cause instanceof SolanaReceiptsFailure) {
          const failed = fail(cause.message);
          if (failed !== undefined) return failed;
          continue;
        }
        throw cause;
      }
      const bytes = `${JSON.stringify(program, null, 2)}\n`;
      try {
        await mkdir(dirname(target.receiptsPath), { recursive: true });
        await writeFile(target.receiptsPath, bytes, { signal });
      } catch (cause) {
        return err(
          new ProviderAdapterError(
            SOLANA_PROGRAM_PROVIDER_IDENTITY.id,
            OPERATION,
            { cause },
          ),
        );
      }
      if (mode === "single") singleReceiptBytes = bytes;
      programs.push(program);
    }
    if (programs.length === 0)
      return err(
        inputIssue(
          "analysis_path",
          `No program could be receipted: ${skipped
            .map((item) => `${item.name}: ${item.reason}`)
            .join("; ")}`,
        ),
      );

    const totals = {
      total_candidates: programs.reduce(
        (sum, program) => sum + program.summary.total_candidates,
        0,
      ),
      recovered: programs.reduce(
        (sum, program) => sum + program.summary.recovered,
        0,
      ),
      failed: programs.reduce(
        (sum, program) => sum + program.summary.failed,
        0,
      ),
      not_a_handler: programs.reduce(
        (sum, program) => sum + program.summary.not_a_handler,
        0,
      ),
      leads: programs.reduce((sum, program) => sum + program.summary.leads, 0),
      orphans: programs.reduce(
        (sum, program) => sum + program.summary.orphans.length,
        0,
      ),
    };
    const orphanPrograms = documents
      .filter((document) => !usedShas.has(document.program.elf_sha256))
      .map((document) => document.program.elf_sha256);

    if (mode === "single") {
      const only = programs[0] as SolanaProgramReceipts;
      return ok({
        mode,
        receipts_path: only.program.receipts_path,
        receipts_sha256: createHash("sha256")
          .update(singleReceiptBytes as string)
          .digest("hex"),
        programs,
        totals,
        orphan_programs: orphanPrograms,
        skipped_items: skipped,
      });
    }
    const rootPath = join(batchRoot as string, "receipts.json");
    const rootBytes = `${JSON.stringify(
      {
        mode,
        programs,
        totals,
        orphan_programs: orphanPrograms,
        skipped_items: skipped,
      },
      null,
      2,
    )}\n`;
    try {
      await writeFile(rootPath, rootBytes, { signal });
    } catch (cause) {
      return err(
        new ProviderAdapterError(
          SOLANA_PROGRAM_PROVIDER_IDENTITY.id,
          OPERATION,
          {
            cause,
          },
        ),
      );
    }
    return ok({
      mode,
      receipts_path: rootPath,
      receipts_sha256: createHash("sha256").update(rootBytes).digest("hex"),
      programs,
      totals,
      orphan_programs: orphanPrograms,
      skipped_items: skipped,
    });
  }
}
