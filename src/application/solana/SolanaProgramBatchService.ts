import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import { parseAnalysisInput } from "../AnalysisInput.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { SolanaProgramService } from "./SolanaProgramService.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  analyzeSolanaProgramsInputSchema,
  solanaProgramBatchSchema,
  type AnalyzeSolanaProgramsInput,
  type SolanaProgramAnalysis,
  type SolanaProgramBatch,
  type SolanaProgramBatchItem,
} from "../../domain/solana/solanaProgram.js";
import { err, type Result } from "../../domain/result.js";

const OPERATION = "analyze_solana_programs";
const DEFAULT_CONCURRENCY = 4;

const BATCH_LIMITATIONS: readonly string[] = [
  "Each entry is the single-program analysis of one item with that workflow's own limitations; handler candidates remain reconstruction leads, not a verified instruction inventory.",
  "Items are isolated: a failed item records its error in the index and never blocks the rest of the batch.",
];

/** Derive the item's directory name from its source, deduplicated in order. */
const itemName = (item: SolanaProgramBatchItem, used: Set<string>): string => {
  const raw =
    item.path !== undefined
      ? basename(item.path).replace(/\.(so|elf)$/i, "")
      : (item.program_id as string);
  const cleaned = raw.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  const base = cleaned.length > 0 ? cleaned : "program";
  let name = base;
  for (let suffix = 2; used.has(name); suffix += 1)
    name = `${base}-${String(suffix)}`;
  used.add(name);
  return name;
};

interface PlannedItem {
  readonly item: SolanaProgramBatchItem;
  readonly name: string;
  readonly source: string;
  readonly itemDir: string;
}

/** Run `task` over every index with at most `limit` in flight. */
const runPool = async <T>(
  count: number,
  limit: number,
  task: (index: number) => Promise<T>,
): Promise<readonly T[]> => {
  const results = new Array<T>(count);
  let next = 0;
  const workers = Array.from(
    { length: Math.min(limit, count) },
    async (): Promise<void> => {
      while (true) {
        const index = next;
        next += 1;
        if (index >= count) return;
        results[index] = await task(index);
      }
    },
  );
  await Promise.all(workers);
  return results;
};

/**
 * Batch workflow over the single-program service: the same validation,
 * analysis, and artifact writing per item, plus one `index.json` binding
 * the batch together. This service adds orchestration only — it never
 * re-implements program analysis.
 */
export class SolanaProgramBatchService {
  constructor(readonly programs: SolanaProgramService) {}

  close(): Promise<void> {
    return this.programs.close();
  }

  async inspectBatch(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const input = parseAnalysisInput(
      OPERATION,
      rawInput,
      analyzeSolanaProgramsInputSchema,
      options?.signal,
    );
    if (!input.ok) return input;
    const value: AnalyzeSolanaProgramsInput = input.value;
    const used = new Set<string>();
    const planned: PlannedItem[] = value.items.map((item) => {
      const name = itemName(item, used);
      return {
        item,
        name,
        source: item.path ?? (item.program_id as string),
        itemDir: join(value.out_dir, name),
      };
    });

    const entries = await runPool(
      planned.length,
      value.concurrency ?? DEFAULT_CONCURRENCY,
      async (index): Promise<SolanaProgramBatch["entries"][number]> => {
        const plan = planned[index] as PlannedItem;
        const result = await this.programs.inspect(
          {
            ...(plan.item.path === undefined ? {} : { path: plan.item.path }),
            ...(plan.item.program_id === undefined
              ? {}
              : { program_id: plan.item.program_id }),
            ...(plan.item.rpc_url === undefined
              ? {}
              : { rpc_url: plan.item.rpc_url }),
            out_dir: plan.itemDir,
            ...(value.handoff === undefined ? {} : { handoff: value.handoff }),
            ...(value.instruction_names === undefined
              ? {}
              : { instruction_names: value.instruction_names }),
          },
          options,
        );
        if (!result.ok)
          return {
            name: plan.name,
            source: plan.source,
            status: "error",
            sha256: null,
            slot: null,
            handler_candidates: null,
            dispatch: null,
            analysis_path: null,
            error: result.error.message,
          };
        const analysis = result.value
          .normalized_result as SolanaProgramAnalysis;
        return {
          name: plan.name,
          source: plan.source,
          status: "ok",
          sha256: analysis.artifact.sha256,
          slot: analysis.artifact.slot,
          handler_candidates: analysis.handlers.length,
          dispatch: analysis.dispatch,
          analysis_path: join(plan.itemDir, "solana-analysis.json"),
          error: null,
        };
      },
    );

    const batch: SolanaProgramBatch = {
      out_dir: value.out_dir,
      index_path: join(value.out_dir, "index.json"),
      total: entries.length,
      succeeded: entries.filter((entry) => entry.status === "ok").length,
      failed: entries.filter((entry) => entry.status === "error").length,
      entries: [...entries],
    };
    const parsed = solanaProgramBatchSchema.safeParse(batch);
    if (!parsed.success) return err(outputError());
    const indexBytes = `${JSON.stringify(parsed.data.entries, null, 2)}\n`;
    try {
      await mkdir(value.out_dir, { recursive: true });
      await writeFile(batch.index_path, indexBytes);
    } catch {
      return err(outputError());
    }
    return completeProviderEvidence(
      createEvidence(
        {
          path: batch.index_path,
          sha256: createHash("sha256").update(indexBytes).digest("hex"),
          format: "file",
        },
        this.programs.provider.identity,
        {
          operation: OPERATION,
          parameters: {
            out_dir: value.out_dir,
            items: planned.map((plan) => plan.source),
            ...(value.concurrency === undefined
              ? {}
              : { concurrency: value.concurrency }),
          },
          result: parsed.data,
          confidence: "inferred",
          limitations: [...BATCH_LIMITATIONS],
          locations: [
            { kind: "artifact-path", path: batch.index_path },
            ...parsed.data.entries.flatMap((entry) =>
              entry.analysis_path === null
                ? []
                : [
                    {
                      kind: "artifact-path",
                      path: entry.analysis_path,
                    } as const,
                  ],
            ),
          ],
        },
      ),
      options?.signal,
    );
  }
}

const outputError = (): AnalysisOutputError =>
  new AnalysisOutputError(
    OPERATION,
    "Solana batch analysis could not assemble or write its index.",
  );
