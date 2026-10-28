import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { BtfPort } from "./BtfPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  MAX_INSPECT_BTF_EXT_PAGE,
  MAX_INSPECT_BTF_TYPE_PAGE,
  btfSchema,
  inspectBtfInputSchema,
  type Btf,
} from "../../domain/native/btf.js";
import { BINARY_ARCHITECTURES } from "../../domain/binaryTargetTypes.js";
import { elfArchitecture } from "../../domain/elfFixedHeader.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { parseAnalysisInput } from "../AnalysisInput.js";

const OPERATION = "inspect_btf";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class BtfService {
  constructor(readonly provider: BtfPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const input = parseAnalysisInput(
      OPERATION,
      rawInput,
      inspectBtfInputSchema,
      options?.signal,
    );
    if (!input.ok) return input;
    if (!isAbsolute(input.value.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const result = await this.provider.inspect(input.value, options);
    if (!result.ok) return result;
    const report = btfSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.value.path ||
      !validReport(report.data, input.value)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "BTF provider returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    const elf = value.elf;
    const architecture =
      elf === null
        ? undefined
        : BINARY_ARCHITECTURES.find(
            (supported) => supported === elfArchitecture(elf.machine),
          );
    const locations = [
      { kind: "artifact-path" as const, path: value.artifact.path },
      ...(value.section === null
        ? [
            {
              kind: "file-offset-range" as const,
              start: value.header.type.offset,
              end: value.header.type.offset + value.header.type.bytes,
            },
            {
              kind: "file-offset-range" as const,
              start: value.header.string.offset,
              end: value.header.string.offset + value.header.string.bytes,
            },
          ]
        : [
            {
              kind: "file-offset-range" as const,
              start: value.section.location.offset,
              end: value.section.location.offset + value.section.location.bytes,
            },
          ]),
    ];
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          format: value.carrier === "standalone" ? "file" : "elf",
          sha256: value.artifact.sha256,
          ...(architecture === undefined ? {} : { architecture }),
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.value,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations,
        },
      ),
      options?.signal,
    );
  }
}

const validReport = (
  report: Btf,
  input: { max_file_bytes: number },
): boolean => {
  if (report.artifact.bytes > input.max_file_bytes) return false;
  if (report.types.page.returned > report.types.page.limit) return false;
  if (report.types.page.returned !== report.types.entries.length) return false;
  if (report.types.page.limit > MAX_INSPECT_BTF_TYPE_PAGE) return false;
  const selection = report.ext?.selection ?? null;
  if (selection !== null && selection.limit > MAX_INSPECT_BTF_EXT_PAGE)
    return false;
  const blobBytes =
    report.section === null
      ? report.artifact.bytes
      : report.section.location.bytes;
  const inside = (range: { offset: number; bytes: number }) =>
    range.offset <= blobBytes - range.bytes;
  return (
    inside(report.header.type) &&
    inside(report.header.string) &&
    (report.section === null ||
      (report.section.location.offset <=
        report.artifact.bytes - report.section.location.bytes &&
        report.elf !== null))
  );
};
