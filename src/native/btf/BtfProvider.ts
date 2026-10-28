import {
  projectStableArtifactFailure,
  projectArtifactCloseFailure,
} from "../../artifacts/StableArtifactFailure.js";
import { isSelectedRegularFileError } from "../../filesystem/RegularFile.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import {
  artifactFilePrimaryFacts,
  type ArtifactFilePrimaryFacts,
  artifactFileCancellationCause,
} from "../../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { BtfPort } from "../../application/binaryDiagnostics/BtfPort.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { ArtifactOperationError } from "../../domain/artifactOperationError.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import { fixedAllowanceOptions } from "../../domain/fixedAllowanceRemediation.js";
import {
  MAX_INSPECT_BTF_FILE_BYTES,
  type InspectBtfInput,
} from "../../domain/native/btf.js";
import { err, ok } from "../../domain/result.js";
import { BTF_PROVIDER } from "../../domain/investigationProviders.js";
import { selectBtfCarrier } from "./BtfCarrier.js";
import { parseBtf } from "./BtfParser.js";
import { BinaryFormatFailure } from "../metadata/BinaryContainer.js";

const OPERATION = "inspect_btf";

/** Portable parser over one bounded, identity-checked regular file. */
export class BtfProvider implements BtfPort {
  readonly identity = BTF_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(cause, BTF_PROVIDER.id, OPERATION);
    }
  }

  async inspect(input: InspectBtfInput, options?: ExecutionOptions) {
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        );
        const artifact = {
          path: input.path,
          sha256: snapshot.sha256,
          bytes: snapshot.bytes.length,
        };
        const carrier = selectBtfCarrier(
          snapshot.bytes,
          input.section,
          input.max_file_bytes,
        );
        return ok(parseBtf(carrier, artifact, input));
      });
    } catch (cause) {
      return err(btfFailure(cause, input));
    }
  }
}

const NAME_TEXT_BUDGET =
  "The ELF section-name text and scan budget fixed by the admitted image length";

const inputBudgetRemediation = (
  boundary: "file-size" | "capacity",
  input: InspectBtfInput,
): string =>
  boundary === "file-size"
    ? input.max_file_bytes >= MAX_INSPECT_BTF_FILE_BYTES
      ? `The artifact exceeds the ${String(MAX_INSPECT_BTF_FILE_BYTES)}-byte input ceiling this operation accepts; select a smaller artifact.`
      : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes or select a smaller artifact; the limit is the caller-selected input read budget.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} or select a smaller artifact; the limit is the caller-selected input budget.`;

const btfFailurePrimary = (
  facts: ArtifactFilePrimaryFacts,
  input: InspectBtfInput,
) => {
  const { cause, origin } = facts;
  if (cause instanceof BinaryFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          cause.message,
          { cause },
        )
      : new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: cause.message,
          },
        ]);
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure &&
    cause.reason === "integrity"
  )
    return new AnalysisArtifactChangedError(
      OPERATION,
      input.path,
      cause.message,
      {
        cause,
      },
    );
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure &&
    cause.reason === "cancelled"
  )
    return new AnalysisCancelledError(OPERATION, {
      cause: artifactFileCancellationCause(cause),
    });
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure
  ) {
    if (cause.reason === "limit") {
      const memory = cause.boundary === "memory";
      return new AnalysisResourceConstraintError(
        OPERATION,
        cause.boundary ?? "memory",
        cause.message,
        {
          max_file_bytes: input.max_file_bytes,
        },
        {
          cause,
          ...(cause.boundary === undefined
            ? {}
            : memory
              ? fixedAllowanceOptions(NAME_TEXT_BUDGET, "parser")
              : {
                  retryable: false as const,
                  remediationAction: inputBudgetRemediation(
                    cause.boundary,
                    input,
                  ),
                }),
        },
      );
    }
    if (cause.reason === "path" || cause.reason === "format")
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: cause.message,
        },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, input.path, cause.code, {
        cause,
      });
    if (isSelectedRegularFileError(cause))
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected BTF artifact could not be read (${String(cause.code)}): ${input.path}.`,
        },
      ]);
  }
  return new ArtifactOperationError(
    OPERATION,
    origin === "owned-or-classified" && cause instanceof ArtifactReaderFailure
      ? cause.reason
      : "io",
    undefined,
    cause instanceof Error ? cause.message : "BTF inspection failed.",
    { cause },
  );
};

const btfFailure = (cause: unknown, input: InspectBtfInput) => {
  const primary = btfFailurePrimary(artifactFilePrimaryFacts(cause), input);
  return projectStableArtifactFailure(
    cause,
    primary,
    input.path,
    BTF_PROVIDER.id,
    OPERATION,
  );
};
