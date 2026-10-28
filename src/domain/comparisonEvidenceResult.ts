import {
  artifactComparisonResultSchema,
  type ArtifactComparisonResult,
} from "./artifactComparison.js";
import type { ComparisonEvidenceOperation } from "./comparisonEvidenceIdentity.js";
import type { Evidence } from "./evidence.js";
import { EvidenceIntegrityError } from "./evidenceErrors.js";
import { readEvidencePayload } from "./evidenceValidation.js";
import {
  functionComparisonResultSchema,
  type FunctionComparisonResult,
} from "./functionComparisonSchemas.js";
import {
  processCaptureComparisonSchema,
  type ProcessCaptureComparison,
} from "./process/processComparison.js";
import { err, ok, type Result } from "./result.js";

type ComparisonResults = {
  readonly compare_artifacts: ArtifactComparisonResult;
  readonly compare_functions: FunctionComparisonResult;
  readonly compare_process_captures: ProcessCaptureComparison;
};

/** One admitted comparison's envelope and its operation-specific parsed facts. */
export type ParsedComparisonEvidence<
  Operation extends ComparisonEvidenceOperation = ComparisonEvidenceOperation,
> = {
  [Kind in Operation]: {
    readonly operation: Kind;
    readonly evidence: Evidence;
    readonly result: ComparisonResults[Kind];
  };
}[Operation];

/** Decode an admitted comparison's payload and validate nested finding citations. */
export function readComparisonResult<
  Operation extends ComparisonEvidenceOperation,
>(
  evidence: Evidence,
  operation: Operation,
): Result<ParsedComparisonEvidence<Operation>, EvidenceIntegrityError>;
export function readComparisonResult(
  evidence: Evidence,
  operation: ComparisonEvidenceOperation,
): Result<ParsedComparisonEvidence, EvidenceIntegrityError> {
  if (operation === "compare_process_captures") {
    const parsed = readEvidencePayload(
      processCaptureComparisonSchema,
      evidence.normalized_result,
    );
    if (!parsed.ok) return parsed;
    return ok({ operation, evidence, result: parsed.value });
  }
  if (operation === "compare_functions") {
    const parsed = readEvidencePayload(
      functionComparisonResultSchema,
      evidence.normalized_result,
    );
    if (!parsed.ok) return parsed;
    const links = validateFindingLinks(
      evidence,
      parsed.value.dimensions.flatMap(({ evidence_links }) => evidence_links),
    );
    if (!links.ok) return links;
    return ok({ operation, evidence, result: parsed.value });
  }
  const parsed = readEvidencePayload(
    artifactComparisonResultSchema,
    evidence.normalized_result,
  );
  if (!parsed.ok) return parsed;
  const consistency = validateUnchangedArtifactComparison(parsed.value);
  if (!consistency.ok) return consistency;
  const links = validateFindingLinks(
    evidence,
    parsed.value.changes.flatMap(({ evidence_links }) => evidence_links),
  );
  if (!links.ok) return links;
  return ok({ operation, evidence, result: parsed.value });
}

const validateUnchangedArtifactComparison = (
  result: ArtifactComparisonResult,
): Result<void, EvidenceIntegrityError> => {
  if (
    result.status !== "unchanged" ||
    (result.changes.length === 0 &&
      result.summary.added === 0 &&
      result.summary.removed === 0 &&
      result.summary.changed === 0 &&
      result.summary.unknown === 0 &&
      result.summary.contradiction === 0)
  )
    return ok(undefined);
  return err(
    new EvidenceIntegrityError(
      "Artifact comparison marked unchanged contains retained changes or non-zero change counts",
    ),
  );
};

const validateFindingLinks = (
  evidence: Evidence,
  nestedLinks: readonly string[],
): Result<void, EvidenceIntegrityError> => {
  const closure = new Set(evidence.evidence_links);
  return nestedLinks.some((id) => !closure.has(id))
    ? err(
        new EvidenceIntegrityError(
          "Comparison finding cites Evidence outside its top-level closure",
        ),
      )
    : ok(undefined);
};
