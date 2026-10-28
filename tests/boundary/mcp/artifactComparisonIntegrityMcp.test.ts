import { expect, it, onTestFinished } from "vitest";

import { ARTIFACT_COMPARISON_EXAMPLE } from "../../../src/contracts/artifactComparisonExample.js";
import { compareArtifacts } from "../../../src/domain/artifactComparison.js";
import { createEvidence } from "../../../src/domain/evidence.js";

import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { createApplicationMcpHarness } from "../../fixtures/applicationMcpHarness.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

it("rejects an unchanged artifact comparison that retains a changed row", async () => {
  const left = ARTIFACT_COMPARISON_EXAMPLE.left;
  const right = ARTIFACT_COMPARISON_EXAMPLE.right;
  const comparison = createEvidence(
    undefined,
    {
      id: "rea-artifact-comparison",
      name: "REA artifact comparison",
      version: "1",
    },
    {
      predicateType: "rea.artifact-comparison",
      operation: "compare_artifacts",
      parameters: {
        left_evidence_ids: [left.evidence_id],
        right_evidence_ids: [right.evidence_id],
      },
      result: {
        ...compareArtifacts(left, right),
        status: "unchanged",
      },
      confidence: "derived",
      authority: "analyst-inference",
      evidenceLinks: [left.evidence_id, right.evidence_id],
    },
  );
  const session = createTestBinarySession(() => {
    throw new Error(
      "Retained comparison verification must not launch a provider",
    );
  });
  const harness = await createApplicationMcpHarness({ session });
  onTestFinished(harness.close);
  for (const record of [left, right, comparison])
    expect(session.recordEvidence(record).ok).toBe(true);

  const response = await harness.client.callTool({
    name: "verify_reconstruction",
    arguments: {
      specification: {
        name: "Artifact structure",
        claims: [
          {
            kind: "structural-artifact",
            claim_id: "artifact-graph",
            title: "Artifact graph remains equal",
            comparison_evidence_id: comparison.evidence_id,
            dimension: "overall",
          },
        ],
      },
    },
  });

  expect(response.isError).toBe(true);
  expect(parseMcpToolError(response)).toMatchObject({
    error: {
      code: "evidence_integrity_mismatch",
      category: "integrity_mismatch",
    },
  });
  expect(session.evidenceById(comparison.evidence_id)).toEqual(comparison);
});
