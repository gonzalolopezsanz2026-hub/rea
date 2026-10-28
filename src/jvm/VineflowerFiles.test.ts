import { expect, it } from "vitest";
import { JvmMetadataBudget, JVM_METADATA_BYTES } from "./VineflowerFiles.js";
import { AnalysisResourceConstraintError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";

it("explains the effective heap-derived metadata allowance and how to raise it", () => {
  let failure: unknown;
  try {
    new JvmMetadataBudget().add(
      "a".repeat(Math.floor(JVM_METADATA_BYTES / 6) + 1),
    );
  } catch (cause) {
    failure = cause;
  }
  expect(failure).toBeInstanceOf(AnalysisResourceConstraintError);
  if (!(failure instanceof AnalysisResourceConstraintError)) throw failure;
  const recovery = projectAnalysisError(failure).remediation.action;
  expect(recovery).toContain(String(JVM_METADATA_BYTES));
  expect(recovery).toContain("1/32");
  expect(recovery).toContain("NODE_OPTIONS");
  expect(recovery).toContain("--max-old-space-size");
  expect(recovery).toContain("restart");
});
