import { describe, expect, it } from "vitest";

import { createEvidence } from "../../domain/evidence.js";
import { EvidenceReferenceError } from "../../domain/evidenceErrors.js";
import { ANDROID_APPLICATION_PROVIDER } from "../../domain/investigationProviders.js";
import { projectAndroidJniNamesEvidence } from "./AndroidJniNamesService.js";

const classEvidence = (
  class_name: string = "pkg.Native",
  dex_class_name: string = "pkg.Native",
) =>
  createEvidence(
    { path: "/tmp/Example.apk", sha256: "c".repeat(64), format: "apk" },
    ANDROID_APPLICATION_PROVIDER,
    {
      predicateType: "rea.android-class",
      operation: "inspect_android_class",
      parameters: {},
      result: {
        engine: {
          name: "jadx",
          version: null,
          artifact_sha256: "d".repeat(64),
          source_revision: null,
          worker_count: 1,
          heap_limit_mib: null,
        },
        class_name,
        dex_class_name,
        methods: [
          {
            name: "nativeInit",
            dex_method_name: "nativeInit",
            reported_signature: "void nativeInit(int)",
            overload_index: 0,
            is_constructor: false,
            dex_descriptor: "(I)V",
          },
        ],
        fields: [],
        inner_classes: [],
      },
      rawResult: null,
      confidence: "observed",
      authority: "shipped-artifact",
      environment: null,
      limitations: [],
      evidenceLinks: [],
    },
  );

describe("projectAndroidJniNamesEvidence", () => {
  it("wraps the projection in derived analyst-inference Evidence", () => {
    const result = projectAndroidJniNamesEvidence({
      class_name: "pkg.Cls",
      methods: [{ method_name: "nativeInit", dex_descriptor: "()V" }],
    });
    if (!result.ok) throw result.error;
    expect(result.value.operation).toBe("project_android_jni_names");
    expect(result.value.confidence).toBe("derived");
    expect(result.value.normalized_result).toMatchObject({
      class_name: "pkg.Cls",
      coverage: "complete",
    });
  });

  it("links and attributes the projection to the selected class Evidence", () => {
    const source = classEvidence();
    const result = projectAndroidJniNamesEvidence({
      class_name: "pkg.Native",
      methods: [{ method_name: "nativeInit", dex_descriptor: "(I)V" }],
      source_evidence: source,
    });
    if (!result.ok) throw result.error;
    expect(result.value.evidence_links).toEqual([source.evidence_id]);
    expect(result.value.parameters).toMatchObject({
      source_evidence_id: source.evidence_id,
    });
    expect(result.value.subject).toMatchObject({
      local_path: "/tmp/Example.apk",
      format: "apk",
      digest: { sha256: "c".repeat(64) },
    });
  });

  it("refuses a decompiler display name where the raw DEX identity is required", () => {
    const result = projectAndroidJniNamesEvidence({
      class_name: "pkg.Outer.Worker",
      methods: [{ method_name: "run", dex_descriptor: "()V" }],
      source_evidence: classEvidence("pkg.Outer.Worker", "pkg.Outer$Worker"),
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("resolves a retained Evidence reference through the session lookup", () => {
    const source = classEvidence();
    const result = projectAndroidJniNamesEvidence(
      {
        class_name: "pkg.Native",
        methods: [{ method_name: "nativeInit", dex_descriptor: "(I)V" }],
        source_evidence: {
          kind: "retained-evidence",
          evidence_id: source.evidence_id,
        },
      },
      (evidenceId) => (evidenceId === source.evidence_id ? source : undefined),
    );
    if (!result.ok) throw result.error;
    expect(result.value.evidence_links).toEqual([source.evidence_id]);
    expect(result.value.parameters).toMatchObject({
      source_evidence_id: source.evidence_id,
    });
    expect(result.value.subject).toMatchObject({
      local_path: "/tmp/Example.apk",
      format: "apk",
    });
  });

  it("refuses a retained reference the session cannot resolve", () => {
    const source = classEvidence();
    const result = projectAndroidJniNamesEvidence({
      class_name: "pkg.Native",
      methods: [{ method_name: "nativeInit", dex_descriptor: "(I)V" }],
      source_evidence: {
        kind: "retained-evidence",
        evidence_id: source.evidence_id,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected the reference to stay unresolved");
    expect(result.error).toBeInstanceOf(EvidenceReferenceError);
  });

  it("refuses methods the linked class Evidence does not report", () => {
    const result = projectAndroidJniNamesEvidence({
      class_name: "pkg.Native",
      methods: [{ method_name: "nativeInit", dex_descriptor: "(J)V" }],
      source_evidence: classEvidence(),
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("rejects empty method lists as input errors", () => {
    const result = projectAndroidJniNamesEvidence({
      class_name: "pkg.Cls",
      methods: [],
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });
});
