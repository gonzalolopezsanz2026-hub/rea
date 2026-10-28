import { describe, expect, it } from "vitest";

import { createEvidence } from "../../domain/evidence.js";
import { EvidenceReferenceError } from "../../domain/evidenceErrors.js";
import { ANDROID_APPLICATION_PROVIDER } from "../../domain/investigationProviders.js";
import { projectAndroidAttackSurfaceEvidence } from "./AndroidAttackSurfaceService.js";

const component = {
  kind: "activity",
  declared_name: ".Main",
  name: "io.example.Main",
  exported: true,
  exported_default: null,
  permission: null,
  permission_source: "none",
  permission_overrides: "none",
  path_permissions: "none",
  intent_filter_count: 1,
  actions: ["android.intent.action.MAIN"],
  categories: [],
  foreground_service_type: null,
  authorities: null,
  target_activity: null,
} as const;

const secondComponent = {
  ...component,
  kind: "service",
  declared_name: ".Sync",
  name: "io.example.Sync",
} as const;

const packageEvidence = (
  items: readonly unknown[] = [component],
  status: "complete" | "partial" | "unavailable" = "complete",
) =>
  createEvidence(
    { path: "/tmp/Example.apk", sha256: "a".repeat(64), format: "apk" },
    ANDROID_APPLICATION_PROVIDER,
    {
      predicateType: "rea.android-package",
      operation: "inspect_android_package",
      parameters: {},
      result: {
        engine: {
          name: "jadx",
          version: null,
          artifact_sha256: "b".repeat(64),
          source_revision: null,
          worker_count: 1,
          heap_limit_mib: null,
        },
        package_name: "io.example",
        version_name: null,
        version_code: null,
        min_sdk: null,
        target_sdk: null,
        permissions: [],
        manifest: {
          status: "complete",
          text: "<manifest/>",
          reported_total_bytes: null,
        },
        components: { status, items, limitations: [] },
        class_count: 0,
        resource_count: 0,
        signature_verification: "not_performed",
      },
      rawResult: null,
      confidence: "observed",
      authority: "shipped-artifact",
      environment: null,
      limitations: [],
      evidenceLinks: [],
    },
  );

describe("projectAndroidAttackSurfaceEvidence", () => {
  it("wraps the projection in derived analyst-inference Evidence", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [],
      component_coverage: "complete",
    });
    if (!result.ok) throw result.error;
    expect(result.value.operation).toBe("project_android_attack_surface");
    expect(result.value.confidence).toBe("derived");
    expect(result.value.parameters).toMatchObject({
      package_name: "io.example",
      component_coverage: "complete",
      component_count: 0,
    });
  });

  it("retains the selected declarations the projection drops from its result", () => {
    const unexported = {
      kind: "provider",
      declared_name: ".Files",
      name: "io.example.Files",
      exported: false,
      exported_default: null,
      permission: null,
      permission_source: "unknown",
      intent_filter_count: 0,
      actions: [],
      categories: [],
      foreground_service_type: null,
      authorities: ["io.example.files"],
      target_activity: null,
    } as const;
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [unexported],
      component_coverage: "partial",
    });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      exported_without_permission: [],
    });
    expect(result.value.parameters).toMatchObject({
      component_count: 1,
      components: [unexported],
    });
  });

  it("rejects unused declaration facts instead of ignoring them", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      target_sdk: "30",
      permissions: [],
      components: [],
      component_coverage: "complete",
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("resolves a retained Evidence reference through the session lookup", () => {
    const source = packageEvidence();
    const result = projectAndroidAttackSurfaceEvidence(
      {
        package_name: "io.example",
        components: [component],
        component_coverage: "complete",
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
    const source = packageEvidence();
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [component],
      component_coverage: "complete",
      source_evidence: {
        kind: "retained-evidence",
        evidence_id: source.evidence_id,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected the reference to stay unresolved");
    expect(result.error).toBeInstanceOf(EvidenceReferenceError);
  });

  it("rejects unknown coverage values as input errors", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: null,
      components: [],
      component_coverage: "everything",
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });
});

describe("projectAndroidAttackSurfaceEvidence with a linked source", () => {
  it("links and attributes the projection to the selected package Evidence", () => {
    const source = packageEvidence();
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [component],
      component_coverage: "complete",
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
      digest: { sha256: "a".repeat(64) },
    });
  });

  it("records that declarations without a linked source have no APK", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [component],
      component_coverage: "complete",
    });
    if (!result.ok) throw result.error;
    expect(result.value.subject).toBeNull();
    expect(result.value.evidence_links).toEqual([]);
    expect(result.value.limitations.join(" ")).toContain(
      "No source Evidence was linked",
    );
  });

  it("refuses components the linked inventory does not report", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [
        {
          ...component,
          permission: "io.example.INVENTED",
          permission_source: "component",
        },
      ],
      component_coverage: "complete",
      source_evidence: packageEvidence(),
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("refuses an edited intent filter count the inventory did not report", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [{ ...component, intent_filter_count: 9 }],
      component_coverage: "complete",
      source_evidence: packageEvidence(),
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("refuses a complete claim over a partial linked inventory", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [component],
      component_coverage: "complete",
      source_evidence: packageEvidence([component], "partial"),
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("refuses a selection that omits components of a complete linked inventory", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [component],
      component_coverage: "complete",
      source_evidence: packageEvidence([component, secondComponent]),
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("refuses a package name the linked inventory does not report", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.other",
      components: [component],
      component_coverage: "complete",
      source_evidence: packageEvidence(),
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("refuses an edited source record whose identity no longer matches", () => {
    const source = packageEvidence();
    const edited = {
      ...source,
      normalized_result: {
        ...(source.normalized_result as Record<string, unknown>),
        components: { status: "complete", items: [], limitations: [] },
      },
    } as typeof source;
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [component],
      component_coverage: "complete",
      source_evidence: edited,
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });
});
