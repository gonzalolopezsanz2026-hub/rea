import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisProtocolError } from "../../domain/analysisErrorCore.js";
import {
  androidAttackSurfaceInputSchema,
  projectAttackSurface,
} from "../../domain/android/androidAttackSurface.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { ANDROID_APPLICATION_PROVIDER } from "../../domain/investigationProviders.js";
import {
  resolveEvidenceInput,
  type EvidenceLookup,
} from "../EvidenceInputResolver.js";
import {
  authenticateComponentSelection,
  projectionSourceTarget,
} from "./AndroidProjectionSource.js";

const OPERATION = "project_android_attack_surface" as const;

/**
 * Project structural attack-surface facts from caller-selected package
 * declarations. A retained source reference resolves through the session's
 * Evidence ledger before authentication; an inline record passes through.
 */
export const projectAndroidAttackSurfaceEvidence = (
  rawInput: unknown,
  lookup?: EvidenceLookup,
): Result<Evidence, AnalysisError> => {
  const parsed = androidAttackSurfaceInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(OPERATION, parsed.error.issues, rawInput, {
        cause: parsed.error,
      }),
    );
  const selected = parsed.data.source_evidence;
  let linked: Evidence | undefined;
  if (selected !== undefined) {
    const resolved = resolveEvidenceInput(selected, lookup);
    if (!resolved.ok) return resolved;
    linked = resolved.value;
  }
  const source = authenticateComponentSelection(OPERATION, linked, {
    package_name: parsed.data.package_name,
    component_coverage: parsed.data.component_coverage,
    components: parsed.data.components,
  });
  if (!source.ok) return source;
  try {
    const result = projectAttackSurface({
      package_name: parsed.data.package_name,
      components: parsed.data.components,
      component_coverage: parsed.data.component_coverage,
    });
    return ok(
      createEvidence(
        source.value === undefined
          ? undefined
          : projectionSourceTarget(source.value),
        ANDROID_APPLICATION_PROVIDER,
        {
          predicateType: "rea.android-attack-surface",
          operation: OPERATION,
          parameters: {
            package_name: parsed.data.package_name,
            component_coverage: parsed.data.component_coverage,
            component_count: parsed.data.components.length,
            source_evidence_id: source.value?.evidence_id ?? null,
            // The selection stays readable even where the projection drops
            // fields (permission_source) or whole non-exported components.
            components: parsed.data.components,
          },
          result,
          rawResult: null,
          confidence: "derived",
          authority: "analyst-inference",
          environment: null,
          limitations: [
            "Findings rank static declarations from caller-selected facts; they do not read an APK or establish exploitability.",
            ...(source.value === undefined
              ? [
                  "No source Evidence was linked, so this projection records only the selected declarations, not the APK they came from.",
                ]
              : [
                  "The selected components were authenticated against the linked inspect_android_package Evidence; the projection reads no APK itself.",
                ]),
          ],
          evidenceLinks:
            source.value === undefined ? [] : [source.value.evidence_id],
        },
      ),
    );
  } catch (cause: unknown) {
    // Input already parsed against the same schema; a failure here is the
    // projection's own invariant, never caller-supplied data.
    return err(
      new AnalysisProtocolError(
        "Android attack-surface projection produced an invalid result",
        { cause },
      ),
    );
  }
};
