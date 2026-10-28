import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisProtocolError } from "../../domain/analysisErrorCore.js";
import {
  androidJniNamesInputSchema,
  projectJniNames,
} from "../../domain/android/androidJniNames.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { ANDROID_APPLICATION_PROVIDER } from "../../domain/investigationProviders.js";
import {
  resolveEvidenceInput,
  type EvidenceLookup,
} from "../EvidenceInputResolver.js";
import {
  authenticateClassSelection,
  projectionSourceTarget,
} from "./AndroidProjectionSource.js";

const OPERATION = "project_android_jni_names" as const;

/**
 * Project expected JNI/JNA symbol names for caller-selected DEX methods.
 * A retained source reference resolves through the session's Evidence ledger
 * before authentication; an inline record passes through.
 */
export const projectAndroidJniNamesEvidence = (
  rawInput: unknown,
  lookup?: EvidenceLookup,
): Result<Evidence, AnalysisError> => {
  const parsed = androidJniNamesInputSchema.safeParse(rawInput);
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
  const source = authenticateClassSelection(OPERATION, linked, {
    class_name: parsed.data.class_name,
    methods: parsed.data.methods,
  });
  if (!source.ok) return source;
  try {
    const result = projectJniNames({
      class_name: parsed.data.class_name,
      methods: parsed.data.methods,
    });
    return ok(
      createEvidence(
        source.value === undefined
          ? undefined
          : projectionSourceTarget(source.value),
        ANDROID_APPLICATION_PROVIDER,
        {
          predicateType: "rea.android-jni-names",
          operation: OPERATION,
          parameters: {
            class_name: parsed.data.class_name,
            method_count: parsed.data.methods.length,
            // Null records a projection over facts supplied without a source.
            source_evidence_id: source.value?.evidence_id ?? null,
          },
          result,
          rawResult: null,
          confidence: "derived",
          authority: "analyst-inference",
          environment: null,
          limitations: [
            "Expected names are string projections from caller-selected declarations; they do not read an APK or native library.",
            ...(source.value === undefined
              ? [
                  "No source Evidence was linked, so this projection records only the selected declarations, not the APK they came from.",
                ]
              : [
                  "The selected members were authenticated against the linked inspect_android_class Evidence; the projection reads no APK itself.",
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
        "Android JNI name projection produced an invalid result",
        { cause },
      ),
    );
  }
};
