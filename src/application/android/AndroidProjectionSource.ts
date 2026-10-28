import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { androidResultSchemas } from "../../domain/android/androidAnalysis.js";
import type { AttackSurfaceComponent } from "../../domain/android/androidAttackSurface.js";
import type { Evidence, EvidenceSubjectTarget } from "../../domain/evidence.js";
import { safeParseEvidence } from "../../domain/evidenceValidation.js";
import { err, ok, type Result } from "../../domain/result.js";

/** One caller-selected declaration, shaped as the projection consumes it. */
type ManifestComponent = AttackSurfaceComponent;

/** Refuse a linked source that cannot establish the requested provenance. */
const sourceInputError = (
  operation: string,
  field: string,
  message: string,
): AnalysisError =>
  new AnalysisInputError(operation, { userMessage: message }, [
    { path: ["source_evidence", field], reason: "invalid_value", message },
  ]);

/**
 * Artifact identity reported by linked source Evidence. The projection copies
 * it so identical declarations read from different APKs stay distinguishable.
 */
export const projectionSourceTarget = (
  source: Evidence,
): EvidenceSubjectTarget | undefined => {
  const { subject } = source;
  if (subject === null) return undefined;
  return {
    path: subject.local_path,
    sha256: subject.digest.sha256,
    format: subject.format,
  };
};

/**
 * Facts the attack-surface projection consumes, including the facts its
 * retained parameters keep readable. Two components authenticate as the same
 * declaration only when every one of them matches.
 */
const componentFactsKey = (component: ManifestComponent): string =>
  JSON.stringify([
    component.kind,
    component.declared_name,
    component.name,
    component.exported,
    component.exported_default,
    component.permission,
    component.permission_source,
    component.permission_overrides,
    component.path_permissions,
    component.intent_filter_count,
    component.actions,
    component.categories,
    component.foreground_service_type,
    component.authorities,
    component.target_activity,
  ]);

/**
 * Require every selected component to be one the linked package Evidence
 * reported, so the projection never attributes invented declarations to an
 * artifact. A selection may be narrower than that inventory; it may claim the
 * complete coverage only when it is exactly that inventory.
 */
export const authenticateComponentSelection = (
  operation: string,
  source: Evidence | undefined,
  selection: {
    readonly package_name: string | null;
    readonly component_coverage: string;
    readonly components: readonly ManifestComponent[];
  },
): Result<Evidence | undefined, AnalysisError> => {
  if (source === undefined) return ok(undefined);
  if (source.operation !== "inspect_android_package")
    return err(
      sourceInputError(
        operation,
        "operation",
        `source_evidence is a ${source.operation} result; select the inspect_android_package Evidence whose components you passed`,
      ),
    );
  const authenticated = safeParseEvidence(source);
  if (!authenticated.ok)
    return err(
      sourceInputError(
        operation,
        "evidence_id",
        "source_evidence no longer matches its own identity; pass the retained record unchanged instead of editing its facts, digest or result",
      ),
    );
  const parsed = androidResultSchemas.inspect_android_package.safeParse(
    authenticated.value.normalized_result,
  );
  if (!parsed.success)
    return err(
      sourceInputError(
        operation,
        "normalized_result",
        "source_evidence does not carry an inspect_android_package result; recreate it with the current REA release",
      ),
    );
  if (parsed.data.package_name !== selection.package_name)
    return err(
      sourceInputError(
        operation,
        "package_name",
        `package_name "${String(selection.package_name)}" is not the linked inventory's "${String(parsed.data.package_name)}"; pass the reported value`,
      ),
    );
  const status = parsed.data.components.status;
  if (selection.component_coverage === "complete" && status !== "complete")
    return err(
      sourceInputError(
        operation,
        "component_coverage",
        `the linked inventory reports ${status} component coverage, so this selection cannot claim complete; pass that status as component_coverage`,
      ),
    );
  const remaining = new Map<string, number>();
  for (const item of parsed.data.components.items) {
    const key = componentFactsKey(item);
    remaining.set(key, (remaining.get(key) ?? 0) + 1);
  }
  for (const [index, component] of selection.components.entries()) {
    const key = componentFactsKey(component);
    const left = remaining.get(key) ?? 0;
    if (left === 0)
      return err(
        sourceInputError(
          operation,
          `components.${String(index)}`,
          `${component.name} is not a component the linked inventory reported, or its facts differ from that report; pass that inventory's own component facts, or omit source_evidence`,
        ),
      );
    remaining.set(key, left - 1);
  }
  if (selection.component_coverage === "complete")
    for (const count of remaining.values())
      if (count > 0)
        return err(
          sourceInputError(
            operation,
            "components",
            "the linked inventory reports components this selection omits; a complete selection must pass every reported component, otherwise describe the subset as partial or unknown coverage",
          ),
        );
  return ok(authenticated.value);
};

/** One selected DEX method awaiting correlation with native symbols. */
interface SelectedMethod {
  readonly method_name: string;
  readonly dex_descriptor?: string | null | undefined;
}

/**
 * Require the selected class and methods to be ones the linked class Evidence
 * reported, identified by raw DEX values rather than decompiler display names.
 */
export const authenticateClassSelection = (
  operation: string,
  source: Evidence | undefined,
  selection: {
    readonly class_name: string;
    readonly methods: readonly SelectedMethod[];
  },
): Result<Evidence | undefined, AnalysisError> => {
  if (source === undefined) return ok(undefined);
  if (source.operation !== "inspect_android_class")
    return err(
      sourceInputError(
        operation,
        "operation",
        `source_evidence is a ${source.operation} result; select the inspect_android_class Evidence whose members you passed`,
      ),
    );
  const authenticated = safeParseEvidence(source);
  if (!authenticated.ok)
    return err(
      sourceInputError(
        operation,
        "evidence_id",
        "source_evidence no longer matches its own identity; pass the retained record unchanged instead of editing its members, digest or result",
      ),
    );
  const parsed = androidResultSchemas.inspect_android_class.safeParse(
    authenticated.value.normalized_result,
  );
  if (!parsed.success)
    return err(
      sourceInputError(
        operation,
        "normalized_result",
        "source_evidence does not carry an inspect_android_class result; recreate it with the current REA release",
      ),
    );
  if (parsed.data.dex_class_name === undefined)
    return err(
      sourceInputError(
        operation,
        "source_evidence",
        "the linked Evidence predates raw DEX identity reporting, so the selection cannot be authenticated against it; inspect the class with the current REA release or omit source_evidence",
      ),
    );
  if (parsed.data.dex_class_name !== selection.class_name)
    return err(
      sourceInputError(
        operation,
        "class_name",
        `${selection.class_name} is not the raw DEX identity the linked Evidence inspected (${parsed.data.dex_class_name}); its display name can be a decompiler alias and would project symbols no native library exports`,
      ),
    );
  const reported = new Set(
    parsed.data.methods
      .filter(
        (method): method is typeof method & { dex_method_name: string } =>
          method.dex_method_name !== undefined,
      )
      .map(
        (method) => `${method.dex_method_name}\u0000${method.dex_descriptor}`,
      ),
  );
  const reportedNames = new Set(
    parsed.data.methods
      .filter(
        (method): method is typeof method & { dex_method_name: string } =>
          method.dex_method_name !== undefined,
      )
      .map((method) => method.dex_method_name),
  );
  for (const [index, method] of selection.methods.entries()) {
    const matches =
      method.dex_descriptor === null || method.dex_descriptor === undefined
        ? reportedNames.has(method.method_name)
        : reported.has(`${method.method_name}\u0000${method.dex_descriptor}`);
    if (!matches)
      return err(
        sourceInputError(
          operation,
          `methods.${String(index)}`,
          `${method.method_name} ${method.dex_descriptor ?? "(no descriptor)"} is not a method the linked Evidence reported; pass that class inventory's own dex_method_name and dex_descriptor, or omit source_evidence`,
        ),
      );
  }
  return ok(authenticated.value);
};
