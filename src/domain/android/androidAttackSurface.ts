import { z } from "zod";

import { evidenceInputSchema } from "../evidenceReference.js";
import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";
import { androidManifestComponentSchema } from "./androidManifestComponents.js";

/** One request projects at most this many components. */
const ATTACK_SURFACE_COMPONENT_LIMIT = 1000;

/** Intent-filter entries projected per component before a selection is split. */
const ATTACK_SURFACE_ACTION_LIMIT = 128;

/**
 * Provider authorities retained per component, matching the producing parser's
 * cap in AndroidManifestComponents, so a schema-valid selection can never
 * carry more authorities than the inventory that reported it.
 */
const ATTACK_SURFACE_AUTHORITY_LIMIT = 64;

/** JVM constant-pool text limit for one class name, action or permission value. */
const ATTACK_SURFACE_TEXT_LIMIT = 65_535;

/**
 * Caller-selected declaration text allowed per call. Every string is repeated
 * in the findings, the action index and Evidence, so the aggregate is bounded
 * before the projection allocates any of it.
 */
const ATTACK_SURFACE_INPUT_TEXT_LIMIT = 1_048_576;

/** Projected response text allowed per call, counted before any finding exists. */
const ATTACK_SURFACE_OUTPUT_TEXT_LIMIT = 4_194_304;

/** Fixed keys and enum values one finding carries besides its selected values. */
const ATTACK_SURFACE_FINDING_OVERHEAD = 256;

/**
 * The declaration facts this projection, its provenance checks and the
 * linked-Evidence authentication consume. The producing inventory also
 * reports detail facets this projection never reads (intent filters,
 * metadata, locations, enabled state); accepting those without advertising
 * them keeps a selection copied from the current inventory valid while the
 * advertised schema stays shallow enough for inline compact presentation.
 */
const attackSurfaceComponentFacts = androidManifestComponentSchema.pick({
  kind: true,
  declared_name: true,
  name: true,
  exported: true,
  exported_default: true,
  permission: true,
  permission_source: true,
  permission_overrides: true,
  path_permissions: true,
  intent_filter_count: true,
  actions: true,
  categories: true,
  foreground_service_type: true,
  authorities: true,
  target_activity: true,
});

/** One inventory component with each caller-selected field bounded. */
const attackSurfaceComponentSchema = z
  .object(attackSurfaceComponentFacts.shape)
  .extend({
    declared_name: z.string().max(ATTACK_SURFACE_TEXT_LIMIT),
    name: z.string().max(ATTACK_SURFACE_TEXT_LIMIT),
    permission: z.string().max(ATTACK_SURFACE_TEXT_LIMIT).nullable(),
    actions: z
      .array(z.string().max(ATTACK_SURFACE_TEXT_LIMIT))
      .max(ATTACK_SURFACE_ACTION_LIMIT)
      .describe(
        `At most ${String(ATTACK_SURFACE_ACTION_LIMIT)} actions per component`,
      ),
    categories: z
      .array(z.string().max(ATTACK_SURFACE_TEXT_LIMIT))
      .max(ATTACK_SURFACE_ACTION_LIMIT),
    foreground_service_type: z
      .string()
      .max(ATTACK_SURFACE_TEXT_LIMIT)
      .nullable(),
    authorities: z
      .array(z.string().max(ATTACK_SURFACE_TEXT_LIMIT))
      .max(ATTACK_SURFACE_AUTHORITY_LIMIT)
      .nullable()
      .describe(
        `At most ${String(ATTACK_SURFACE_AUTHORITY_LIMIT)} authorities per provider`,
      ),
    target_activity: z.string().max(ATTACK_SURFACE_TEXT_LIMIT).nullable(),
  });

/** A component shaped as this projection parses and consumes it. */
export type AttackSurfaceComponent = z.output<
  typeof attackSurfaceComponentSchema
>;

/** Characters the selection repeats in findings, the index and Evidence. */
const selectedTextLength = (input: AndroidAttackSurfaceInput): number => {
  let total = input.package_name?.length ?? 0;
  for (const component of input.components) {
    total +=
      component.declared_name.length +
      component.name.length +
      (component.permission?.length ?? 0) +
      (component.foreground_service_type?.length ?? 0) +
      (component.target_activity?.length ?? 0) +
      component.actions.reduce((sum, action) => sum + action.length, 0) +
      component.categories.reduce((sum, category) => sum + category.length, 0) +
      (component.authorities ?? []).reduce(
        (sum, authority) => sum + authority.length,
        0,
      );
  }
  return total;
};

/**
 * Characters the projection would emit, counted without building a finding.
 * A component name appears in its finding, in every action-index entry that
 * repeats it, and once in the authority or service-type list, so the input
 * size does not bound the response.
 */
const projectedTextLength = (input: AndroidAttackSurfaceInput): number => {
  let total = input.package_name?.length ?? 0;
  for (const component of input.components) {
    const actionLength = component.actions.reduce(
      (sum, action) => sum + action.length,
      0,
    );
    const nameLength = component.declared_name.length + component.name.length;
    // The finding repeats the names once, and each action once with its name.
    total +=
      nameLength +
      (component.permission?.length ?? 0) +
      actionLength +
      ATTACK_SURFACE_FINDING_OVERHEAD;
    // The action index repeats every action with the component name.
    total += actionLength + component.actions.length * component.name.length;
    // Provider authorities and service types repeat beside the findings.
    total +=
      (component.foreground_service_type?.length ?? 0) +
      (component.authorities ?? []).reduce(
        (sum, authority) => sum + authority.length,
        0,
      );
  }
  return total;
};

/** Caller-selected package facts, mirroring inspect_android_package declarations. */
export const androidAttackSurfaceInputSchema = z
  .strictObject({
    package_name: z.string().max(ATTACK_SURFACE_TEXT_LIMIT).nullable(),
    components: z
      .array(attackSurfaceComponentSchema)
      .max(ATTACK_SURFACE_COMPONENT_LIMIT)
      .describe(
        `At most ${String(ATTACK_SURFACE_COMPONENT_LIMIT)} components per call; pass a subset with component_coverage=partial to rank a larger inventory`,
      ),
    component_coverage: z.enum(["complete", "partial", "unknown"]),
    source_evidence: evidenceInputSchema
      .optional()
      .describe(
        "inspect_android_package Evidence these declarations came from, as its retained reference or inline record; its artifact subject and identity are linked, and every component must match that inventory",
      ),
  })
  .superRefine((input, context) => {
    // Permission and its provenance are admitted together: a guarded claim needs
    // a value, and a value needs the source that established it. Contradictory
    // pairs would otherwise become a definite security conclusion.
    for (const [index, component] of input.components.entries()) {
      const path = ["components", index, "permission_source"] as const;
      if (
        (component.permission_source === "component" ||
          component.permission_source === "application") &&
        (component.permission === null || component.permission.length === 0)
      )
        context.addIssue({
          code: "custom",
          path: [...path],
          message: `permission_source "${component.permission_source}" requires the permission value it established; report an empty or unresolved value as source "unknown" with permission null, or "none" with permission null`,
        });
      if (
        component.permission_source !== "component" &&
        component.permission_source !== "application" &&
        component.permission !== null
      )
        context.addIssue({
          code: "custom",
          path: [...path],
          message: `permission "${component.permission}" requires permission_source "component" or "application"; report source "${component.permission_source}" with permission null`,
        });
    }
    const selected = selectedTextLength(input);
    if (selected > ATTACK_SURFACE_INPUT_TEXT_LIMIT)
      context.addIssue({
        code: "custom",
        path: ["components"],
        message: `Selected declaration text is ${String(selected)} characters; at most ${String(ATTACK_SURFACE_INPUT_TEXT_LIMIT)} are accepted per call. Shorten the component names, actions or authorities, or pass a subset with component_coverage=partial.`,
      });
    const projected = projectedTextLength(input);
    if (projected > ATTACK_SURFACE_OUTPUT_TEXT_LIMIT)
      context.addIssue({
        code: "custom",
        path: ["components"],
        message: `Projected finding text is ${String(projected)} characters; at most ${String(ATTACK_SURFACE_OUTPUT_TEXT_LIMIT)} are produced per call. Pass fewer components or fewer actions per component, with component_coverage describing the subset.`,
      });
  });

/** One exported component with its guard and trigger summary. */
export const attackSurfaceFindingSchema = z.strictObject({
  kind: z.string(),
  name: z.string().nullable(),
  resolved_name: z.string().nullable(),
  exported_source: z.enum(["explicit", "implicit", "unknown"]),
  permission: z.string().nullable(),
  permission_source: z.enum(["component", "application", "none", "unknown"]),
  permission_overrides: z.enum([
    "none",
    "read",
    "write",
    "read-write",
    "unknown",
  ]),
  path_permissions: z.enum(["none", "present", "unknown"]),
  intent_actions: z.array(z.string()),
  note: z.string(),
});

export type AttackSurfaceFinding = z.infer<typeof attackSurfaceFindingSchema>;

/** Ranked structural attack-surface observations over static declarations. */
export const androidAttackSurfaceResultSchema = z.strictObject({
  package_name: z.string().nullable(),
  exported_without_permission: z.array(attackSurfaceFindingSchema),
  exported_guarded: z.array(attackSurfaceFindingSchema),
  exported_guard_unknown: z.array(attackSurfaceFindingSchema),
  export_unknown: z.array(attackSurfaceFindingSchema),
  intent_action_index: z.array(
    z.strictObject({
      action: z.string(),
      components: z.array(z.string().nullable()),
    }),
  ),
  foreground_service_types: z.array(z.string()),
  provider_authorities: z.array(z.string().nullable()),
  coverage: z.enum(["complete", "partial", "unknown"]),
  unknowns: z.array(z.string()),
});

export type AndroidAttackSurfaceInput = z.infer<
  typeof androidAttackSurfaceInputSchema
>;
export type AndroidAttackSurfaceResult = z.infer<
  typeof androidAttackSurfaceResultSchema
>;

/** Findings that hold for every projection of static declarations. */
export const ANDROID_ATTACK_SURFACE_UNKNOWNS = [
  "Permission declarations do not establish protection levels or runtime enforcement.",
  "Reachability through intents, tasks, and deep links was not traced; listed triggers are static declarations.",
] as const;

/** Finding note for an exported component with no established guard. */
export const UNGUARDED_COMPONENT_NOTE =
  "Exported without a guarding permission.";

/** Finding note for an exported component whose permission value is unresolved. */
export const UNRESOLVED_GUARD_NOTE =
  "Exported; the guarding permission is unresolved, so absence of a guard is not established.";

/** Finding note for an exported provider whose operation-specific guards are not projected. */
export const PROVIDER_OVERRIDE_NOTE =
  "Exported; provider readPermission/writePermission overrides are projected only as present, so neither their value nor the absence of an operation guard is established.";

/** Finding note for an exported provider whose child path guards are not projected. */
export const PROVIDER_PATH_PERMISSION_NOTE =
  "Exported; child <path-permission> guards cover only the paths they declare and their values are not projected, so the provider's access guard is not established.";

/** Finding note for an exported provider whose override presence predates the projection. */
export const UNPROJECTED_OVERRIDE_NOTE =
  "Exported; whether this provider declares readPermission/writePermission overrides is not established by the retained inventory, so absence of an override is not established.";

/** Finding note for an exported provider whose path-guard presence predates the projection. */
export const UNPROJECTED_PATH_NOTE =
  "Exported; whether this provider declares child <path-permission> guards is not established by the retained inventory, so absence of path guards is not established.";

/** Explanation of unresolved permission values counted in this result. */
export const unresolvedGuardUnknown = (count: number): string =>
  `${String(count)} exported component(s) have an unresolved permission value; they stay guard-unknown rather than unguarded.`;

/** Explanation of exported providers kept guard-unknown by unprojected overrides. */
export const providerOverrideUnknown = (count: number): string =>
  `${String(count)} exported provider(s) declare android:readPermission or android:writePermission; those override values are not projected, so they stay guard-unknown even where a base permission is declared.`;

/** Explanation of exported providers kept guard-unknown by unprojected path guards. */
export const providerPathPermissionUnknown = (count: number): string =>
  `${String(count)} exported provider(s) declare child <path-permission> guards; their paths and permission values are not projected, so those providers stay guard-unknown.`;

/** Explanation of exported providers whose guard presence predates the projection. */
export const unprojectedProviderGuardUnknown = (count: number): string =>
  `${String(count)} exported provider(s) come from an inventory that predates the provider-guard projection; override and path-guard presence stay unknown rather than absent.`;

/** Explanation of incomplete component coverage. */
export const coverageUnknown = (coverage: string): string =>
  `Component inventory coverage is ${coverage}; absence of a finding is unknown.`;

/** How the effective export state was established: declared, defaulted, or unresolved. */
const exportedSource = (
  component: AttackSurfaceComponent,
): "explicit" | "implicit" | "unknown" =>
  component.exported !== null
    ? "explicit"
    : component.exported_default !== null
      ? "implicit"
      : "unknown";

const toFinding = (
  component: AttackSurfaceComponent,
  note: string,
): AttackSurfaceFinding => ({
  kind: component.kind,
  name: component.declared_name,
  resolved_name: component.name,
  exported_source: exportedSource(component),
  permission: component.permission,
  permission_source: component.permission_source,
  permission_overrides: component.permission_overrides,
  path_permissions: component.path_permissions,
  intent_actions: [...component.actions],
  note,
});

/**
 * Project structural attack-surface facts from static declarations.
 * Pure ranking; protection levels and runtime enforcement stay unknown.
 */
export const projectAttackSurface = (
  input: AndroidAttackSurfaceInput,
): AndroidAttackSurfaceResult => {
  const parsed = androidAttackSurfaceInputSchema.parse(input);
  const exportedWithout: AttackSurfaceFinding[] = [];
  const guarded: AttackSurfaceFinding[] = [];
  const guardUnknown: AttackSurfaceFinding[] = [];
  const unknown: AttackSurfaceFinding[] = [];
  const actionIndex = new Map<string, (string | null)[]>();
  const serviceTypes = new Set<string>();
  const authorities = new Set<string | null>();
  let unresolvedGuards = 0;
  let providerOverrideGuards = 0;
  let providerPathGuards = 0;
  let providerGuardPresenceUnknown = 0;
  for (const component of parsed.components) {
    for (const action of component.actions) {
      const list = actionIndex.get(action) ?? [];
      list.push(component.name);
      actionIndex.set(action, list);
    }
    if (component.foreground_service_type !== null)
      serviceTypes.add(component.foreground_service_type);
    if (component.kind === "provider" && component.authorities !== null) {
      for (const authority of component.authorities) authorities.add(authority);
    }
    // The effective export state is the declared literal, else Android's
    // documented default for an absent android:exported when it applies.
    const exported = component.exported ?? component.exported_default;
    if (exported === null) {
      unknown.push(
        toFinding(
          component,
          "Export state is unresolved; treat the component as reachable.",
        ),
      );
      continue;
    }
    if (!exported) continue;
    if (
      component.kind === "provider" &&
      (component.permission_overrides !== "none" ||
        component.path_permissions !== "none")
    ) {
      // The producer projects whether readPermission/writePermission and child
      // <path-permission> guards exist but not their values or paths. Either
      // replaces or clears the base permission for some operations, so the
      // projected statement does not establish the guard. An inventory that
      // predates the projection leaves the presence itself unknown, which is
      // reported as unknown rather than as a declared guard.
      const overridesDeclared =
        component.permission_overrides === "read" ||
        component.permission_overrides === "write" ||
        component.permission_overrides === "read-write";
      const pathsDeclared = component.path_permissions === "present";
      if (overridesDeclared) providerOverrideGuards += 1;
      if (pathsDeclared) providerPathGuards += 1;
      if (
        component.permission_overrides === "unknown" ||
        component.path_permissions === "unknown"
      )
        providerGuardPresenceUnknown += 1;
      guardUnknown.push(
        toFinding(
          component,
          overridesDeclared
            ? PROVIDER_OVERRIDE_NOTE
            : pathsDeclared
              ? PROVIDER_PATH_PERMISSION_NOTE
              : component.permission_overrides === "unknown"
                ? UNPROJECTED_OVERRIDE_NOTE
                : UNPROJECTED_PATH_NOTE,
        ),
      );
    } else if (
      component.permission_source === "component" ||
      component.permission_source === "application"
    ) {
      guarded.push(
        toFinding(component, `Exported, guarded by ${component.permission}.`),
      );
    } else if (component.permission_source === "unknown") {
      unresolvedGuards += 1;
      guardUnknown.push(toFinding(component, UNRESOLVED_GUARD_NOTE));
    } else {
      exportedWithout.push(toFinding(component, UNGUARDED_COMPONENT_NOTE));
    }
  }
  const unknowns: string[] = [...ANDROID_ATTACK_SURFACE_UNKNOWNS];
  if (unresolvedGuards > 0)
    unknowns.push(unresolvedGuardUnknown(unresolvedGuards));
  if (providerOverrideGuards > 0)
    unknowns.push(providerOverrideUnknown(providerOverrideGuards));
  if (providerPathGuards > 0)
    unknowns.push(providerPathPermissionUnknown(providerPathGuards));
  if (providerGuardPresenceUnknown > 0)
    unknowns.push(
      unprojectedProviderGuardUnknown(providerGuardPresenceUnknown),
    );
  if (parsed.component_coverage !== "complete")
    unknowns.push(coverageUnknown(parsed.component_coverage));
  return androidAttackSurfaceResultSchema.parse({
    package_name: parsed.package_name,
    exported_without_permission: exportedWithout,
    exported_guarded: guarded,
    exported_guard_unknown: guardUnknown,
    export_unknown: unknown,
    intent_action_index: [...actionIndex]
      .map(([action, components]) => ({ action, components }))
      .sort((a, b) => compareUnicodeCodePoints(a.action, b.action)),
    foreground_service_types: [...serviceTypes].sort(compareUnicodeCodePoints),
    provider_authorities: [...authorities].sort((a, b) =>
      compareUnicodeCodePoints(a ?? "", b ?? ""),
    ),
    coverage: parsed.component_coverage,
    unknowns,
  });
};
