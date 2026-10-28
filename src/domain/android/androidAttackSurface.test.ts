import { describe, expect, it } from "vitest";

import { androidManifestComponentSchema } from "./androidManifestComponents.js";
import {
  ANDROID_ATTACK_SURFACE_UNKNOWNS,
  coverageUnknown,
  projectAttackSurface,
  PROVIDER_OVERRIDE_NOTE,
  PROVIDER_PATH_PERMISSION_NOTE,
  providerOverrideUnknown,
  providerPathPermissionUnknown,
  UNGUARDED_COMPONENT_NOTE,
  UNPROJECTED_OVERRIDE_NOTE,
  UNPROJECTED_PATH_NOTE,
  UNRESOLVED_GUARD_NOTE,
  unprojectedProviderGuardUnknown,
  unresolvedGuardUnknown,
} from "./androidAttackSurface.js";

type Component = typeof androidManifestComponentSchema._output;

const component = (
  overrides: Partial<Component> & Pick<Component, "kind" | "name">,
): Component => ({
  declared_name: overrides.name,
  exported: null,
  exported_default: null,
  permission: null,
  permission_source: "none",
  permission_overrides: "none",
  path_permissions: "none",
  intent_filter_count: 0,
  actions: [],
  categories: [],
  foreground_service_type: null,
  authorities: null,
  target_activity: null,
  declaration_coverage: "unknown",
  ...overrides,
});

const components: Component[] = [
  component({
    kind: "activity",
    name: "io.example.Main",
    exported: true,
    actions: ["android.intent.action.MAIN"],
    intent_filter_count: 1,
  }),
  component({
    kind: "service",
    name: "io.example.Sync",
    exported_default: true,
    permission: "android.permission.BIND_JOB_SERVICE",
    permission_source: "component",
    foreground_service_type: "shortService",
    actions: ["SYNC"],
    intent_filter_count: 1,
  }),
  component({
    kind: "receiver",
    name: "io.example.Sms",
    exported: true,
    actions: ["android.provider.Telephony.SMS_RECEIVED"],
    intent_filter_count: 1,
  }),
  component({
    kind: "provider",
    name: "io.example.Files",
    exported: false,
    authorities: ["io.example.files"],
  }),
  component({
    kind: "activity",
    name: "io.example.Ambiguous",
    declared_name: ".Ambiguous",
  }),
  component({
    kind: "provider",
    name: "io.example.Bridge",
    exported: true,
    permission_overrides: "read-write",
    authorities: ["io.example.bridge"],
  }),
  component({
    kind: "provider",
    name: "io.example.Open",
    exported: true,
    authorities: ["io.example.open"],
  }),
  component({
    kind: "activity",
    name: "io.example.Tokenized",
    exported: true,
    permission_source: "unknown",
  }),
  component({
    kind: "service",
    name: "io.example.Delegated",
    exported: true,
    permission: "io.example.permission.GUARD",
    permission_source: "application",
  }),
];

const facts = {
  package_name: "io.example",
  components,
  component_coverage: "complete" as const,
};

describe("projectAttackSurface", () => {
  it("separates unguarded, guarded and guard-unknown components", () => {
    const result = projectAttackSurface(facts);
    expect(result.coverage).toBe("complete");
    expect(
      result.exported_without_permission.map(
        (finding) => finding.resolved_name,
      ),
    ).toEqual(["io.example.Main", "io.example.Sms", "io.example.Open"]);
    expect(
      result.exported_without_permission.map((finding) => finding.note),
    ).toEqual([
      UNGUARDED_COMPONENT_NOTE,
      UNGUARDED_COMPONENT_NOTE,
      UNGUARDED_COMPONENT_NOTE,
    ]);
    expect(
      result.exported_without_permission.map(
        (finding) => finding.permission_source,
      ),
    ).toEqual(["none", "none", "none"]);
    expect(
      result.exported_guarded.map((finding) => [
        finding.permission,
        finding.permission_source,
      ]),
    ).toEqual([
      ["android.permission.BIND_JOB_SERVICE", "component"],
      ["io.example.permission.GUARD", "application"],
    ]);
    expect(result.exported_guarded.map((f) => f.exported_source)).toEqual([
      "implicit",
      "explicit",
    ]);
    expect(
      result.exported_guard_unknown.map((finding) => [
        finding.resolved_name,
        finding.permission_source,
        finding.permission_overrides,
        finding.note,
      ]),
    ).toEqual([
      ["io.example.Bridge", "none", "read-write", expect.any(String)],
      ["io.example.Tokenized", "unknown", "none", UNRESOLVED_GUARD_NOTE],
    ]);
    expect(result.exported_guard_unknown[0]?.note).not.toBe(
      UNGUARDED_COMPONENT_NOTE,
    );
    expect(result.export_unknown.map((f) => f.resolved_name)).toEqual([
      "io.example.Ambiguous",
    ]);
    expect(result.export_unknown.map((f) => f.exported_source)).toEqual([
      "unknown",
    ]);
    expect(result.foreground_service_types).toEqual(["shortService"]);
    expect(result.provider_authorities).toEqual([
      "io.example.bridge",
      "io.example.files",
      "io.example.open",
    ]);
    expect(
      result.intent_action_index.find(
        (entry) => entry.action === "android.provider.Telephony.SMS_RECEIVED",
      )?.components,
    ).toEqual(["io.example.Sms"]);
  });

  it("explains unresolved guards, overrides and incomplete coverage", () => {
    const result = projectAttackSurface({
      ...facts,
      component_coverage: "partial",
    });
    expect(result.unknowns).toEqual([
      ...ANDROID_ATTACK_SURFACE_UNKNOWNS,
      unresolvedGuardUnknown(1),
      providerOverrideUnknown(1),
      coverageUnknown("partial"),
    ]);
  });

  it("keeps a provider with a base permission and an override guard-unknown", () => {
    const result = projectAttackSurface({
      ...facts,
      components: [
        component({
          kind: "provider",
          name: "io.example.Base",
          exported: true,
          permission: "io.example.permission.BASE",
          permission_source: "component",
          permission_overrides: "read",
        }),
        component({
          kind: "provider",
          name: "io.example.BaseOnly",
          exported: true,
          permission: "io.example.permission.BASE",
          permission_source: "component",
        }),
      ],
    });
    // The override can clear or replace the base value for one operation, so
    // the base permission does not establish the exported provider's guard.
    expect(result.exported_guarded.map((f) => f.resolved_name)).toEqual([
      "io.example.BaseOnly",
    ]);
    expect(
      result.exported_guard_unknown.map((f) => [
        f.resolved_name,
        f.permission,
        f.permission_overrides,
        f.note,
      ]),
    ).toEqual([
      [
        "io.example.Base",
        "io.example.permission.BASE",
        "read",
        PROVIDER_OVERRIDE_NOTE,
      ],
    ]);
    expect(result.exported_without_permission).toEqual([]);
  });

  it("reports an exported provider as unguarded only without projected overrides", () => {
    const result = projectAttackSurface({
      ...facts,
      components: [
        component({
          kind: "provider",
          name: "io.example.Open",
          exported: true,
        }),
        component({
          kind: "provider",
          name: "io.example.Stale",
          exported: true,
          permission_overrides: "unknown",
        }),
      ],
    });
    expect(
      result.exported_without_permission.map((f) => f.resolved_name),
    ).toEqual(["io.example.Open"]);
    expect(result.exported_guard_unknown.map((f) => f.resolved_name)).toEqual([
      "io.example.Stale",
    ]);
    // The inventory predates the projection, so the presence itself is
    // unknown; that is not a declared guard.
    expect(result.exported_guard_unknown[0]?.note).toBe(
      UNPROJECTED_OVERRIDE_NOTE,
    );
    expect(result.unknowns).toContain(unprojectedProviderGuardUnknown(1));
    expect(result.unknowns).not.toContain(providerOverrideUnknown(1));
  });
});

describe("projectAttackSurface provider guards", () => {
  it("keeps a path-protected provider guard-unknown", () => {
    const result = projectAttackSurface({
      ...facts,
      components: [
        component({
          kind: "provider",
          name: "io.example.Paths",
          exported: true,
          path_permissions: "present",
        }),
        component({
          kind: "provider",
          name: "io.example.StalePaths",
          exported: true,
          path_permissions: "unknown",
        }),
      ],
    });
    // Path guards restrict the paths they declare; the remaining paths and the
    // guard values are not projected, so neither bucket can be decided.
    expect(result.exported_without_permission).toEqual([]);
    expect(
      result.exported_guard_unknown.map((f) => [f.resolved_name, f.note]),
    ).toEqual([
      ["io.example.Paths", PROVIDER_PATH_PERMISSION_NOTE],
      ["io.example.StalePaths", UNPROJECTED_PATH_NOTE],
    ]);
    expect(result.unknowns).toContain(providerPathPermissionUnknown(1));
    // Unknown presence is reported as unknown, never as a declared guard.
    expect(result.unknowns).toContain(unprojectedProviderGuardUnknown(1));
    expect(result.unknowns).not.toContain(providerPathPermissionUnknown(2));
  });
});

describe("projectAttackSurface permission provenance", () => {
  it("rejects a guarded claim without a value and a value without a source", () => {
    expect(() =>
      projectAttackSurface({
        ...facts,
        components: [
          component({
            kind: "activity",
            name: "io.example.Valueless",
            exported: true,
            permission_source: "component",
          }),
        ],
      }),
    ).toThrow(/requires the permission value/u);
    expect(() =>
      projectAttackSurface({
        ...facts,
        components: [
          component({
            kind: "activity",
            name: "io.example.Unsourced",
            exported: true,
            permission: "io.example.GUARD",
            permission_source: "none",
          }),
        ],
      }),
    ).toThrow(/requires permission_source/u);
  });

  it("rejects an empty established permission instead of emitting a guard", () => {
    // The producing parser normalizes an explicit empty permission to null with
    // source "none", so an established source with "" is not a guard value.
    expect(() =>
      projectAttackSurface({
        ...facts,
        components: [
          component({
            kind: "activity",
            name: "io.example.EmptyGuard",
            exported: true,
            permission: "",
            permission_source: "component",
          }),
        ],
      }),
    ).toThrow(/requires the permission value/u);
  });
});

describe("projectAttackSurface budgets", () => {
  it("rejects a selection that exceeds the component or text budget", () => {
    expect(() =>
      projectAttackSurface({
        ...facts,
        components: Array.from({ length: 1001 }, (_, index) =>
          component({ kind: "activity", name: `io.example.C${String(index)}` }),
        ),
      }),
    ).toThrow(/1000/u);
    expect(() =>
      projectAttackSurface({
        ...facts,
        components: Array.from({ length: 32 }, () =>
          component({
            kind: "activity",
            name: "io.example.Long",
            actions: Array.from({ length: 128 }, () => "a".repeat(60_000)),
          }),
        ),
      }),
    ).toThrow(/declaration text is/u);
    // Empty authorities add nothing to the text budgets, so the producing
    // parser's per-provider cap is what bounds the retained selection.
    expect(() =>
      projectAttackSurface({
        ...facts,
        components: [
          component({
            kind: "provider",
            name: "io.example.ManyAuthorities",
            exported: true,
            authorities: Array.from(
              { length: 65 },
              (_, index) => `io.example.auth${String(index)}`,
            ),
          }),
        ],
      }),
    ).toThrow(/64/u);
  });

  it("bounds the projected findings before building them", () => {
    // A selected name that stays inside every input budget is repeated once per
    // action in the index, so the response budget rejects it before allocation.
    expect(() =>
      projectAttackSurface({
        ...facts,
        components: [
          component({
            kind: "activity",
            name: "n".repeat(60_000),
            exported: true,
            actions: Array.from({ length: 128 }, () => "a"),
          }),
        ],
      }),
    ).toThrow(/Projected finding text is/u);
  });
});
