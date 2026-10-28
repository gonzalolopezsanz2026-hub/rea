import { expect, it } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { createApplicationMcpHarness } from "../../fixtures/applicationMcpHarness.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const exportedActivity = {
  kind: "activity",
  declared_name: ".Main",
  name: "io.example.Main",
  exported: true,
  exported_default: null,
  permission: null,
  permission_source: "none",
  intent_filter_count: 1,
  actions: ["android.intent.action.MAIN"],
  categories: ["android.intent.category.LAUNCHER"],
  foreground_service_type: null,
  authorities: null,
  target_activity: null,
};

it(
  "projects Android names and attack surface with readable Evidence",
  { timeout: 60_000 },
  async () => {
    const { client } = await createApplicationMcpHarness({
      session: createTestBinarySession(() => {
        throw new Error("structural projections must not launch a provider");
      }),
    });
    const { tools } = await client.listTools();
    const names = new Set(tools.map(({ name }) => name));
    expect(names.has("project_android_jni_names")).toBe(true);
    expect(names.has("project_android_attack_surface")).toBe(true);
    // The advertisement shows source_evidence as its retained reference so a
    // complete producer record does not repeat its bytes on every turn; the
    // canonical parser still accepts the inline record.
    for (const name of [
      "project_android_jni_names",
      "project_android_attack_surface",
    ]) {
      const schema = JSON.stringify(
        tools.find((tool) => tool.name === name)?.inputSchema ?? {},
      );
      expect(schema).toContain("retained-evidence");
      expect(schema).not.toContain("normalized_result");
    }

    const jni = await client.callTool({
      name: "project_android_jni_names",
      arguments: {
        class_name: "io.example.Native",
        methods: [{ method_name: "nativeInit", dex_descriptor: "(I)V" }],
      },
    });
    if (jni.isError === true) throw new Error(JSON.stringify(jni, null, 2));
    const jniEvidence = parseEvidence(jni.structuredContent);
    expect(jniEvidence.confidence).toBe("derived");
    expect(jniEvidence.normalized_result).toMatchObject({
      class_name: "io.example.Native",
      methods: [
        {
          jni_short_name: "Java_io_example_Native_nativeInit",
          jni_long_name: "Java_io_example_Native_nativeInit__I",
          jna_expected_name: "nativeInit",
        },
      ],
    });

    const omitted = await client.callTool({
      name: "project_android_jni_names",
      arguments: {
        class_name: "io.example.Native",
        methods: [{ method_name: "m" }],
      },
    });
    if (omitted.isError === true)
      throw new Error(JSON.stringify(omitted, null, 2));

    const surface = await client.callTool({
      name: "project_android_attack_surface",
      arguments: {
        package_name: "io.example",
        components: [exportedActivity],
        component_coverage: "complete",
      },
    });
    if (surface.isError === true)
      throw new Error(JSON.stringify(surface, null, 2));
    const surfaceEvidence = parseEvidence(surface.structuredContent);
    expect(surfaceEvidence.normalized_result).toMatchObject({
      exported_without_permission: [
        { resolved_name: "io.example.Main", permission_source: "none" },
      ],
      exported_guarded: [],
      exported_guard_unknown: [],
    });
    expect(surfaceEvidence.parameters).toMatchObject({
      package_name: "io.example",
      component_count: 1,
      components: [exportedActivity],
    });

    const bundle = await client.callTool({
      name: "get_evidence_bundle",
      arguments: {},
    });
    expect(bundle.structuredContent).toMatchObject({
      result: {
        records: expect.arrayContaining([
          expect.objectContaining({ evidence_id: jniEvidence.evidence_id }),
          expect.objectContaining({ evidence_id: surfaceEvidence.evidence_id }),
        ]),
      },
    });

    const invalid = await client.callTool({
      name: "project_android_attack_surface",
      arguments: {
        package_name: "io.example",
        target_sdk: "30",
        permissions: [],
        components: [],
        component_coverage: "complete",
      },
    });
    expect(invalid.isError).toBe(true);
  },
);
