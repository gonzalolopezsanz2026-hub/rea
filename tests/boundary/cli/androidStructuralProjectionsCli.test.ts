import { expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest(
  "projects JNI names from inline declarations through the compiled CLI",
  async ({ cli }) => {
    const result = await cli.run({
      arguments: [
        "project-android-jni-names",
        '{"class_name":"io.example.Native","methods":[{"method_name":"nativeInit","dex_descriptor":"(I)V"}]}',
        "--json",
      ],
    });
    expect(result.exitCode).toBe(0);
    const evidence = parseEvidence(result.json);
    expect(evidence.operation).toBe("project_android_jni_names");
    expect(evidence.normalized_result).toMatchObject({
      class_name: "io.example.Native",
      methods: [
        {
          jni_short_name: "Java_io_example_Native_nativeInit",
          jni_long_name: "Java_io_example_Native_nativeInit__I",
        },
      ],
    });
  },
);

cliTest(
  "ranks exported components through the compiled CLI",
  async ({ cli }) => {
    const result = await cli.run({
      arguments: [
        "project-android-attack-surface",
        JSON.stringify({
          package_name: "io.example",
          components: [
            {
              kind: "receiver",
              declared_name: ".Sms",
              name: "io.example.Sms",
              exported: true,
              exported_default: null,
              permission: null,
              permission_source: "unknown",
              intent_filter_count: 1,
              actions: ["android.provider.Telephony.SMS_RECEIVED"],
              categories: [],
              foreground_service_type: null,
              authorities: null,
              target_activity: null,
            },
          ],
          component_coverage: "partial",
        }),
        "--json",
      ],
    });
    expect(result.exitCode).toBe(0);
    const evidence = parseEvidence(result.json);
    expect(evidence.operation).toBe("project_android_attack_surface");
    expect(evidence.normalized_result).toMatchObject({
      exported_without_permission: [],
      exported_guard_unknown: [
        { resolved_name: "io.example.Sms", permission_source: "unknown" },
      ],
      coverage: "partial",
    });
  },
);

cliTest(
  "rejects declaration facts the projection does not consume",
  async ({ cli }) => {
    const result = await cli.run({
      arguments: [
        "project-android-attack-surface",
        '{"package_name":"io.example","target_sdk":"30","permissions":[],"components":[],"component_coverage":"complete"}',
        "--json",
      ],
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.json).toMatchObject({ code: "invalid_request" });
  },
);
