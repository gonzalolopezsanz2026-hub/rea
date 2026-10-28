import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it, onTestFinished, vi } from "vitest";
import { createAnalysisExecution } from "../../../src/application/AnalysisProvider.js";
import type { JvmAnalysisPort } from "../../../src/application/jvm/JvmAnalysisPort.js";
import { expandToolAvailability } from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { ok } from "../../../src/domain/result.js";
import type { JvmRequest } from "../../../src/domain/jvm/jvmAnalysis.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { assertAdvertisedMcpContracts } from "./mcpContractHarness.js";

const target = {
  path: "/targets/probe.jar",
  sha256: "a".repeat(64),
  bytes: 500,
};

const fixtureExecution = (request: JvmRequest) => {
  const client = {
    command: "/tools/vineflower",
    command_source: "environment",
    version: "1.12.0",
  };
  const result =
    request.operation === "inspect_jvm_decompiler"
      ? { client }
      : {
          client,
          target,
          dependencies: [
            {
              path: "/targets/dependency.jar",
              sha256: "d".repeat(64),
              bytes: 30,
            },
          ],
          class_prefix: request.input.class_prefix ?? null,
          sources: [
            {
              path: "/analysis/probe/org/example/Probe.java",
              relative_path: "org/example/Probe.java",
              sha256: "b".repeat(64),
              bytes: 75,
            },
          ],
          manifest: {
            path: "/analysis/probe/manifest.json",
            sha256: "c".repeat(64),
            bytes: 200,
          },
          diagnostics: {
            stdout: "",
            stderr: "",
            exit_code: 0,
            truncated: false,
          },
          source_inventory_complete: true,
          compilation_status: "not_attempted",
          runtime_equivalence: "unknown",
          limitations: [
            "Emitted source inventory does not establish input-class coverage.",
          ],
        };
  return ok(
    createAnalysisExecution(
      result,
      { id: "vineflower", name: "Vineflower", version: "1.12.0" },
      request.operation === "inspect_jvm_decompiler"
        ? {}
        : { subject: { ...target, format: "zip" as const } },
    ),
  );
};

it("advertises JVM schemas and preserves caller inputs and source provenance through target-free MCP", async () => {
  const close = vi.fn(async () => {});
  const requests: unknown[] = [];
  const provider: JvmAnalysisPort = {
    close,
    async inspectAvailability() {
      return { status: "available", code: null, reason: null, diagnostics: {} };
    },
    async execute(request) {
      requests.push(request);
      return fixtureExecution(request);
    },
  };
  const session = createTestBinarySession(() => {
    throw new Error("No target-bound provider should start");
  });
  const server = createServer(
    { kind: "session", session },
    { jvmAnalysis: provider },
  );
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "jvm-boundary", version: "0.0.0" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    expect(close).toHaveBeenCalled();
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const names = ["inspect_jvm_decompiler", "decompile_jvm_artifact"] as const;
  const { tools } = await client.listTools();
  assertAdvertisedMcpContracts(names, tools);
  const status = await client.callTool({
    name: "binary_session",
    arguments: {},
  });
  expect(status.isError).not.toBe(true);
  const statusResult = toolContract("binary_session").outputSchema.parse(
    status.structuredContent,
  );
  for (const name of names)
    expect(
      expandToolAvailability(statusResult.result.tool_availability).find(
        (entry) => entry.name === name,
      ),
    ).toMatchObject({ available: true });
  expect(requests).toHaveLength(0);
  expect(toolContract(names[0]).effects).toMatchObject({
    launchesProcess: true,
    writesFilesystem: false,
  });
  expect(toolContract(names[1]).effects).toMatchObject({
    launchesProcess: true,
    writesFilesystem: true,
    mutatesTarget: false,
    idempotent: false,
  });
  const invalid = await client.callTool({
    name: names[1],
    arguments: { path: target.path },
  });
  expect(invalid.isError).toBe(true);
  expect(requests).toHaveLength(0);
  const input = {
    path: target.path,
    output_directory: "/analysis/probe",
    classpath: ["/targets/dependency.jar"],
    class_prefix: "org/example/",
  };
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  for (const name of names) {
    const response = await client.callTool({
      name,
      arguments: name === names[0] ? {} : input,
    });
    expect(response.isError).not.toBe(true);
    const evidence = parseEvidence(response.structuredContent);
    const validate = ajv.compile(
      JSON.parse(
        JSON.stringify(tools.find((tool) => tool.name === name)?.outputSchema),
      ),
    );
    expect(validate(evidence), JSON.stringify(validate.errors)).toBe(true);
    expect(evidence.provider).toEqual({
      id: "vineflower",
      name: "Vineflower",
      version: "1.12.0",
    });
    expect(session.evidenceById(evidence.evidence_id)).toEqual(evidence);
    if (name === names[1]) {
      expect(evidence.parameters).toEqual(input);
      expect(evidence.subject).toMatchObject({
        local_path: target.path,
        digest: { sha256: target.sha256 },
      });
      expect(evidence.normalized_result).toMatchObject({
        source_inventory_complete: true,
        compilation_status: "not_attempted",
        runtime_equivalence: "unknown",
        class_prefix: input.class_prefix,
      });
    }
  }
  expect(requests).toEqual([
    { operation: names[0], input: {} },
    { operation: names[1], input },
  ]);
});
