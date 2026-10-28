import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { expandToolAvailability } from "../dist/contracts/toolOutputSchemaPrimitives.js";
import { toolContract } from "../dist/contracts/toolContracts.js";
import { evidenceBundleSchema } from "../dist/domain/evidenceBundle.js";
import {
  withVerifierCleanup,
  closeVerifierResources,
} from "./lib/verifier-cleanup.mjs";
import { buildJvmFixture } from "./verify/jvm/fixtures.mjs";
import {
  mcpTextValue,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";

if (process.argv.includes("--help")) {
  process.stdout.write(
    "Usage: npm run verify:jvm\n" +
      "Requires Vineflower (REA_VINEFLOWER_COMMAND or PATH) and a full JDK\n" +
      "(JAVA_HOME or javac/jar on PATH). Builds an authored Java fixture and\n" +
      "checks the public CLI and stdio MCP; never runs the fixture or installs tools.\n",
  );
  process.exit(0);
}
assert.deepEqual(process.argv.slice(2), [], "verify:jvm accepts only --help");

const execute = promisify(execFile);
const cli = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const environment = { ...process.env, REA_LOG_LEVEL: "silent" };
const directory = await realpath(
  await mkdtemp(join(tmpdir(), "rea-jvm-verify-")),
);
const client = new Client({ name: "rea-jvm-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [cli, "mcp"],
  env: environment,
  stderr: "pipe",
});
transport.stderr?.on("data", () => undefined);
const validator = new Ajv({ strict: false });
addFormats(validator);
let report;
await withVerifierCleanup(async () => {
  const inspected = await runCli("inspect_jvm_decompiler", [
    "inspect-jvm-decompiler",
  ]);
  assert.ok(
    inspected.normalized_result.client.version,
    "Vineflower did not report its version",
  );
  const fixture = await buildJvmFixture(directory, environment);
  await client.connect(transport);
  const catalog = await client.listTools();
  const advertised = new Map();
  for (const name of ["inspect_jvm_decompiler", "decompile_jvm_artifact"]) {
    const tool = catalog.tools.find((candidate) => candidate.name === name);
    assert.ok(
      tool?.outputSchema,
      `${name} omitted its advertised output schema`,
    );
    for (const schema of [tool.inputSchema, tool.outputSchema]) {
      assert.equal(
        validator.validateSchema(schema),
        true,
        JSON.stringify(validator.errors),
      );
      validator.compile(schema);
    }
    advertised.set(name, tool);
  }
  const call = async (name, input) => {
    const tool = advertised.get(name);
    if (tool !== undefined)
      assert.equal(
        validator.validate(tool.inputSchema, input),
        true,
        JSON.stringify(validator.errors),
      );
    const response = await client.callTool(
      { name, arguments: input },
      { timeout: 180_000 },
    );
    assert.notEqual(response.isError, true, mcpTextValue(response));
    const evidence = toolContract(name).outputSchema.parse(
      response.structuredContent,
    );
    assert.deepEqual(
      JSON.parse(mcpTextValue(response)),
      evidence,
      `${name} text/structured Evidence differs`,
    );
    if (tool !== undefined)
      assert.equal(
        validator.validate(tool.outputSchema, evidence),
        true,
        JSON.stringify(validator.errors),
      );
    return evidence;
  };
  const mcpInspection = await call("inspect_jvm_decompiler", {});
  assert.deepEqual(
    mcpInspection.normalized_result,
    inspected.normalized_result,
  );
  assert.equal(mcpInspection.evidence_id, inspected.evidence_id);
  const availability = expandToolAvailability(
    (await call("binary_session", {})).result.tool_availability,
  );
  for (const name of ["inspect_jvm_decompiler", "decompile_jvm_artifact"])
    assert.equal(
      availability.find((tool) => tool.name === name)?.available,
      true,
      `${name} was unavailable with the installed launcher`,
    );
  const retained = [mcpInspection];
  const outputs = [];
  const scenarios = [
    { name: "class", path: fixture.classPath, classpath: [] },
    { name: "jar", path: fixture.jarPath, classpath: fixture.classpath },
    {
      name: "prefix",
      path: fixture.jarPath,
      classpath: fixture.classpath,
      class_prefix: "fixture/Probe",
    },
  ];
  if (fixture.caseSensitive)
    scenarios.push({ name: "case", path: fixture.casePath, classpath: [] });
  for (const scenario of scenarios) {
    const cliOutput = join(directory, `${scenario.name}-cli`);
    const mcpOutput = join(directory, `${scenario.name}-mcp`);
    const arguments_ = ["decompile-jvm-artifact", scenario.path, cliOutput];
    for (const path of scenario.classpath) arguments_.push("--classpath", path);
    if (scenario.class_prefix !== undefined)
      arguments_.push("--class-prefix", scenario.class_prefix);
    const cliEvidence = await runCli("decompile_jvm_artifact", arguments_);
    const mcpEvidence = await call("decompile_jvm_artifact", {
      path: scenario.path,
      output_directory: mcpOutput,
      classpath: scenario.classpath,
      ...(scenario.class_prefix === undefined
        ? {}
        : { class_prefix: scenario.class_prefix }),
    });
    for (const [evidence, output] of [
      [cliEvidence, cliOutput],
      [mcpEvidence, mcpOutput],
    ]) {
      await verifyOutput(evidence.normalized_result, scenario, output);
      assert.equal(evidence.provider.id, "vineflower");
      assert.equal(
        evidence.provider.version,
        inspected.normalized_result.client.version,
      );
      assert.equal(
        evidence.subject.digest.sha256,
        evidence.normalized_result.target.sha256,
      );
      outputs.push(evidence.normalized_result);
    }
    assert.deepEqual(
      semanticResult(cliEvidence.normalized_result),
      semanticResult(mcpEvidence.normalized_result),
    );
    retained.push(mcpEvidence);
  }

  if (!fixture.caseSensitive) {
    const output = join(directory, "case-refusal");
    let cliError;
    try {
      await runCli("decompile_jvm_artifact", [
        "decompile-jvm-artifact",
        fixture.casePath,
        output,
      ]);
    } catch (cause) {
      if (typeof cause.stdout !== "string") throw cause;
      cliError = JSON.parse(cause.stdout);
    }
    assert.ok(
      cliError,
      "Case-insensitive output silently lost a Java class through CLI",
    );
    assert.ok(
      !(await readdir(directory)).includes("case-refusal"),
      "Failed CLI publication retained partial sources",
    );
    const response = await client.callTool({
      name: "decompile_jvm_artifact",
      arguments: { path: fixture.casePath, output_directory: output },
    });
    const error = requireMcpToolError(response);
    assert.equal(cliError.code, error.code);
    assert.equal(cliError.category, error.category);
    assert.equal(error.category, "execution_failure");
    for (const name of [
      "sources/fixture/CaseProbe.java",
      "sources/fixture/caseprobe.java",
    ])
      assert.ok(
        error.message.includes(name),
        "Collision diagnostic omitted a logical source name",
      );
    assert.ok(
      !(await readdir(directory)).includes("case-refusal"),
      "Failed MCP publication retained partial sources",
    );
  }

  const conflictInput = {
    path: fixture.classPath,
    output_directory: join(directory, "class-cli"),
    classpath: [],
  };
  const conflict = await client.callTool({
    name: "decompile_jvm_artifact",
    arguments: conflictInput,
  });
  const conflictError = requireMcpToolError(conflict);
  let cliConflict;
  try {
    await runCli("decompile_jvm_artifact", [
      "decompile-jvm-artifact",
      conflictInput.path,
      conflictInput.output_directory,
    ]);
  } catch (cause) {
    if (typeof cause.stdout !== "string") throw cause;
    cliConflict = JSON.parse(cause.stdout);
  }
  assert.deepEqual(
    cliConflict,
    conflictError,
    "CLI/MCP output-conflict diagnostics differ",
  );

  const bundle = (await call("get_evidence_bundle", {})).result;
  for (const evidence of retained)
    assert.deepEqual(
      bundle.records.find(
        (record) => record.evidence_id === evidence.evidence_id,
      ),
      evidence,
    );
  const bundlePath = join(directory, "evidence.json");
  await call("export_evidence_bundle", { path: bundlePath });
  const exported = evidenceBundleSchema.parse(
    JSON.parse(await readFile(bundlePath, "utf8")),
  );
  for (const evidence of retained)
    assert.deepEqual(
      exported.records.find(
        (record) => record.evidence_id === evidence.evidence_id,
      ),
      evidence,
    );
  await client.close();
  await transport.close();
  for (let index = 0; index < outputs.length; index += 1) {
    const scenario = scenarios[Math.floor(index / 2)];
    await verifyOutput(
      outputs[index],
      scenario,
      join(directory, `${scenario.name}-${index % 2 === 0 ? "cli" : "mcp"}`),
    );
  }
  for (const input of fixture.inputs)
    assert.equal(
      await digest(input.path),
      input.sha256,
      "JVM analysis modified an input artifact",
    );
  report = {
    ok: true,
    provider: "vineflower",
    engine_version: inspected.normalized_result.client.version,
    host_platform: process.platform,
    host_arch: process.arch,
    javac_version: fixture.javacVersion,
    workflows: scenarios.map(({ name }) => `${name}:cli+stdio-mcp`),
    source_counts: scenarios.map((scenario, index) => ({
      scenario: scenario.name,
      count: outputs[index * 2].sources.length,
    })),
    advertised_schemas_valid: true,
    session_availability_verified: true,
    case_distinct_classes: fixture.caseSensitive
      ? "both_sources_preserved"
      : "collision_refused_without_partial_output",
    source_and_manifest_digests_verified: true,
    durable_outputs_after_session_close_verified: true,
    input_bytes_unchanged: true,
    output_conflict_preserved: true,
    retained_and_exported_evidence_verified: true,
    compilation_status: "not_attempted",
    runtime_equivalence: "unknown",
  };
}, [
  async () => {
    await closeVerifierResources([
      () => client.close(),
      () => transport.close(),
    ]);
    await rm(directory, { recursive: true, force: true });
  },
]);
process.stdout.write(
  `${JSON.stringify({ ...report, owned_cleanup_completed: true })}\n`,
);

async function runCli(operation, arguments_) {
  const { stdout } = await execute(
    process.execPath,
    [cli, ...arguments_, "--json"],
    {
      env: environment,
      maxBuffer: 16 * 1024 * 1024,
      timeout: 180_000,
    },
  );
  return toolContract(operation).outputSchema.parse(JSON.parse(stdout));
}

async function digest(path) {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

async function verifyOutput(result, scenario, output) {
  assert.equal(result.target.path, scenario.path);
  assert.equal(result.target.sha256, await digest(scenario.path));
  assert.equal(result.target.bytes, (await readFile(scenario.path)).length);
  assert.equal(result.class_prefix, scenario.class_prefix ?? null);
  assert.deepEqual(
    result.dependencies.map(({ path }) => path),
    scenario.classpath,
  );
  for (const dependency of result.dependencies) {
    assert.equal(dependency.sha256, await digest(dependency.path));
    assert.equal(dependency.bytes, (await readFile(dependency.path)).length);
  }
  assert.equal(result.compilation_status, "not_attempted");
  assert.equal(result.runtime_equivalence, "unknown");
  assert.equal(result.source_inventory_complete, true);
  assert.equal(result.diagnostics.exit_code, 0);
  assert.equal(result.diagnostics.truncated, false);
  assert.ok(
    result.sources.length > 0,
    `${scenario.name}: Vineflower produced no Java sources: ${JSON.stringify(result.diagnostics)}`,
  );
  const onDisk = (await readdir(output, { recursive: true }))
    .filter((path) => path.endsWith(".java"))
    .sort();
  assert.deepEqual(
    result.sources.map(({ relative_path }) => relative_path).sort(),
    onDisk.map((path) => path.replaceAll("\\", "/")),
  );
  let text = "";
  for (const source of result.sources) {
    assert.equal(
      relative(output, source.path).replaceAll("\\", "/"),
      source.relative_path,
    );
    const bytes = await readFile(source.path);
    assert.equal(source.bytes, bytes.length);
    assert.equal(source.sha256, await digest(source.path));
    text += bytes.toString("utf8");
  }
  assert.ok(
    text.includes("REA_JVM_FIXTURE"),
    "Derived source omitted the authored marker",
  );
  if (scenario.name === "prefix") {
    assert.ok(
      result.sources.every(({ relative_path }) =>
        relative_path.startsWith("sources/fixture/Probe"),
      ),
    );
    assert.ok(
      !text.includes("UNSELECTED_FIXTURE"),
      "Class prefix included an unrelated class",
    );
    assert.ok(
      text.includes("Nested"),
      "Archive decompilation lost the nested class",
    );
    assert.ok(text.includes("->"), "Archive decompilation lost the lambda");
  }
  if (scenario.name === "case") {
    assert.deepEqual(
      result.sources.map(({ relative_path }) => relative_path).sort(),
      ["sources/fixture/CaseProbe.java", "sources/fixture/caseprobe.java"],
    );
    assert.ok(text.includes("REA_JVM_FIXTURE_UPPER"));
    assert.ok(text.includes("REA_JVM_FIXTURE_LOWER"));
  }
  assert.equal(result.manifest.sha256, await digest(result.manifest.path));
  assert.equal(
    result.manifest.bytes,
    (await readFile(result.manifest.path)).length,
  );
  const manifest = JSON.parse(await readFile(result.manifest.path, "utf8"));
  const { manifest: identity, ...expectedManifest } = result;
  assert.equal(identity.path, join(output, "manifest.json"));
  assert.deepEqual(
    manifest,
    expectedManifest,
    "Durable manifest differs from inline decompilation facts",
  );
}

function semanticResult(result) {
  return {
    client: result.client,
    target: result.target,
    dependencies: result.dependencies,
    class_prefix: result.class_prefix,
    sources: result.sources.map(({ relative_path, sha256, bytes }) => ({
      relative_path,
      sha256,
      bytes,
    })),
    source_inventory_complete: result.source_inventory_complete,
    compilation_status: result.compilation_status,
    runtime_equivalence: result.runtime_equivalence,
    limitations: result.limitations,
  };
}
