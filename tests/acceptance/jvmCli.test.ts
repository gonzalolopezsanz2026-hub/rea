import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { expect, onTestFinished } from "vitest";

import { expandToolAvailability } from "../../src/contracts/toolOutputSchemaPrimitives.js";
import { toolContract } from "../../src/contracts/toolContracts.js";

import { parseMcpToolError } from "../fixtures/mcpToolError.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const connect = async (command: string) => {
  const client = new Client({ name: "jvm-public-failures", version: "1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve("scripts/rea.mjs"), "mcp"],
    env: {
      PATH: process.env.PATH ?? "",
      REA_LOG_LEVEL: "silent",
      REA_VINEFLOWER_COMMAND: command,
    },
    stderr: "pipe",
  });
  transport.stderr?.on("data", () => undefined);
  onTestFinished(async () => {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  });
  await client.connect(transport);
  return client;
};

cliTest(
  "reports the caller-selected missing JVM decompiler through CLI and stdio MCP without installing a provider",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-unavailable-");
    const command = join(root, "missing-vineflower");
    const response = await cli.run({
      arguments: ["inspect-jvm-decompiler", "--json"],
      environment: { REA_VINEFLOWER_COMMAND: command, REA_LOG_LEVEL: "silent" },
      timeoutMs: 20_000,
    });
    expect(response.exitCode).toBe(1);
    expect(response.json).toMatchObject({
      code: "capability_unavailable",
      category: "unsupported_provider",
    });
    expect(JSON.stringify(response.json)).toContain(command);
    const client = await connect(command);
    const status = await client.callTool({
      name: "binary_session",
      arguments: {},
    });
    expect(status.isError).not.toBe(true);
    const availability = expandToolAvailability(
      toolContract("binary_session").outputSchema.parse(
        status.structuredContent,
      ).result.tool_availability,
    );
    expect(
      availability.find((tool) => tool.name === "inspect_jvm_decompiler"),
    ).toMatchObject({ available: true });
    const unavailable = availability.find(
      (tool) => tool.name === "decompile_jvm_artifact",
    );
    expect(unavailable).toMatchObject({
      available: false,
      reason: "provider_unavailable",
    });
    expect(unavailable?.remediation).toContain(command);

    const result = await client.callTool({
      name: "inspect_jvm_decompiler",
      arguments: {},
    });
    expect(parseMcpToolError(result)).toEqual({ error: response.json });
    expect(await readdir(root)).toEqual([]);
    const path = join(root, "Fixture.class");
    const output = join(root, "sources");
    const bytes = Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 1]);
    await writeFile(path, bytes);
    const decompilation = await cli.run({
      arguments: ["decompile-jvm-artifact", path, output, "--json"],
      environment: { REA_VINEFLOWER_COMMAND: command, REA_LOG_LEVEL: "silent" },
      timeoutMs: 20_000,
    });
    expect(decompilation.exitCode).toBe(1);
    expect(decompilation.json).toMatchObject({
      code: "capability_unavailable",
    });
    const mcpDecompilation = await client.callTool({
      name: "decompile_jvm_artifact",
      arguments: { path, output_directory: output },
    });
    expect(parseMcpToolError(mcpDecompilation)).toEqual({
      error: decompilation.json,
    });
    expect(await readdir(root)).toEqual(["Fixture.class"]);
    expect((await readFile(path)).equals(bytes)).toBe(true);
  },
  60_000,
);

cliTest(
  "refuses an existing JVM output before provider execution and preserves caller files through CLI and stdio MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-jvm-conflict-");
    const command = join(root, "must-not-run-vineflower");
    const path = join(root, "Fixture.class");
    const output = join(root, "sources");
    const inputBytes = Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61]);
    await writeFile(path, inputBytes);
    await mkdir(output);
    const preserved = join(output, "keep.java");
    await writeFile(preserved, "caller-owned source\n");
    const response = await cli.run({
      arguments: ["decompile-jvm-artifact", path, output, "--json"],
      environment: { REA_VINEFLOWER_COMMAND: command, REA_LOG_LEVEL: "silent" },
      timeoutMs: 20_000,
    });
    expect(response.exitCode).toBe(1);
    expect(response.json).toMatchObject({ code: "invalid_request" });
    expect(JSON.stringify(response.json)).toMatch(/exist|absent|overwrite/u);
    const client = await connect(command);
    const result = await client.callTool({
      name: "decompile_jvm_artifact",
      arguments: { path, output_directory: output, classpath: [] },
    });
    expect(parseMcpToolError(result)).toEqual({ error: response.json });
    expect((await readFile(path)).equals(inputBytes)).toBe(true);
    expect(await readFile(preserved, "utf8")).toBe("caller-owned source\n");
    expect(await readdir(output)).toEqual(["keep.java"]);
  },
  60_000,
);
