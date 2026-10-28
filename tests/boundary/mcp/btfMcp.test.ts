import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import {
  btfElfFixture,
  btfExtFixture,
  btfFuncRecord,
  canonicalBtf,
} from "../../../src/native/btf/Btf.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { mcpTest, type TestMcp } from "../../support/mcp/mcpFixture.js";

const connect = async (mcp: TestMcp) => {
  const session = createTestBinarySession(() => {
    throw new Error("BTF inspection must not start a deep provider");
  });
  const client = await mcp.connect(createServer({ kind: "session", session }));
  return { client, session };
};

mcpTest(
  "advertises inspect_btf and reads a selected struct",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const advertised = (await client.listTools()).tools.find(
        (tool) => tool.name === "inspect_btf",
      );
      expect(advertised?.annotations).toMatchObject({
        readOnlyHint: false,
        idempotentHint: true,
      });
      const root = await createTestTempDirectory("rea-btf-mcp-");
      const path = join(root, "vmlinux.btf");
      await writeFile(path, canonicalBtf().bytes);
      const response = await client.callTool({
        name: "inspect_btf",
        arguments: { path, type_name: "sample", type_limit: 1 },
      });
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      const evidence = toolContract("inspect_btf").outputSchema.parse(
        response.structuredContent,
      );
      expect(evidence.normalized_result.carrier).toBe("standalone");
      expect(evidence.normalized_result.types.selection).toBe("name");
      expect(evidence.normalized_result.types.entries).toMatchObject([
        {
          name: "sample",
          kind: "struct",
          members: [
            { name: "a", bit_offset: 0 },
            { name: "b", bit_offset: 32 },
          ],
        },
      ]);
    } finally {
      await session.close();
    }
  },
);

mcpTest("requires an absolute path for inspect_btf", async ({ mcp }) => {
  const { client, session } = await connect(mcp);
  try {
    const response = await client.callTool({
      name: "inspect_btf",
      arguments: { path: "vmlinux.btf" },
    });
    expect(response.isError).toBe(true);
    expect(parseMcpToolError(response).error).toMatchObject({
      code: "invalid_request",
      details: { operation: "inspect_btf" },
    });
  } finally {
    await session.close();
  }
});

mcpTest("rejects selecting a type by both id and name", async ({ mcp }) => {
  const { client, session } = await connect(mcp);
  try {
    const root = await createTestTempDirectory("rea-btf-select-mcp-");
    const path = join(root, "vmlinux.btf");
    await writeFile(path, canonicalBtf().bytes);
    const response = await client.callTool({
      name: "inspect_btf",
      arguments: { path, type_id: 1, type_name: "sample" },
    });
    expect(response.isError).toBe(true);
    expect(parseMcpToolError(response).error).toMatchObject({
      code: "invalid_request",
      details: { operation: "inspect_btf" },
    });
  } finally {
    await session.close();
  }
});

mcpTest(
  "reads func and line records from an ELF .BTF.ext section",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const root = await createTestTempDirectory("rea-btf-ext-mcp-");
      const path = join(root, "program.ko");
      const { fixture, ids } = canonicalBtf();
      const text = ".text";
      const source = "src/main.c";
      const ext = btfExtFixture({
        func: [
          {
            sectionNameOffset: fixture.name(text),
            records: [btfFuncRecord(0, ids.func)],
          },
        ],
        line: [
          {
            sectionNameOffset: fixture.name(text),
            records: [],
          },
        ],
      });
      await writeFile(path, btfElfFixture(fixture.build(), { ext }));
      const response = await client.callTool({
        name: "inspect_btf",
        arguments: { path, ext_section: text },
      });
      expect(response.isError, JSON.stringify(response.content)).not.toBe(true);
      const evidence = toolContract("inspect_btf").outputSchema.parse(
        response.structuredContent,
      );
      expect(evidence.normalized_result.elf).toMatchObject({
        format: "elf64",
        type_name: "relocatable",
      });
      expect(evidence.normalized_result.ext?.selection).toMatchObject({
        section: text,
        func: [{ type_id: ids.func, function: "do_work" }],
      });
    } finally {
      await session.close();
    }
  },
);

mcpTest(
  "reports a non-BTF artifact as invalid input and recovers",
  async ({ mcp }) => {
    const { client, session } = await connect(mcp);
    try {
      const root = await createTestTempDirectory("rea-btf-bad-mcp-");
      const path = join(root, "not-btf");
      await writeFile(path, Buffer.from("not a btf blob"));
      const rejected = await client.callTool({
        name: "inspect_btf",
        arguments: { path },
      });
      expect(rejected.isError).toBe(true);
      expect(parseMcpToolError(rejected).error).toMatchObject({
        code: "invalid_request",
        category: "invalid_input",
      });
      await writeFile(path, canonicalBtf().bytes);
      const accepted = await client.callTool({
        name: "inspect_btf",
        arguments: { path, type_limit: 1 },
      });
      expect(accepted.isError).not.toBe(true);
    } finally {
      await session.close();
    }
  },
);
