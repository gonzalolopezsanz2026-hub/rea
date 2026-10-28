import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import {
  btfElfFixture,
  btfExtFixture,
  btfFuncRecord,
  canonicalBtf,
} from "../../src/native/btf/Btf.fixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest("inspects a standalone BTF type by name", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-btf-cli-");
  const path = join(root, "vmlinux.btf");
  await writeFile(path, canonicalBtf().bytes);
  const result = await cli.run({
    arguments: ["inspect-btf", path, "--type-name", "flags", "--json"],
  });
  expect(result.exitCode, result.stderr).toBe(0);
  const evidence = toolContract("inspect_btf").outputSchema.parse(result.json);
  expect(evidence.subject?.local_path).toBe(path);
  expect(evidence.normalized_result.types.entries).toMatchObject([
    {
      id: 21,
      kind: "struct",
      kind_flag: true,
      members: [{ name: "low", bit_offset: 0, bitfield_size: 3 }],
    },
  ]);
});

cliTest(
  "resolves a relative BTF path against the working directory",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-btf-cli-rel-");
    await writeFile(join(root, "vmlinux.btf"), canonicalBtf().bytes);
    const result = await cli.run({
      arguments: ["inspect-btf", "vmlinux.btf", "--type-limit", "1", "--json"],
      cwd: root,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = toolContract("inspect_btf").outputSchema.parse(
      result.json,
    );
    expect(evidence.normalized_result.types.entries[0]).toMatchObject({
      id: 1,
      name: "int",
    });
  },
);

cliTest("pages .BTF.ext func records for an ELF section", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-btf-cli-ext-");
  const path = join(root, "program.ko");
  const { fixture, ids } = canonicalBtf();
  const text = ".text";
  const ext = btfExtFixture({
    func: [
      {
        sectionNameOffset: fixture.name(text),
        records: [btfFuncRecord(0, ids.func), btfFuncRecord(8, ids.func)],
      },
    ],
  });
  const bytes = btfElfFixture(fixture.build(), { ext });
  await writeFile(path, bytes);
  const result = await cli.run({
    arguments: [
      "inspect-btf",
      path,
      "--ext-section",
      text,
      "--ext-offset",
      "1",
      "--ext-limit",
      "1",
      "--json",
    ],
  });
  expect(result.exitCode, result.stderr).toBe(0);
  const evidence = toolContract("inspect_btf").outputSchema.parse(result.json);
  expect(evidence.normalized_result.ext?.selection).toMatchObject({
    section: text,
    offset: 1,
    limit: 1,
    func: [{ insn_off: 8, type_id: ids.func }],
    func_total: 2,
  });
  expect(Buffer.compare(await readFile(path), bytes)).toBe(0);
});

cliTest("reports a non-BTF artifact as invalid input", async ({ cli }) => {
  const root = await createTestTempDirectory("rea-btf-cli-bad-");
  const path = join(root, "broken");
  await writeFile(path, Buffer.from("\x7fELF"));
  const result = await cli.run({
    arguments: ["inspect-btf", path, "--json"],
  });
  expect(result.exitCode).toBe(1);
  expect(result.json).toMatchObject({
    code: "invalid_request",
    details: { operation: "inspect_btf" },
  });
});

cliTest(
  "reports a missing BTF section as invalid input without mutation",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-btf-cli-section-");
    const path = join(root, "no-btf.o");
    const bytes = btfElfFixture(canonicalBtf().bytes, { sectionName: ".data" });
    await writeFile(path, bytes);
    const result = await cli.run({
      arguments: ["inspect-btf", path, "--json"],
    });
    expect(result.exitCode).toBe(1);
    expect(result.json).toMatchObject({
      code: "invalid_request",
      details: {
        operation: "inspect_btf",
        issues: [
          {
            path: ["path"],
            reason: "invalid_format",
            message: expect.stringContaining("declares no .BTF section"),
          },
        ],
      },
    });
    expect((await readFile(path)).equals(bytes)).toBe(true);
  },
);
