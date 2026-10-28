import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

describe.skipIf(process.platform !== "darwin")(
  "native dispatch format admission",
  () => {
    cliTest(
      "accepts a walkable 4097-command table and classifies malformed section sizes",
      async ({ cli }) => {
        const root = await createTestTempDirectory("rea-dispatch-format-");
        const commands = Buffer.alloc(32 + 4097 * 16);
        commands.writeUInt32LE(0xfeedfacf, 0);
        commands.writeUInt32LE(0x0100000c, 4);
        commands.writeUInt32LE(2, 12);
        commands.writeUInt32LE(4097, 16);
        commands.writeUInt32LE(4097 * 16, 20);
        for (let index = 0; index < 4097; index++) {
          commands.writeUInt32LE(0x2a, 32 + index * 16);
          commands.writeUInt32LE(16, 36 + index * 16);
        }
        const path = join(root, "commands.macho");
        await writeFile(path, commands);
        const valid = await cli.run({
          arguments: ["inspect-native-dispatch-metadata", path, "--json"],
        });
        expect(valid.exitCode, valid.stdout).toBe(0);
        expect(valid.json).toMatchObject({
          normalized_result: { result: { objc_classes: [] } },
        });

        const malformed = Buffer.alloc(4096);
        malformed.writeUInt32LE(0xfeedfacf, 0);
        malformed.writeUInt32LE(0x0100000c, 4);
        malformed.writeUInt32LE(2, 12);
        malformed.writeUInt32LE(1, 16);
        malformed.writeUInt32LE(152, 20);
        malformed.writeUInt32LE(0x19, 32);
        malformed.writeUInt32LE(152, 36);
        malformed.write("__DATA", 40);
        malformed.writeBigUInt64LE(0x100000000n, 56);
        malformed.writeBigUInt64LE(4096n, 64);
        malformed.writeBigUInt64LE(4096n, 80);
        malformed.writeUInt32LE(1, 96);
        malformed.write("__objc_classlist", 104);
        malformed.write("__DATA", 120);
        malformed.writeBigUInt64LE(0x100000200n, 136);
        malformed.writeBigUInt64LE(12n, 144);
        malformed.writeUInt32LE(512, 152);
        await writeFile(path, malformed);
        const refused = await cli.run({
          arguments: ["inspect-native-dispatch-metadata", path, "--json"],
        });
        expect(refused.exitCode, refused.stdout).toBe(1);
        expect(refused.json).toMatchObject({
          code: "unsupported_target",
          details: { reason: "Misaligned Objective-C class-list size" },
        });
      },
    );
  },
);
