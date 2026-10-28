import { symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createBtfService } from "../../../src/composition/binaryDiagnostics.js";
import { canonicalBtf } from "../../../src/native/btf/Btf.fixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

describe("BTF stable filesystem boundary", () => {
  it("reports non-file and malformed selections as caller input errors", async () => {
    const root = await createTestTempDirectory("rea-btf-files-");
    const path = join(root, "vmlinux.btf");
    const alias = join(root, "alias");
    const malformed = join(root, "malformed");
    await writeFile(path, canonicalBtf().bytes);
    await writeFile(malformed, Buffer.from("not btf"));
    await symlink(path, alias);
    const service = createBtfService();
    for (const [candidate, reason] of [
      [root, "invalid_format"],
      [alias, "invalid_format"],
      [malformed, "invalid_format"],
      [join(root, "missing"), "invalid_value"],
      [join(path, "child"), "invalid_value"],
    ] as const) {
      const result = await service.inspect({ path: candidate });
      if (result.ok) throw new Error("Expected file acquisition failure");
      expect(result.error).toMatchObject({
        _tag: "AnalysisInputError",
        operation: "inspect_btf",
        issues: [
          {
            path: ["path"],
            reason,
            message: expect.any(String),
          },
        ],
      });
    }
  });

  it("returns typed resource and cancellation failures", async () => {
    const root = await createTestTempDirectory("rea-btf-budget-");
    const path = join(root, "vmlinux.btf");
    await writeFile(path, canonicalBtf().bytes);
    const service = createBtfService();
    const tooSmall = await service.inspect({ path, max_file_bytes: 64 });
    if (tooSmall.ok) throw new Error("Expected resource budget failure");
    expect(tooSmall.error._tag).toBe("AnalysisResourceConstraintError");
    const cancelled = await service.inspect(
      { path },
      { signal: AbortSignal.abort() },
    );
    if (cancelled.ok) throw new Error("Expected cancellation");
    expect(cancelled.error._tag).toBe("AnalysisCancelledError");
  });
});
