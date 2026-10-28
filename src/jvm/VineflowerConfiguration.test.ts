import { expect, it } from "vitest";
import { parseVineflowerVersion } from "./VineflowerConfiguration.js";

it("recognizes the real help banner while rejecting unrelated tools", () => {
  expect(
    parseVineflowerVersion(
      "=== Vineflower Decompiler 1.12.0 ===\n\n--- Command-line options ---",
      "",
    ),
  ).toBe("1.12.0");
  expect(() =>
    parseVineflowerVersion("java 24.0.2", "", "decompile_jvm_artifact"),
  ).toThrow(
    expect.objectContaining({
      operation: "decompile_jvm_artifact",
      _tag: "AnalysisCapabilityUnavailableError",
    }),
  );
});
