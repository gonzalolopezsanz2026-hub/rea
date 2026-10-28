import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, onTestFinished } from "vitest";
import { cliTest } from "../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import {
  FIT_DEVICETREE,
  FIT_EMBEDDED,
  FIT_EXTERNAL,
  FIT_KERNEL,
  fitFixture,
} from "../../src/artifacts/fit/FitImage.fixture.js";
import {
  cells,
  dtString,
} from "../../src/firmware/devicetree/Devicetree.fixture.js";
import { parseEvidence } from "../../src/domain/evidence.js";
import { artifactInspectionResultSchema } from "../../src/domain/artifactInspection.js";
import {
  artifactExtractionResultSchema,
  artifactInventoryResultSchema,
} from "../../src/domain/artifactGraph.js";

const cases = [
  { mode: "embedded", bytes: FIT_EMBEDDED },
  { mode: "external", bytes: FIT_EXTERNAL },
] as const;

cliTest.for(cases)(
  "inventories and extracts $mode FIT images through the compiled CLI",
  async ({ bytes }, { cli }) => {
    const directory = await createTestTempDirectory("rea-fit-cli-");
    const source = join(directory, "boot.itb");
    await writeFile(source, bytes);
    const inspected = await cli.run({
      arguments: ["inspect-artifact", source, "--json"],
    });
    expect(inspected.exitCode, inspected.stdout + inspected.stderr).toBe(0);
    const inspection = artifactInspectionResultSchema.parse(
      parseEvidence(inspected.json).normalized_result,
    );
    const graph = artifactInventoryResultSchema.parse(
      inspection.substeps[0]?.evidence.normalized_result,
    );
    expect(graph.manifest.root_format).toBe("fit");
    expect(
      graph.occurrences.find((row) => row.logical_path === ".")
        ?.format_metadata,
    ).toMatchObject({
      kind: "fit",
      description: "Test FIT",
      default_configuration: "conf-1",
    });
    expect(
      graph.occurrences
        .filter((row) => row.logical_path !== ".")
        .map((row) => row.logical_path)
        .sort(),
    ).toEqual(["images/fdt-1.bin", "images/kernel.bin"]);
    expect(inspection.next_probes.map((probe) => probe.operation)).toEqual([
      "inspect_devicetree",
      "open_binary",
    ]);
    const extracted = await cli.run({
      arguments: ["extract-artifact", source, "--json"],
      environment: { TMPDIR: directory, TMP: directory, TEMP: directory },
    });
    expect(extracted.exitCode, extracted.stdout + extracted.stderr).toBe(0);
    const result = artifactExtractionResultSchema.parse(
      parseEvidence(extracted.json).normalized_result,
    );
    onTestFinished(() =>
      rm(result.output_root, { recursive: true, force: true }),
    );
    expect(result.containment_verified).toBe(true);
    for (const [path, data] of [
      ["images/kernel.bin", FIT_KERNEL],
      ["images/fdt-1.bin", FIT_DEVICETREE],
    ] as const)
      expect(
        Buffer.compare(await readFile(join(result.output_root, path)), data),
      ).toBe(0);
  },
);

cliTest("rejects a FIT hash mismatch through the CLI", async ({ cli }) => {
  const directory = await createTestTempDirectory("rea-fit-invalid-cli-");
  const source = join(directory, "boot.itb");
  const bytes = Buffer.from(FIT_EXTERNAL);
  const kernel = bytes.indexOf(FIT_KERNEL);
  bytes[kernel] = (bytes[kernel] ?? 0) ^ 1;
  await writeFile(source, bytes);
  const result = await cli.run({
    arguments: ["inspect-artifact", source, "--json"],
  });
  expect(result.exitCode).not.toBe(0);
  expect(result.stdout + result.stderr).toContain(
    "FIT image kernel hash-1 crc32 does not match",
  );
});

cliTest(
  "suggests no direct analysis for compressed or ciphered FIT images",
  async ({ cli }) => {
    const directory = await createTestTempDirectory("rea-fit-encoded-cli-");
    const source = join(directory, "boot.itb");
    await writeFile(
      source,
      fitFixture({
        images: [
          {
            name: "kernel",
            data: FIT_KERNEL,
            properties: {
              compression: dtString("none"),
              load: cells(0x4020_0000),
            },
            children: [
              { name: "cipher", properties: { algo: dtString("aes256") } },
            ],
          },
          {
            name: "fdt-1",
            data: FIT_DEVICETREE,
            properties: {
              type: dtString("flat_dt"),
              compression: dtString("gzip"),
            },
          },
        ],
      }),
    );
    const inspected = await cli.run({
      arguments: ["inspect-artifact", source, "--json"],
    });
    expect(inspected.exitCode, inspected.stdout + inspected.stderr).toBe(0);
    const inspection = artifactInspectionResultSchema.parse(
      parseEvidence(inspected.json).normalized_result,
    );
    expect(inspection.next_probes.map((probe) => probe.operation)).not.toEqual(
      expect.arrayContaining(["inspect_devicetree"]),
    );
    expect(inspection.next_probes.map((probe) => probe.operation)).not.toEqual(
      expect.arrayContaining(["open_binary"]),
    );
  },
);
