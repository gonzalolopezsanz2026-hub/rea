import { readFile, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { FitArtifactReader } from "./FitArtifactReader.js";
import { ArtifactResourceScope } from "./ArtifactResourceScope.js";
import { extractArtifact } from "./extraction/ArtifactExtraction.js";
import * as fitStructure from "./fit/FitStructure.js";
import {
  FIT_DEVICETREE,
  FIT_EMBEDDED,
  FIT_EXTERNAL,
  FIT_KERNEL,
  fitFixture,
} from "./fit/FitImage.fixture.js";
import {
  cells,
  devicetreeFixture,
} from "../firmware/devicetree/Devicetree.fixture.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { scanCanonicalArtifactInventory } from "../../tests/fixtures/artifactInventory.js";

const MIB = 1024 * 1024;

const writeFit = async (name: string, bytes: Buffer): Promise<string> => {
  const directory = await createTestTempDirectory("rea-fit-");
  const path = join(directory, name);
  await writeFile(path, bytes);
  return path;
};

const withTotalsize = (bytes: Buffer, totalsize: number): Buffer => {
  const copy = Buffer.from(bytes);
  copy.writeUInt32BE(totalsize, 4);
  return copy;
};

const LARGE_FIT = fitFixture({
  images: [{ name: "kernel", data: Buffer.alloc(MIB, 7), hashes: ["sha256"] }],
  mode: "offset",
});

const firstEntry = async (reader: FitArtifactReader) => {
  const { value: entry } = await reader
    .entries()
    [Symbol.asyncIterator]()
    .next();
  if (entry === undefined) throw new Error("Missing FIT image");
  return entry;
};

it.each([
  ["embedded", FIT_EMBEDDED, "embedded"],
  ["external", FIT_EXTERNAL, "data-offset"],
] as const)(
  "inventories %s FIT images with root and image facts",
  async (_mode, bytes, dataSource) => {
    const snapshot = await scanCanonicalArtifactInventory(
      await writeFit("boot.itb", bytes),
    );
    expect(snapshot.manifest.root_format).toBe("fit");
    expect(snapshot.coverage).toMatchObject({
      scope: "container-entries",
      status: "complete",
    });
    expect(
      snapshot.limitations.some((limitation) =>
        limitation.startsWith("FIT inventory"),
      ),
    ).toBe(true);
    const root = snapshot.occurrences.find((row) => row.logical_path === ".");
    expect(root).toMatchObject({
      artifact_kind: "container",
      format_metadata: {
        kind: "fit",
        fdt_version: 17,
        description: "Test FIT",
        timestamp: 1_700_000_000,
        address_cells: 1,
        default_configuration: "conf-1",
        configurations: [
          {
            name: "conf-1",
            description: "Boot Linux",
            kernel: ["kernel"],
            fdt: ["fdt-1"],
            signature_algorithms: ["sha256,rsa2048"],
          },
        ],
      },
    });
    const kernel = snapshot.occurrences.find(
      (row) => row.logical_path === "images/kernel.bin",
    );
    const devicetree = snapshot.occurrences.find(
      (row) => row.logical_path === "images/fdt-1.bin",
    );
    expect(snapshot.occurrences).toHaveLength(3);
    for (const [row, data] of [
      [kernel, FIT_KERNEL],
      [devicetree, FIT_DEVICETREE],
    ] as const) {
      const offset = row?.source_location?.offset ?? -1;
      expect(row?.declared_size).toBe(data.length);
      expect(bytes.subarray(offset, offset + data.length).equals(data)).toBe(
        true,
      );
    }
    expect(kernel?.format_metadata).toMatchObject({
      kind: "fit-image",
      name: "kernel",
      type: "kernel",
      arch: "arm64",
      load: "0x40200000",
      entry: "0x40200000",
      data_source: dataSource,
      hashes_verified: 6,
      hashes_unverified: 0,
    });
    expect(devicetree?.format_metadata).toMatchObject({
      kind: "fit-image",
      type: "flat_dt",
      hashes_verified: 1,
    });
  },
);

it.each(["crc32", "md5", "sha1", "sha256", "sha384", "sha512"])(
  "fails a %s hash mismatch naming the image, node and algorithm",
  async (algo) => {
    const bytes = fitFixture({
      images: [{ name: "kernel", data: FIT_KERNEL, hashes: [algo] }],
      mode: "offset",
    });
    const kernel = bytes.indexOf(FIT_KERNEL);
    bytes[kernel + 10] = (bytes[kernel + 10] ?? 0) ^ 1;
    await expect(
      scanCanonicalArtifactInventory(await writeFit("bad.itb", bytes)),
    ).rejects.toMatchObject({
      reason: "integrity",
      message: expect.stringMatching(
        new RegExp(
          `^FIT image kernel hash-1 ${algo} does not match: declared [0-9a-f]+, computed [0-9a-f]+$`,
          "u",
        ),
      ),
    });
  },
);

it.each([
  ["embedded", FIT_EMBEDDED],
  ["external", FIT_EXTERNAL],
] as const)(
  "extracts byte-exact %s images that re-inventory as raw files",
  async (_mode, bytes) => {
    const path = await writeFit("boot.itb", bytes);
    const resourceScope = new ArtifactResourceScope();
    try {
      const extracted = await extractArtifact({
        inputPath: path,
        inputFormat: "fit",
        outputRoot: join(path, "..", "out"),
        environment: process.env,
        integrityPolicy: "fail",
        resourceScope,
      });
      expect(extracted.containment_verified).toBe(true);
      for (const [name, data] of [
        ["kernel.bin", FIT_KERNEL],
        ["fdt-1.bin", FIT_DEVICETREE],
      ] as const)
        expect(
          Buffer.compare(
            await readFile(join(extracted.output_root, "images", name)),
            data,
          ),
        ).toBe(0);
      const reinventoried = await scanCanonicalArtifactInventory(
        extracted.output_root,
      );
      expect(
        reinventoried.occurrences
          .filter((row) => row.entry_kind === "file")
          .map((row) => [row.logical_path, row.artifact_format])
          .sort(),
      ).toEqual([
        ["images/fdt-1.bin", "file"],
        ["images/kernel.bin", "file"],
      ]);
    } finally {
      await resourceScope.close();
    }
  },
);

it("inventories an external-data FIT larger than 16 MiB", async () => {
  const bytes = fitFixture({
    images: [
      {
        name: "rootfs",
        data: Buffer.alloc(0),
        properties: { "data-offset": cells(17 * MIB), "data-size": cells(4) },
      },
    ],
    mode: "offset",
  });
  const path = await writeFit("large.itb", bytes);
  const base = Math.ceil(bytes.readUInt32BE(4) / 4) * 4;
  await truncate(path, base + 17 * MIB + 4);
  const snapshot = await scanCanonicalArtifactInventory(path);
  expect(
    snapshot.occurrences.find(
      (row) => row.logical_path === "images/rootfs.bin",
    ),
  ).toMatchObject({
    declared_size: 4,
    source_location: { offset: base + 17 * MIB, length: 4 },
  });
});

it("fails an embedded devicetree above 16 MiB with a fixed limit", async () => {
  const path = await writeFit(
    "huge.itb",
    withTotalsize(FIT_EMBEDDED, 16 * MIB + 4),
  );
  await truncate(path, 16 * MIB + 8);
  await expect(scanCanonicalArtifactInventory(path)).rejects.toMatchObject({
    reason: "limit",
    boundary: "memory",
  });
});

it("fails a devicetree totalsize past the end of the file", async () => {
  await expect(
    scanCanonicalArtifactInventory(
      await writeFit(
        "short.itb",
        withTotalsize(FIT_EMBEDDED, FIT_EMBEDDED.length + 4),
      ),
    ),
  ).rejects.toMatchObject({
    reason: "format",
    message: expect.stringContaining("FIT devicetree is truncated"),
  });
});

it("fails /images followed by a malformed structure, and leaves a plain DTB a file", async () => {
  const bytes = Buffer.from(FIT_EMBEDDED);
  const end = bytes.readUInt32BE(8) + bytes.readUInt32BE(36) - 4;
  expect(bytes.readUInt32BE(end)).toBe(9);
  bytes.writeUInt32BE(10, end);
  await expect(
    scanCanonicalArtifactInventory(await writeFit("broken.itb", bytes)),
  ).rejects.toMatchObject({
    reason: "format",
    message: "FIT is malformed: Unknown FDT token 10",
  });
  const plain = await scanCanonicalArtifactInventory(
    await writeFit("board.dtb", devicetreeFixture()),
  );
  expect(plain.manifest.root_format).toBe("file");
});

it("rejects a changed carrier during extraction preparation", async () => {
  const reader = new FitArtifactReader(
    await writeFit("changed.itb", FIT_EMBEDDED),
  );
  try {
    await expect(reader.prepareContainer("0".repeat(64))).rejects.toMatchObject(
      { reason: "integrity" },
    );
  } finally {
    await reader.close();
  }
});

it("rejects forged entries and changed carrier identity, then closes idempotently", async () => {
  const path = await writeFit("identity.itb", FIT_EXTERNAL);
  const reader = new FitArtifactReader(path);
  try {
    const entry = await firstEntry(reader);
    await expect(
      reader.open({ ...entry, byteOffset: 0 }),
    ).rejects.toMatchObject({ reason: "integrity" });
    await expect(
      reader.open({ ...entry, adapterKey: "fit:9" }),
    ).rejects.toMatchObject({ reason: "integrity" });
    await writeFile(path, FIT_EMBEDDED);
    await expect(reader.open(entry)).rejects.toMatchObject({
      reason: "integrity",
    });
  } finally {
    await reader.close();
    await reader.close();
  }
});

it("settles an active image stream when closed", async () => {
  const reader = new FitArtifactReader(await writeFit("close.itb", LARGE_FIT));
  try {
    const stream = await reader.open(await firstEntry(reader));
    await reader.close();
    expect(stream.destroyed).toBe(true);
    await expect(
      reader.entries()[Symbol.asyncIterator]().next(),
    ).rejects.toMatchObject({ reason: "unavailable" });
  } finally {
    await reader.close();
  }
});

it("keeps the cancellation reason before admission", async () => {
  const reader = new FitArtifactReader(
    await writeFit("cancel.itb", FIT_EMBEDDED),
  );
  const controller = new AbortController();
  const reason = { stage: "before admission" };
  controller.abort(reason);
  try {
    await expect(
      reader.entries(controller.signal)[Symbol.asyncIterator]().next(),
    ).rejects.toMatchObject({ reason: "cancelled", cause: reason });
  } finally {
    await reader.close();
  }
});

it("keeps the cancellation reason during hash verification", async () => {
  const reader = new FitArtifactReader(
    await writeFit("hashing.itb", LARGE_FIT),
  );
  const controller = new AbortController();
  const reason = { stage: "hashing" };
  const create = fitStructure.createFitDigest;
  const observer = vi
    .spyOn(fitStructure, "createFitDigest")
    .mockImplementation((algo) => {
      const digest = create(algo);
      return (
        digest && {
          update: (chunk) => {
            controller.abort(reason);
            digest.update(chunk);
          },
          digest: () => digest.digest(),
        }
      );
    });
  try {
    await expect(
      reader.entries(controller.signal)[Symbol.asyncIterator]().next(),
    ).rejects.toMatchObject({ reason: "cancelled", cause: reason });
    expect(observer).toHaveBeenCalledWith("sha256");
  } finally {
    observer.mockRestore();
    await reader.close();
  }
});

it("keeps the cancellation reason after an image stream was opened", async () => {
  const reader = new FitArtifactReader(await writeFit("stream.itb", LARGE_FIT));
  const controller = new AbortController();
  const reason = { stage: "image consumption" };
  try {
    const stream = await reader.open(
      await firstEntry(reader),
      controller.signal,
    );
    controller.abort(reason);
    await expect(
      (async () => {
        for await (const _chunk of stream) {
          /* drain */
        }
      })(),
    ).rejects.toMatchObject({ reason: "cancelled", cause: reason });
    await reader.close();
    expect(stream.closed).toBe(true);
  } finally {
    await reader.close();
  }
});
