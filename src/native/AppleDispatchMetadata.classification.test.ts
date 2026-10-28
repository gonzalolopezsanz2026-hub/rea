import { expect, it } from "vitest";

import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  appleDispatchMetadataFailure,
  decodeAppleDispatchMetadata,
} from "./AppleDispatchMetadata.js";
import { parseMachoLayout } from "./AppleMachoSelection.js";

const provenance = { path: "/selected", sha256: "fixture" };

const metadataSection = (name: string, size: number): Buffer => {
  const bytes = Buffer.alloc(4096);
  bytes.writeUInt32LE(0xfeedfacf, 0);
  bytes.writeUInt32LE(0x0100000c, 4);
  bytes.writeUInt32LE(2, 12);
  bytes.writeUInt32LE(1, 16);
  bytes.writeUInt32LE(152, 20);
  bytes.writeUInt32LE(0x19, 32);
  bytes.writeUInt32LE(152, 36);
  bytes.write("__DATA", 40);
  bytes.writeBigUInt64LE(0x100000000n, 56);
  bytes.writeBigUInt64LE(4096n, 64);
  bytes.writeBigUInt64LE(4096n, 80);
  bytes.writeUInt32LE(1, 96);
  bytes.write(name, 104);
  bytes.write("__DATA", 120);
  bytes.writeBigUInt64LE(0x100000200n, 136);
  bytes.writeBigUInt64LE(BigInt(size), 144);
  bytes.writeUInt32LE(512, 152);
  return bytes;
};

it.each([
  ["__objc_classlist", 12, "Misaligned Objective-C class-list size"],
  ["__objc_protolist", 12, "Misaligned Objective-C protocol list"],
  ["__objc_catlist", 12, "Misaligned Objective-C category list"],
  ["__swift5_types", 6, "Misaligned Swift type section"],
  ["__swift5_proto", 6, "Misaligned Swift conformance section"],
] as const)(
  "classifies malformed %s as a target refusal",
  (name, size, reason) => {
    let thrown: unknown;
    try {
      decodeAppleDispatchMetadata(metadataSection(name, size), 10, provenance);
    } catch (cause) {
      thrown = cause;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(
      projectAnalysisError(
        appleDispatchMetadataFailure(thrown, provenance.path),
      ),
    ).toMatchObject({
      code: "unsupported_target",
      message: expect.stringContaining(reason),
    });
  },
);

it("admits a complete 4097-command table and rejects truncated framing", () => {
  const count = 4097;
  const bytes = Buffer.alloc(32 + count * 16);
  bytes.writeUInt32LE(0xfeedfacf, 0);
  bytes.writeUInt32LE(0x0100000c, 4);
  bytes.writeUInt32LE(2, 12);
  bytes.writeUInt32LE(count, 16);
  bytes.writeUInt32LE(count * 16, 20);
  for (let index = 0; index < count; index++) {
    bytes.writeUInt32LE(0x2a, 32 + index * 16);
    bytes.writeUInt32LE(16, 36 + index * 16);
  }
  expect(parseMachoLayout(bytes, "arm64").sections).toEqual([]);
  let thrown: unknown;
  try {
    parseMachoLayout(bytes.subarray(0, bytes.length - 1), "arm64");
  } catch (cause) {
    thrown = cause;
  }
  expect(
    projectAnalysisError(appleDispatchMetadataFailure(thrown, provenance.path)),
  ).toMatchObject({
    code: "unsupported_target",
    details: { reason: "Malformed Mach-O command bounds" },
  });
});

it("classifies an unsupported big-endian CPU as a target refusal", () => {
  const bytes = Buffer.alloc(32);
  bytes.writeUInt32BE(0xfeedfacf, 0);
  bytes.writeUInt32BE(0x0100000c, 4);
  let thrown: unknown;
  try {
    decodeAppleDispatchMetadata(bytes, 10, provenance);
  } catch (cause) {
    thrown = cause;
  }
  expect(
    projectAnalysisError(appleDispatchMetadataFailure(thrown, provenance.path)),
  ).toMatchObject({
    code: "unsupported_target",
    message: expect.stringContaining("Unsupported big-endian Mach-O CPU type"),
  });
});
