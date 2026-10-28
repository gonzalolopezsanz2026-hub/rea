import { expect, it } from "vitest";
import { BtfService } from "./BtfService.js";
import { BTF_PROVIDER } from "../../domain/investigationProviders.js";
import {
  inspectBtfInputSchema,
  type Btf,
  type InspectBtfInput,
} from "../../domain/native/btf.js";
import { ok } from "../../domain/result.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { btfElfFixture, canonicalBtf } from "../../native/btf/Btf.fixture.js";
import { selectBtfCarrier } from "../../native/btf/BtfCarrier.js";
import { parseBtf } from "../../native/btf/BtfParser.js";

const identity = BTF_PROVIDER;
const path = "/artifacts/kernel.btf";

const parse = (bytes: Buffer, overrides: Partial<InspectBtfInput> = {}) => {
  const input = inspectBtfInputSchema.parse({ path, ...overrides });
  const carrier = selectBtfCarrier(bytes, input.section, input.max_file_bytes);
  return parseBtf(
    carrier,
    { path, sha256: "a".repeat(64), bytes: bytes.length },
    input,
  );
};

const report = (): Btf => {
  const { bytes } = canonicalBtf();
  return parse(bytes, { type_limit: 3 });
};

it("rejects a relative path and extra arguments before reading", async () => {
  let calls = 0;
  const service = new BtfService({
    identity,
    inspect: () => {
      calls += 1;
      return Promise.resolve(ok(report()));
    },
  });
  const relative = await service.inspect({ path: "kernel.btf" });
  const extra = await service.inspect({ path, extra: true });
  expect(relative.ok).toBe(false);
  expect(extra.ok).toBe(false);
  if (!relative.ok) expect(relative.error).toBeInstanceOf(AnalysisInputError);
  if (!extra.ok) expect(extra.error).toBeInstanceOf(AnalysisInputError);
  expect(calls).toBe(0);
});

it("records standalone BTF as a file subject without an architecture", async () => {
  const value = report();
  const result = await new BtfService({
    identity,
    inspect: () => Promise.resolve(ok(value)),
  }).inspect({ path, type_limit: 3 });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "observed",
    subject: { format: "file", local_path: path },
    normalized_result: value,
  });
  expect(result.value.subject?.architecture).toBeNull();
  expect(result.value.locations).toEqual(
    expect.arrayContaining([
      { kind: "artifact-path", path },
      {
        kind: "file-offset-range",
        start: value.header.type.offset,
        end: value.header.type.offset + value.header.type.bytes,
      },
    ]),
  );
});

it("records an ELF carrier and its selected section range", async () => {
  const { bytes } = canonicalBtf();
  const value = parse(btfElfFixture(bytes));
  const result = await new BtfService({
    identity,
    inspect: () => Promise.resolve(ok(value)),
  }).inspect({ path });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value.subject?.format).toBe("elf");
  const section = value.section;
  if (section === null) throw new Error("Expected an ELF section carrier");
  expect(result.value.locations).toContainEqual({
    kind: "file-offset-range",
    start: section.location.offset,
    end: section.location.offset + section.location.bytes,
  });
});

it("rejects a page beyond the advertised type limit", async () => {
  const value = report();
  const result = await new BtfService({
    identity,
    inspect: () =>
      Promise.resolve(
        ok({
          ...value,
          types: {
            ...value.types,
            page: { ...value.types.page, limit: 101 },
          },
        }),
      ),
  }).inspect({ path, type_limit: 3 });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
});

it("rejects a report whose artifact exceeds the caller read budget", async () => {
  const value = report();
  const result = await new BtfService({
    identity,
    inspect: () => Promise.resolve(ok(value)),
  }).inspect({ path, max_file_bytes: 64 });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
});

it("rejects a report whose header ranges leave the blob", async () => {
  const value = report();
  const result = await new BtfService({
    identity,
    inspect: () =>
      Promise.resolve(
        ok({
          ...value,
          header: {
            ...value.header,
            type: { offset: value.artifact.bytes, bytes: 1 },
          },
        }),
      ),
  }).inspect({ path, type_limit: 3 });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
});

it("discards an observation if the caller cancels while the provider completes", async () => {
  const controller = new AbortController();
  const service = new BtfService({
    identity,
    inspect: () => {
      controller.abort();
      return Promise.resolve(ok(report()));
    },
  });
  const result = await service.inspect(
    { path, type_limit: 3 },
    {
      signal: controller.signal,
    },
  );
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
});
