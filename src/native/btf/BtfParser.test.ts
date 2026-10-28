import { expect, it } from "vitest";
import {
  inspectBtfInputSchema,
  type InspectBtfInput,
} from "../../domain/native/btf.js";
import {
  BtfFixture,
  btfCoreRecord,
  btfElfFixture,
  btfExtFixture,
  btfFuncRecord,
  btfLineRecord,
  canonicalBtf,
} from "./Btf.fixture.js";
import { selectBtfCarrier } from "./BtfCarrier.js";
import { parseBtf } from "./BtfParser.js";

const parse = (bytes: Buffer, overrides: Partial<InspectBtfInput> = {}) => {
  const input = inspectBtfInputSchema.parse({
    path: "/artifacts/input.btf",
    ...overrides,
  });
  const carrier = selectBtfCarrier(bytes, input.section, input.max_file_bytes);
  return parseBtf(
    carrier,
    {
      path: "/artifacts/input.btf",
      sha256: "a".repeat(64),
      bytes: bytes.length,
    },
    input,
  );
};

it("decodes every released kind from a little-endian blob", () => {
  const { bytes, ids } = canonicalBtf();
  const report = parse(bytes);
  expect(report.header).toMatchObject({
    byte_order: "little",
    version: 1,
    hdr_len: 24,
  });
  expect(report.carrier).toBe("standalone");
  expect(report.types.total).toBe(22);
  expect(report.coverage.status).toBe("complete");

  const entry = (id: number) =>
    report.types.entries.find((candidate) => candidate.id === id);
  expect(entry(ids.int)).toMatchObject({
    kind: "int",
    name: "int",
    size: 4,
    int: {
      encoding: 1,
      encoding_names: ["signed"],
      bits: 32,
      offset_bits: 0,
    },
  });
  expect(entry(ids.pointer)).toMatchObject({ kind: "ptr", type: ids.int });
  expect(entry(ids.array)).toMatchObject({
    kind: "array",
    array: { element_type: ids.int, index_type: ids.int, elements: 8 },
  });
  expect(entry(ids.struct)).toMatchObject({
    kind: "struct",
    name: "sample",
    size: 16,
    members: [
      { name: "a", type: ids.int, bit_offset: 0, bitfield_size: null },
      { name: "b", type: ids.int, bit_offset: 32, bitfield_size: null },
    ],
  });
  expect(entry(ids.union)).toMatchObject({
    kind: "union",
    members: [{ name: "u", type: ids.int, bit_offset: 0 }],
  });
  expect(entry(ids.enumeration)).toMatchObject({
    kind: "enum",
    size: 4,
    enum_values: [
      { name: "off", value: "0" },
      { name: "on", value: "1" },
    ],
  });
  expect(entry(ids.fwd)).toMatchObject({
    kind: "fwd",
    name: "opaque",
    forward: { is_union: false },
  });
  expect(entry(ids.typedef)).toMatchObject({ kind: "typedef", type: ids.int });
  expect(entry(ids.volatileInt)).toMatchObject({
    kind: "volatile",
    type: ids.int,
  });
  expect(entry(ids.constInt)).toMatchObject({ kind: "const", type: ids.int });
  expect(entry(ids.restrictPointer)).toMatchObject({
    kind: "restrict",
    type: ids.pointer,
  });
  expect(entry(ids.proto)).toMatchObject({
    kind: "func_proto",
    type: ids.int,
    params: [
      { name: "x", type: ids.int, variadic: false },
      { name: "", type: 0, variadic: true },
    ],
  });
  expect(entry(ids.func)).toMatchObject({
    kind: "func",
    name: "do_work",
    type: ids.proto,
    func: { linkage: "global" },
  });
  expect(entry(ids.variable)).toMatchObject({
    kind: "var",
    type: ids.int,
    var: { linkage: "global_allocated" },
  });
  expect(entry(ids.dataSec)).toMatchObject({
    kind: "datasec",
    size: 4,
    datasec: [{ type: ids.variable, offset: 0, size: 4 }],
  });
  expect(entry(ids.float)).toMatchObject({ kind: "float", size: 4 });
  expect(entry(ids.declTag)).toMatchObject({
    kind: "decl_tag",
    type: ids.struct,
    decl_tag: { component_index: 0, applies_to_whole_type: false },
  });
  expect(entry(ids.typeTag)).toMatchObject({
    kind: "type_tag",
    type: ids.int,
  });
  expect(entry(ids.enum64)).toMatchObject({
    kind: "enum64",
    size: 8,
    enum_values: [
      { name: "neg", value: "-1" },
      { name: "big", value: "4294967296" },
    ],
  });
  expect(report.types.counts).toContainEqual({ kind: "struct", count: 4 });
  expect(report.types.counts).toContainEqual({ kind: "enum64", count: 1 });
});

it("keeps struct bitfield size and signed enum64 values", () => {
  const { bytes } = canonicalBtf();
  const report = parse(bytes, { type_offset: 20, type_limit: 3 });
  expect(report.types.entries).toMatchObject([
    { id: 20, name: "sample" },
    {
      id: 21,
      name: "flags",
      kind_flag: true,
      members: [{ name: "low", bit_offset: 0, bitfield_size: 3 }],
    },
    {
      id: 22,
      name: "flags_high",
      kind_flag: true,
      members: [{ name: "high", bit_offset: 7, bitfield_size: 1 }],
    },
  ]);
});

it("decodes big-endian headers and payloads", () => {
  const { bytes, ids } = canonicalBtf(false);
  const report = parse(bytes);
  expect(report.header.byte_order).toBe("big");
  expect(
    report.types.entries.find((entry) => entry.id === ids.int)?.int,
  ).toMatchObject({ bits: 32, encoding_names: ["signed"] });
  expect(
    report.types.entries.find((entry) => entry.id === ids.enumeration)
      ?.enum_values,
  ).toEqual([
    { name: "off", value: "0" },
    { name: "on", value: "1" },
  ]);
});

it("selects duplicate type names in id order and pages them", () => {
  const { bytes } = canonicalBtf();
  const report = parse(bytes, { type_name: "sample" });
  expect(report.types.selection).toBe("name");
  expect(report.types.entries.map((entry) => entry.id)).toEqual([4, 20]);

  const paged = parse(bytes, {
    type_name: "sample",
    type_offset: 2,
    type_limit: 1,
  });
  expect(paged.types.entries.map((entry) => entry.id)).toEqual([20]);
});

it("returns one selected id and an empty page past the end", () => {
  const { bytes } = canonicalBtf();
  const selected = parse(bytes, { type_id: 4 });
  expect(selected.types.selection).toBe("id");
  expect(selected.types.entries.map((entry) => entry.id)).toEqual([4]);
  const missing = parse(bytes, { type_id: 999 });
  expect(missing.types.entries).toEqual([]);
  const beyond = parse(bytes, { type_offset: 999 });
  expect(beyond.types.entries).toEqual([]);
});

it("stops at an unknown kind and reports the undecoded range", () => {
  const fixture = new BtfFixture();
  fixture.addRaw({ kind: 20, name: "future" });
  fixture.addInt("int");
  const report = parse(fixture.build());
  expect(report.coverage.status).toBe("partial");
  expect(report.coverage.unknown_kinds).toEqual([
    { type_id: 1, kind: 20, offset: 0 },
  ]);
  expect(report.types.total).toBe(0);
  expect(report.coverage.undecoded_bytes).toBeGreaterThan(0);
  expect(report.limitations.join(" ")).toContain("does not decode");
});

it("reports a truncated type payload without inventing a length", () => {
  const fixture = new BtfFixture();
  fixture.addRaw({
    kind: 4,
    name: "cut",
    vlen: 2,
    sizeOrType: 8,
    payload: Buffer.alloc(12),
  });
  const report = parse(fixture.build());
  expect(report.coverage.status).toBe("partial");
  expect(report.types.total).toBe(0);
  expect(report.coverage.undecoded_bytes).toBe(24);
  expect(report.limitations.join(" ")).toContain("do not form a complete");
});

it("keeps an out-of-range name as null with a limitation", () => {
  const fixture = new BtfFixture();
  fixture.addRaw({
    kind: 1,
    nameOffset: 5000,
    sizeOrType: 4,
    payload: Buffer.from([0x20, 0, 0, 0]),
  });
  const report = parse(fixture.build());
  expect(report.types.entries[0]?.name).toBeNull();
  expect(report.limitations.join(" ")).toContain("outside the string section");
});

it("keeps an unterminated trailing name as null", () => {
  const fixture = new BtfFixture();
  fixture.addInt("unterminated");
  const bytes = fixture.build();
  bytes[bytes.length - 1] = 0x41;
  const report = parse(bytes);
  expect(report.types.entries[0]?.name).toBeNull();
  expect(report.strings.first_empty).toBe(true);
  expect(report.limitations.join(" ")).toContain("ends without a NUL");
});

it("resolves one level of references and marks unknown ids", () => {
  const fixture = new BtfFixture();
  fixture.addInt("int");
  fixture.addPtr("missing_ptr", 99);
  const report = parse(fixture.build());
  expect(report.references).toEqual([
    { id: 99, state: "unresolved", name: null, kind: "unknown" },
  ]);
  expect(report.coverage.unresolved_references).toBe(1);
});

it("reads .BTF and .BTF.ext from an ELF carrier", () => {
  const { fixture, ids } = canonicalBtf();
  const bytes = fixture.build();
  const text = ".text";
  const source = "src/main.c";
  const functionText = "int work(void)";
  const access = "bpf_core_field_offset";
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
        records: [
          btfLineRecord(
            0,
            fixture.name(source),
            fixture.name(functionText),
            42,
            7,
          ),
        ],
      },
    ],
    core: [
      {
        sectionNameOffset: fixture.name(text),
        records: [btfCoreRecord(0, ids.struct, fixture.name(access), 0)],
      },
    ],
  });
  const report = parse(btfElfFixture(bytes, { ext }));
  expect(report.carrier).toBe("elf_section");
  expect(report.elf).toMatchObject({
    format: "elf64",
    machine: 247,
    type: 1,
    type_name: "relocatable",
    has_btf_base: false,
    has_btf_ids: false,
  });
  expect(report.section?.name).toBe(".BTF");
  expect(report.ext).toMatchObject({
    header: { version: 1, hdr_len: 32 },
    func_info: {
      record_bytes: 8,
      total_records: 1,
      sections: [{ name: ".text", records: 1 }],
    },
    line_info: {
      record_bytes: 16,
      total_records: 1,
      sections: [{ name: ".text", records: 1 }],
    },
    core_relo: { record_bytes: 16, total_records: 1 },
  });
  expect(report.ext?.selection).toBeNull();

  const selected = parse(btfElfFixture(bytes, { ext }), {
    ext_section: ".text",
  });
  expect(selected.ext?.selection).toMatchObject({
    section: ".text",
    func: [{ insn_off: 0, type_id: ids.func, function: "do_work" }],
    line: [
      {
        insn_off: 0,
        file: "src/main.c",
        source_line: "int work(void)",
        line: 42,
        column: 7,
      },
    ],
    core: [
      {
        insn_off: 0,
        type_id: ids.struct,
        access: "bpf_core_field_offset",
        kind: 0,
        kind_name: "field_byte_offset",
      },
    ],
  });
});

it("admits a .BTF.ext header without the optional CO-RE tail", () => {
  const { fixture, ids } = canonicalBtf();
  const ext = btfExtFixture({
    hdrLen: 24,
    func: [
      {
        sectionNameOffset: fixture.name(".text"),
        records: [btfFuncRecord(0, ids.func)],
      },
    ],
  });
  const report = parse(btfElfFixture(fixture.build(), { ext }));
  expect(report.ext?.header.core_relo).toBeNull();
  expect(report.ext?.core_relo).toBeNull();
  expect(report.ext?.func_info.total_records).toBe(1);
  expect(report.limitations.join(" ")).toContain(
    "no optional CO-RE subsection",
  );
});

it("pages ext records per section", () => {
  const { fixture, ids } = canonicalBtf();
  const ext = btfExtFixture({
    func: [
      {
        sectionNameOffset: fixture.name(".text"),
        records: [
          btfFuncRecord(0, ids.func),
          btfFuncRecord(8, ids.func),
          btfFuncRecord(16, ids.func),
        ],
      },
    ],
  });
  const report = parse(btfElfFixture(fixture.build(), { ext }), {
    ext_section: ".text",
    ext_offset: 1,
    ext_limit: 1,
  });
  expect(report.ext?.selection).toMatchObject({
    offset: 1,
    limit: 1,
    func: [{ insn_off: 8, type_id: ids.func }],
    func_total: 3,
  });
});

it("reports .BTF.base presence without relocating references", () => {
  const { bytes } = canonicalBtf();
  const report = parse(btfElfFixture(bytes, { hasBase: true, hasIds: true }));
  expect(report.elf).toMatchObject({ has_btf_base: true, has_btf_ids: true });
  expect(report.limitations.join(" ")).toContain("Split-BTF relocation");
});

it("refuses an unknown section and a compressed section", () => {
  const { bytes } = canonicalBtf();
  expect(() => parse(btfElfFixture(bytes), { section: ".NOPE" })).toThrow(
    /declares no \.NOPE section/,
  );
  const elf = btfElfFixture(bytes);
  const sectionHeader = Number(elf.readBigUInt64LE(40)) + 64;
  elf.writeBigUInt64LE(0x800n, sectionHeader + 8);
  expect(() => parse(elf)).toThrow(/Compressed \.BTF sections are unsupported/);
});
