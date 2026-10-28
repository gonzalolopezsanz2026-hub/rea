import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { BTF_CORE_RELOCATION_KINDS } from "../../domain/native/btf.js";
import type { Btf, InspectBtfInput } from "../../domain/native/btf.js";
import { BinaryFormatFailure } from "../metadata/BinaryContainer.js";
import type { BtfStrings } from "./BtfStrings.js";
import type { BtfTypeIndexEntry } from "./BtfTypeDecoder.js";

type BtfExt = NonNullable<Btf["ext"]>;
type ExtSelection = NonNullable<BtfExt["selection"]>;

const fail = (message: string): never => {
  throw new ArtifactReaderFailure("format", message);
};

const MIN_HEADER_BYTES = 24;
const CORE_HEADER_BYTES = 32;

interface Range {
  readonly offset: number;
  readonly bytes: number;
}

interface ExtHeader {
  readonly version: number;
  readonly flags: number;
  readonly hdrLen: number;
  readonly funcInfo: Range;
  readonly lineInfo: Range;
  readonly coreRelo: Range | null;
}

interface ExtSection {
  readonly nameOffset: number;
  readonly records: number;
  readonly dataStart: number;
}

interface ExtSubsection {
  readonly recordBytes: number;
  readonly sections: readonly ExtSection[];
  readonly total: number;
}

const readHeader = (bytes: Buffer): ExtHeader => {
  if (bytes.length < MIN_HEADER_BYTES)
    return fail("BTF.ext header is truncated.");
  const little = bytes[0] === 0x9f && bytes[1] === 0xeb;
  const big = bytes[0] === 0xeb && bytes[1] === 0x9f;
  if (!little && !big) return fail("BTF.ext magic is missing.");
  const u16 = (at: number) =>
    little ? bytes.readUInt16LE(at) : bytes.readUInt16BE(at);
  const u32 = (at: number) =>
    little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  if (u16(0) !== 0xeb9f)
    return fail("BTF.ext magic does not decode to 0xeb9f.");
  const version = bytes.readUInt8(2);
  if (version !== 1)
    throw new BinaryFormatFailure(
      "unsupported",
      `BTF.ext version ${String(version)} is unsupported; this reader admits version 1.`,
    );
  const flags = bytes.readUInt8(3);
  const hdrLen = u32(4);
  if (hdrLen < MIN_HEADER_BYTES)
    return fail("BTF.ext header length is below the 24-byte minimum.");
  if (hdrLen > bytes.length) return fail("BTF.ext header leaves the section.");
  const available = bytes.length - hdrLen;
  const read = (at: number, label: string): Range => {
    const offset = u32(at);
    const length = u32(at + 4);
    if (offset > available || length > available - offset)
      return fail(`BTF.ext ${label} subsection leaves the section.`);
    return Object.freeze({ offset, bytes: length });
  };
  const funcInfo = read(8, "func_info");
  const lineInfo = read(16, "line_info");
  const coreRelo =
    hdrLen >= CORE_HEADER_BYTES && bytes.length >= CORE_HEADER_BYTES
      ? read(24, "core_relo")
      : null;
  return { version, flags, hdrLen, funcInfo, lineInfo, coreRelo };
};

interface SubsectionRequest {
  readonly bytes: Buffer;
  readonly hdrLen: number;
  readonly range: Range;
  readonly minimumRecordBytes: number;
  readonly little: boolean;
  readonly label: string;
}

const walkSubsection = ({
  bytes,
  hdrLen,
  range,
  minimumRecordBytes,
  little,
  label,
}: SubsectionRequest): ExtSubsection => {
  if (range.bytes === 0) return { recordBytes: 0, sections: [], total: 0 };
  const u32 = (at: number) =>
    little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  const start = hdrLen + range.offset;
  const end = start + range.bytes;
  if (range.bytes < 4)
    return fail(`BTF.ext ${label} subsection has no record-size word.`);
  const recordBytes = u32(start);
  if (recordBytes < minimumRecordBytes)
    return fail(
      `BTF.ext ${label} record size ${String(recordBytes)} is below the documented ${String(minimumRecordBytes)} bytes.`,
    );
  const sections: ExtSection[] = [];
  let total = 0;
  let at = start + 4;
  while (at < end) {
    if (end - at < 8) {
      if (bytes.subarray(at, end).some((byte) => byte !== 0))
        return fail(`BTF.ext ${label} subsection has trailing non-zero bytes.`);
      break;
    }
    const nameOffset = u32(at);
    const records = u32(at + 4);
    const payload = BigInt(records) * BigInt(recordBytes);
    if (payload > BigInt(end - at - 8))
      return fail(`BTF.ext ${label} record list leaves its subsection.`);
    sections.push({ nameOffset, records, dataStart: at + 8 });
    total += records;
    at += 8 + Number(payload);
  }
  return { recordBytes, sections, total };
};

const coreKindName = (
  kind: number,
): (typeof BTF_CORE_RELOCATION_KINDS)[number] =>
  BTF_CORE_RELOCATION_KINDS[kind] ?? "unknown";

const summary = (
  subsection: ExtSubsection,
  strings: BtfStrings,
): BtfExt["func_info"] => ({
  record_bytes: subsection.recordBytes,
  total_records: subsection.total,
  sections: subsection.sections.map((section) => ({
    name: strings.resolve(section.nameOffset),
    records: section.records,
  })),
});

interface SelectionRequest {
  readonly bytes: Buffer;
  readonly func: ExtSubsection;
  readonly line: ExtSubsection;
  readonly core: ExtSubsection | null;
  readonly input: InspectBtfInput;
  readonly little: boolean;
  readonly strings: BtfStrings;
  readonly index: ReadonlyMap<number, BtfTypeIndexEntry>;
}

const selectRecords = ({
  bytes,
  func,
  line,
  core,
  input,
  little,
  strings,
  index,
}: SelectionRequest): ExtSelection | null => {
  const target = input.ext_section;
  if (target === undefined) return null;
  const u32 = (at: number) =>
    little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  const pick = (subsection: ExtSubsection): ExtSection | undefined =>
    subsection.sections.find(
      (section) => strings.resolve(section.nameOffset) === target,
    );
  const funcSection = pick(func);
  const lineSection = pick(line);
  const coreSection = core === null ? undefined : pick(core);
  if (
    funcSection === undefined &&
    lineSection === undefined &&
    coreSection === undefined
  )
    return fail(`The BTF.ext section table declares no records for ${target}.`);
  const page = (section: ExtSection | undefined, stride: number) => {
    if (section === undefined) return { start: 0, count: 0 };
    const start = Math.min(input.ext_offset, section.records);
    return {
      start: section.dataStart + start * stride,
      count: Math.min(input.ext_limit, section.records - start),
    };
  };
  const funcPage = page(funcSection, func.recordBytes);
  const linePage = page(lineSection, line.recordBytes);
  const corePage = page(coreSection, core?.recordBytes ?? 0);

  const funcRecords: ExtSelection["func"] = [];
  for (let i = 0; i < funcPage.count; i += 1) {
    const at = funcPage.start + i * func.recordBytes;
    const typeId = u32(at + 4);
    const referenced = index.get(typeId);
    funcRecords.push({
      insn_off: u32(at),
      type_id: typeId,
      function:
        referenced !== undefined && referenced.kind === 12
          ? strings.resolve(referenced.nameOffset)
          : null,
    });
  }

  const lineRecords: ExtSelection["line"] = [];
  for (let i = 0; i < linePage.count; i += 1) {
    const at = linePage.start + i * line.recordBytes;
    const lineColumn = u32(at + 12);
    lineRecords.push({
      insn_off: u32(at),
      file: strings.resolve(u32(at + 4)),
      source_line: strings.resolve(u32(at + 8)),
      line: lineColumn >>> 10,
      column: lineColumn & 0x3ff,
    });
  }

  const coreRecords: ExtSelection["core"] = [];
  if (core !== null) {
    for (let i = 0; i < corePage.count; i += 1) {
      const at = corePage.start + i * core.recordBytes;
      const kind = u32(at + 12);
      coreRecords.push({
        insn_off: u32(at),
        type_id: u32(at + 4),
        access: strings.resolve(u32(at + 8)),
        kind,
        kind_name: coreKindName(kind),
      });
    }
  }

  return {
    section: target,
    offset: input.ext_offset,
    limit: input.ext_limit,
    func: funcRecords,
    func_total: funcSection?.records ?? 0,
    line: lineRecords,
    line_total: lineSection?.records ?? 0,
    core: coreRecords,
    core_total: coreSection?.records ?? 0,
  };
};

/** Decode `.BTF.ext` func, line and optional CO-RE subsections. */
export const parseBtfExt = (
  bytes: Buffer,
  input: InspectBtfInput,
  strings: BtfStrings,
  index: ReadonlyMap<number, BtfTypeIndexEntry>,
): { readonly ext: BtfExt; readonly limitations: readonly string[] } => {
  const header = readHeader(bytes);
  const little = bytes[0] === 0x9f && bytes[1] === 0xeb;
  const funcInfo = walkSubsection({
    bytes,
    hdrLen: header.hdrLen,
    range: header.funcInfo,
    minimumRecordBytes: 8,
    little,
    label: "func_info",
  });
  const lineInfo = walkSubsection({
    bytes,
    hdrLen: header.hdrLen,
    range: header.lineInfo,
    minimumRecordBytes: 16,
    little,
    label: "line_info",
  });
  const coreRelo =
    header.coreRelo === null
      ? null
      : walkSubsection({
          bytes,
          hdrLen: header.hdrLen,
          range: header.coreRelo,
          minimumRecordBytes: 16,
          little,
          label: "core_relo",
        });

  const limitations: string[] = [];
  if (
    [funcInfo, lineInfo, coreRelo].some(
      (subsection) =>
        subsection !== null &&
        subsection.sections.some((section) => section.records === 0),
    )
  )
    limitations.push(
      "A BTF.ext section table entry declares zero records; it is retained as observed, not omitted.",
    );
  if (
    funcInfo.recordBytes > 8 ||
    lineInfo.recordBytes > 16 ||
    (coreRelo !== null && coreRelo.recordBytes > 16)
  )
    limitations.push(
      "A BTF.ext record is wider than the documented structure; only the known prefix is reported.",
    );
  limitations.push(
    "CO-RE relocation records are reported, not applied; no program was loaded or relocated.",
  );
  if (header.coreRelo === null)
    limitations.push(
      "The BTF.ext header declares no optional CO-RE subsection; that is observed absence, not proof no relocation was ever generated.",
    );

  return {
    ext: {
      header: {
        version: header.version,
        flags: header.flags,
        hdr_len: header.hdrLen,
        func_info: header.funcInfo,
        line_info: header.lineInfo,
        core_relo: header.coreRelo,
      },
      func_info: summary(funcInfo, strings),
      line_info: summary(lineInfo, strings),
      core_relo: coreRelo === null ? null : summary(coreRelo, strings),
      selection: selectRecords({
        bytes,
        func: funcInfo,
        line: lineInfo,
        core: coreRelo,
        input,
        little,
        strings,
        index,
      }),
    },
    limitations,
  };
};
