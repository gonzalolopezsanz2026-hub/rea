import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  btfKindName,
  type Btf,
  type InspectBtfInput,
} from "../../domain/native/btf.js";
import { BinaryFormatFailure } from "../metadata/BinaryContainer.js";
import type { BtfCarrier } from "./BtfCarrier.js";
import { parseBtfExt } from "./BtfExtParser.js";
import { BtfStrings } from "./BtfStrings.js";
import { decodeBtfTypes, indexBtfTypes } from "./BtfTypeDecoder.js";

const fail = (message: string): never => {
  throw new ArtifactReaderFailure("format", message);
};

const HEADER_BYTES = 24;

interface BtfHeader {
  readonly byteOrder: "little" | "big";
  readonly version: number;
  readonly flags: number;
  readonly hdrLen: number;
  readonly typeStart: number;
  readonly typeLen: number;
  readonly strStart: number;
  readonly strLen: number;
}

const readHeader = (bytes: Buffer): BtfHeader => {
  if (bytes.length < HEADER_BYTES) return fail("BTF header is truncated.");
  const little = bytes[0] === 0x9f && bytes[1] === 0xeb;
  const big = bytes[0] === 0xeb && bytes[1] === 0x9f;
  if (!little && !big) return fail("BTF magic is missing.");
  const u16 = (at: number) =>
    little ? bytes.readUInt16LE(at) : bytes.readUInt16BE(at);
  const u32 = (at: number) =>
    little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  if (u16(0) !== 0xeb9f) return fail("BTF magic does not decode to 0xeb9f.");
  const version = bytes.readUInt8(2);
  if (version !== 1)
    throw new BinaryFormatFailure(
      "unsupported",
      `BTF version ${String(version)} is unsupported; this reader admits version 1.`,
    );
  const flags = bytes.readUInt8(3);
  const hdrLen = u32(4);
  if (hdrLen < HEADER_BYTES)
    return fail("BTF header length is below the 24-byte minimum.");
  if (hdrLen > bytes.length) return fail("BTF header leaves the blob.");
  const typeOff = u32(8);
  const typeLen = u32(12);
  const strOff = u32(16);
  const strLen = u32(20);
  const available = bytes.length - hdrLen;
  if (typeOff > available || typeLen > available - typeOff)
    return fail("BTF type section leaves the blob.");
  if (strOff > available || strLen > available - strOff)
    return fail("BTF string section leaves the blob.");
  const typeStart = hdrLen + typeOff;
  const strStart = hdrLen + strOff;
  if (
    typeLen !== 0 &&
    strLen !== 0 &&
    typeStart < strStart + strLen &&
    strStart < typeStart + typeLen
  )
    return fail("BTF type and string sections overlap.");
  if (strLen === 0)
    return fail(
      "BTF string section is empty; the leading empty string is required.",
    );
  return {
    byteOrder: little ? "little" : "big",
    version,
    flags,
    hdrLen,
    typeStart,
    typeLen,
    strStart,
    strLen,
  };
};

/** Decode one selected BTF carrier into the portable result contract. */
export const parseBtf = (
  carrier: BtfCarrier,
  artifact: Btf["artifact"],
  input: InspectBtfInput,
): Btf => {
  const bytes = carrier.core;
  const header = readHeader(bytes);
  const limitations = new Set<string>(carrier.limitations);
  const strings = new BtfStrings(
    bytes,
    header.strStart,
    header.strLen,
    limitations,
  );

  let stringCount = 0;
  for (let i = 0; i < header.strLen; i += 1)
    if (bytes[header.strStart + i] === 0) stringCount += 1;
  const firstEmpty = bytes[header.strStart] === 0;
  if (!firstEmpty)
    limitations.add(
      "The BTF string section does not begin with the required empty string.",
    );
  if (bytes[header.strStart + header.strLen - 1] !== 0)
    limitations.add(
      "The BTF string section ends without a NUL terminator; the trailing partial string is not addressable.",
    );

  const index = indexBtfTypes(
    bytes,
    header.typeStart,
    header.typeLen,
    header.byteOrder === "little",
  );
  const types = decodeBtfTypes(bytes, index, strings, input);
  const byId = new Map(index.entries.map((entry) => [entry.id, entry]));

  const extBytes = input.include_ext ? carrier.ext : null;
  let ext: Btf["ext"] = null;
  if (extBytes !== null) {
    const parsed = parseBtfExt(extBytes, input, strings, byId);
    ext = parsed.ext;
    for (const limitation of parsed.limitations) limitations.add(limitation);
  } else if (input.include_ext) {
    if (carrier.carrier === "elf_section")
      limitations.add(
        "No readable .BTF.ext section was available; func, line and CO-RE records were not read for this artifact.",
      );
  } else {
    limitations.add(
      "The caller disabled .BTF.ext reading; func, line and CO-RE records were not examined.",
    );
  }

  const status =
    index.unknownKinds.length > 0 || index.decodedBytes !== header.typeLen
      ? "partial"
      : "complete";
  if (index.unknownKinds.length > 0) {
    const unknown = index.unknownKinds[0];
    if (unknown !== undefined)
      limitations.add(
        `Type ${String(unknown.type_id)} declares kind ${String(unknown.kind)}, which this reader does not decode; the remaining ${String(header.typeLen - index.decodedBytes)} type bytes stay undecoded.`,
      );
  } else if (index.decodedBytes !== header.typeLen) {
    limitations.add(
      `The type section ends with ${String(header.typeLen - index.decodedBytes)} bytes that do not form a complete type entry.`,
    );
  }

  const counts = [...index.counts.entries()]
    .sort(([left], [right]) => left - right)
    .map(([kind, count]) => ({ kind: btfKindName(kind), count }));
  const unresolved = types.references.filter(
    (reference) => reference.state === "unresolved",
  ).length;

  return {
    artifact,
    carrier: carrier.carrier,
    elf: carrier.elf,
    section:
      carrier.section === null
        ? null
        : {
            name: carrier.section.name,
            location: {
              offset: carrier.section.offset,
              bytes: carrier.section.bytes,
            },
          },
    header: {
      magic: "0xeb9f",
      byte_order: header.byteOrder,
      version: header.version,
      flags: header.flags,
      hdr_len: header.hdrLen,
      type: { offset: header.typeStart, bytes: header.typeLen },
      string: { offset: header.strStart, bytes: header.strLen },
    },
    strings: {
      bytes: header.strLen,
      count: stringCount,
      first_empty: firstEmpty,
    },
    types: {
      total: index.entries.length,
      counts,
      selection: types.selection,
      page: {
        offset: types.pageOffset,
        limit: types.pageLimit,
        returned: types.entries.length,
      },
      entries: [...types.entries],
    },
    references: [...types.references],
    ext,
    coverage: {
      status,
      decoded_type_bytes: index.decodedBytes,
      undecoded_bytes: header.typeLen - index.decodedBytes,
      unknown_kinds: index.unknownKinds,
      unresolved_references: unresolved,
      references_truncated: types.referencesTruncated,
      names_truncated: strings.truncated,
      facets_truncated: types.facetsTruncated,
    },
    limitations: [...limitations],
  };
};
