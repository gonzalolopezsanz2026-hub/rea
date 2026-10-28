import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readElfFixedHeader } from "../../domain/elfFixedHeader.js";
import { readElfRawTableDeclarations } from "../../domain/elfRawTableDeclarations.js";
import { readElfSectionHeader } from "../../domain/elfSectionHeader.js";
import { validateElfSectionTablePresence } from "../../domain/elfDeclaredRanges.js";
import { elfObjectTypeName } from "../../domain/native/elfNotes.js";
import type { Btf } from "../../domain/native/btf.js";
import { BinaryFormatFailure } from "../metadata/BinaryContainer.js";
import { decodeElfSectionNameTable } from "../metadata/ElfSectionNameTable.js";

const SHT_STRTAB = 3;
const SHT_NOBITS = 8;
const SHF_COMPRESSED = 0x800n;
const MAX_EXTENDED_COUNT = 0xffff;

/** One selected section with its exact byte range in the inspected artifact. */
export interface BtfSectionSelection {
  readonly name: string;
  readonly offset: number;
  readonly bytes: number;
}

/** Carrier facts the core factory decodes by magic, and the optional section by ELF name. */
export interface BtfCarrier {
  readonly carrier: "standalone" | "elf_section";
  readonly core: Buffer;
  readonly section: BtfSectionSelection | null;
  readonly ext: Buffer | null;
  readonly elf: Btf["elf"];
  readonly limitations: readonly string[];
}

const fail = (message: string): never => {
  throw new ArtifactReaderFailure("format", message);
};

const isBtfMagic = (bytes: Buffer): boolean =>
  bytes.length >= 2 &&
  ((bytes[0] === 0x9f && bytes[1] === 0xeb) ||
    (bytes[0] === 0xeb && bytes[1] === 0x9f));

const rangeOf = (
  offset: bigint,
  size: bigint,
  fileBytes: number,
  label: string,
): BtfSectionSelection => {
  if (
    offset > BigInt(Number.MAX_SAFE_INTEGER) ||
    size > BigInt(Number.MAX_SAFE_INTEGER)
  )
    return fail(`ELF ${label} range exceeds a safe integer.`);
  const start = Number(offset);
  const length = Number(size);
  if (length !== 0 && (start > fileBytes || length > fileBytes - start))
    return fail(`ELF ${label} range leaves the selected artifact.`);
  return { name: label, offset: start, bytes: length };
};

interface ElfSectionRecord {
  readonly index: number;
  readonly name: string | null;
  readonly type: number;
  readonly flags: bigint;
  readonly selection: BtfSectionSelection;
}

const readElfSections = (
  bytes: Buffer,
  maxDecodedNames: number,
): {
  readonly sections: readonly ElfSectionRecord[];
  readonly format: "elf32" | "elf64";
  readonly machine: number;
  readonly type: number;
  readonly limitations: readonly string[];
} => {
  const fixed = readElfFixedHeader(bytes);
  if (!fixed.ok)
    return fail(
      `Selected artifact is neither BTF nor an ELF image: ${fixed.error}`,
    );
  const header = fixed.value;
  const raw = readElfRawTableDeclarations(bytes, header);
  if (!raw.ok) return fail(raw.error.message);
  const presence = validateElfSectionTablePresence(raw.value);
  if (!presence.ok) return fail(presence.error);
  const { sections } = raw.value;
  if (
    sections.offset > BigInt(Number.MAX_SAFE_INTEGER) ||
    sections.count === MAX_EXTENDED_COUNT ||
    sections.namesIndex === MAX_EXTENDED_COUNT ||
    (sections.offset !== 0n && sections.count === 0)
  )
    throw new BinaryFormatFailure(
      "unsupported",
      "ELF extended section numbering is unsupported.",
    );
  const wide = header.elfClass === 64;
  const little = header.byteOrder === "little";
  const count = sections.count;
  const width = sections.width;
  if (count !== 0 && width < (wide ? 64 : 40))
    return fail("ELF section header width is invalid.");
  const shoff = Number(sections.offset);
  const namesIndex = sections.namesIndex;
  const byteLength = bytes.length;

  const limitations: string[] = [];
  let names: Buffer | null = null;
  if (count !== 0 && namesIndex !== 0) {
    if (namesIndex >= count)
      return fail("ELF section name index is out of range.");
    if (shoff > byteLength || count * width > byteLength - shoff)
      return fail("ELF section header table leaves the selected artifact.");
    const at = shoff + namesIndex * width;
    const parsed = readElfSectionHeader(
      bytes.subarray(at, at + width),
      header.elfClass,
      little,
    );
    if (!parsed.ok) return fail(parsed.error.message);
    const namesSection = parsed.value;
    if (namesSection.type !== SHT_STRTAB)
      return fail("ELF section name table is not a string table.");
    const selection = rangeOf(
      namesSection.offset,
      namesSection.size,
      byteLength,
      "section name table",
    );
    const decoded = decodeElfSectionNameTable(
      bytes.subarray(selection.offset, selection.offset + selection.bytes),
      namesSection.flags,
      header.elfClass,
      little,
      maxDecodedNames,
    );
    if (decoded.state === "malformed") return fail(decoded.message);
    if (decoded.state === "limit")
      throw new ArtifactReaderFailure(
        "limit",
        `ELF section names require ${String(decoded.requiredBytes)} decoded bytes, above the ${String(decoded.maximumBytes)}-byte budget.`,
        { boundary: "memory" },
      );
    if (decoded.state === "unsupported")
      return fail(
        `ELF section names use unsupported compression type ${String(decoded.compressionType)}; pass a standalone BTF blob or an ELF whose section-name table is readable.`,
      );
    names = decoded.bytes;
  } else if (count !== 0) {
    return fail(
      "ELF section names are unavailable because no section-name string table is declared; pass a standalone BTF blob or an ELF whose section-name table is readable.",
    );
  }

  const readName = (offset: number): string | null => {
    if (names === null || offset >= names.length) return null;
    const end = names.indexOf(0, offset);
    if (end < 0) return null;
    return names.subarray(offset, end).toString("latin1");
  };

  const records: ElfSectionRecord[] = [];
  if (shoff + count * width > byteLength)
    return fail("ELF section header table leaves the selected artifact.");
  for (let index = 0; index < count; index += 1) {
    const at = shoff + index * width;
    const parsed = readElfSectionHeader(
      bytes.subarray(at, at + width),
      header.elfClass,
      little,
    );
    if (!parsed.ok) return fail(parsed.error.message);
    const section = parsed.value;
    const name = readName(section.nameOffset);
    const selection =
      section.type === SHT_NOBITS
        ? { offset: 0, bytes: 0 }
        : rangeOf(
            section.offset,
            section.size,
            byteLength,
            name ?? `section ${String(index)}`,
          );
    records.push({
      index,
      name,
      type: section.type,
      flags: section.flags,
      selection: { ...selection, name: name ?? `section ${String(index)}` },
    });
  }
  return {
    sections: records,
    format: wide ? "elf64" : "elf32",
    machine: header.machine,
    type: header.type,
    limitations,
  };
};

/** Select the caller's BTF carrier without repairing or guessing the format. */
export const selectBtfCarrier = (
  bytes: Buffer,
  sectionName: string,
  maxDecodedNames: number,
): BtfCarrier => {
  if (isBtfMagic(bytes)) {
    if (bytes.length < 24) return fail("Standalone BTF header is truncated.");
    return {
      carrier: "standalone",
      core: bytes,
      section: null,
      ext: null,
      elf: null,
      limitations: [
        "A standalone BTF blob carries no ELF .BTF.ext section; pass the ELF image to read func, line and CO-RE records.",
      ],
    };
  }
  const elf = readElfSections(bytes, maxDecodedNames);
  const byName = (name: string) =>
    elf.sections.find((section) => section.name === name);
  const core = byName(sectionName);
  if (core === undefined)
    return fail(
      `The selected ELF image declares no ${sectionName} section; no BTF facts were read.`,
    );
  if (core.selection.bytes === 0)
    return fail(`The selected ${sectionName} section is empty.`);
  if ((core.flags & SHF_COMPRESSED) !== 0n)
    throw new BinaryFormatFailure(
      "unsupported",
      `Compressed ${sectionName} sections are unsupported; decompress the section first.`,
    );
  const extSection = byName(".BTF.ext");
  const limitations = [...elf.limitations];
  let ext: Buffer | null = null;
  if (extSection !== undefined) {
    if ((extSection.flags & SHF_COMPRESSED) !== 0n)
      limitations.push(
        "The .BTF.ext section is compressed and was not read; decompress it first.",
      );
    else if (extSection.selection.bytes !== 0)
      ext = bytes.subarray(
        extSection.selection.offset,
        extSection.selection.offset + extSection.selection.bytes,
      );
    else
      limitations.push(
        "The .BTF.ext section is empty; func, line and CO-RE records were not read.",
      );
  }
  const hasBtfBase = byName(".BTF.base") !== undefined;
  if (hasBtfBase)
    limitations.push(
      "This ELF declares .BTF.base. Split-BTF relocation is not performed and base type references remain unresolved; ids reported here are file-local to the split .BTF section.",
    );
  return {
    carrier: "elf_section",
    core: bytes.subarray(
      core.selection.offset,
      core.selection.offset + core.selection.bytes,
    ),
    section: {
      name: sectionName,
      offset: core.selection.offset,
      bytes: core.selection.bytes,
    },
    ext,
    elf: {
      format: elf.format,
      machine: elf.machine,
      type: elf.type,
      type_name: elfObjectTypeName(elf.type),
      has_btf_base: hasBtfBase,
      has_btf_ids: byName(".BTF_ids") !== undefined,
    },
    limitations,
  };
};
