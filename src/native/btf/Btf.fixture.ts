const BTF_MAGIC = 0xeb9f;

const write16 = (
  bytes: Buffer,
  offset: number,
  value: number,
  little: boolean,
): void => {
  if (little) bytes.writeUInt16LE(value, offset);
  else bytes.writeUInt16BE(value, offset);
};

const write32 = (
  bytes: Buffer,
  offset: number,
  value: number,
  little: boolean,
): void => {
  if (little) bytes.writeUInt32LE(value, offset);
  else bytes.writeUInt32BE(value, offset);
};

export interface BtfMemberInput {
  readonly name?: string;
  readonly nameOffset?: number;
  readonly type: number;
  readonly bitOffset: number;
}

export interface BtfParamInput {
  readonly name?: string;
  readonly nameOffset?: number;
  readonly type: number;
}

export interface BtfEnumValueInput {
  readonly name?: string;
  readonly nameOffset?: number;
  readonly value: number;
}

export interface BtfEnum64ValueInput {
  readonly name?: string;
  readonly nameOffset?: number;
  readonly value: bigint;
}

export interface BtfDataSecVariableInput {
  readonly type: number;
  readonly offset: number;
  readonly size: number;
}

export interface BtfRawTypeInput {
  readonly name?: string;
  readonly nameOffset?: number;
  readonly kind: number;
  readonly kindFlag?: boolean;
  readonly vlen?: number;
  readonly sizeOrType?: number;
  readonly payload?: Buffer;
}

/** Deterministic BTF encoder for tests and malformed-input regressions. */
export class BtfFixture {
  readonly little: boolean;
  readonly #typeParts: Buffer[] = [];
  readonly #stringParts: Buffer[] = [Buffer.from([0])];
  readonly #stringOffsets = new Map<string, number>([["", 0]]);
  #stringLength = 1;
  #typeId = 0;

  constructor(little = true) {
    this.little = little;
  }

  name(text: string): number {
    const existing = this.#stringOffsets.get(text);
    if (existing !== undefined) return existing;
    const bytes = Buffer.from(`${text}\0`, "latin1");
    const offset = this.#stringLength;
    this.#stringParts.push(bytes);
    this.#stringLength += bytes.length;
    this.#stringOffsets.set(text, offset);
    return offset;
  }

  get stringBytes(): Buffer {
    return Buffer.concat(this.#stringParts);
  }

  addInt(
    name: string,
    options: {
      readonly size?: number;
      readonly bits?: number;
      readonly encoding?: number;
      readonly offsetBits?: number;
    } = {},
  ): number {
    const payload = Buffer.alloc(4);
    const encoding =
      ((options.encoding ?? 0) << 24) |
      ((options.offsetBits ?? 0) << 16) |
      (options.bits ?? 32);
    write32(payload, 0, encoding, this.little);
    return this.addRaw({
      name,
      kind: 1,
      sizeOrType: options.size ?? 4,
      payload,
    });
  }

  addPtr(name: string, type: number): number {
    return this.addRaw({ name, kind: 2, sizeOrType: type });
  }

  addArray(
    name: string,
    elementType: number,
    indexType: number,
    elements: number,
  ): number {
    const payload = Buffer.alloc(12);
    write32(payload, 0, elementType, this.little);
    write32(payload, 4, indexType, this.little);
    write32(payload, 8, elements, this.little);
    return this.addRaw({ name, kind: 3, payload });
  }

  addStruct(
    name: string,
    size: number,
    members: readonly BtfMemberInput[],
    options: { readonly isUnion?: boolean; readonly kindFlag?: boolean } = {},
  ): number {
    const payload = Buffer.alloc(members.length * 12);
    members.forEach((member, index) => {
      const at = index * 12;
      write32(
        payload,
        at,
        member.nameOffset ?? this.name(member.name ?? ""),
        this.little,
      );
      write32(payload, at + 4, member.type, this.little);
      write32(payload, at + 8, member.bitOffset, this.little);
    });
    return this.addRaw({
      name,
      kind: options.isUnion === true ? 5 : 4,
      kindFlag: options.kindFlag ?? false,
      vlen: members.length,
      sizeOrType: size,
      payload,
    });
  }

  addEnum(
    name: string,
    size: number,
    values: readonly BtfEnumValueInput[],
    signed = false,
  ): number {
    const payload = Buffer.alloc(values.length * 8);
    values.forEach((value, index) => {
      const at = index * 8;
      write32(
        payload,
        at,
        value.nameOffset ?? this.name(value.name ?? ""),
        this.little,
      );
      write32(payload, at + 4, value.value >>> 0, this.little);
    });
    return this.addRaw({
      name,
      kind: 6,
      kindFlag: signed,
      vlen: values.length,
      sizeOrType: size,
      payload,
    });
  }

  addFwd(name: string, isUnion = false): number {
    return this.addRaw({ name, kind: 7, kindFlag: isUnion });
  }

  addTypedef(name: string, type: number): number {
    return this.addRaw({ name, kind: 8, sizeOrType: type });
  }

  addQualified(kind: 9 | 10 | 11 | 18, name: string, type: number): number {
    return this.addRaw({ name, kind, sizeOrType: type });
  }

  addFunc(name: string, protoType: number, linkage = 0): number {
    return this.addRaw({
      name,
      kind: 12,
      vlen: linkage,
      sizeOrType: protoType,
    });
  }

  addFuncProto(
    name: string,
    returnType: number,
    params: readonly BtfParamInput[],
  ): number {
    const payload = Buffer.alloc(params.length * 8);
    params.forEach((param, index) => {
      const at = index * 8;
      write32(
        payload,
        at,
        param.nameOffset ?? this.name(param.name ?? ""),
        this.little,
      );
      write32(payload, at + 4, param.type, this.little);
    });
    return this.addRaw({
      name,
      kind: 13,
      vlen: params.length,
      sizeOrType: returnType,
      payload,
    });
  }

  addVar(name: string, type: number, linkage = 0): number {
    const payload = Buffer.alloc(4);
    write32(payload, 0, linkage, this.little);
    return this.addRaw({ name, kind: 14, sizeOrType: type, payload });
  }

  addDataSec(
    name: string,
    size: number,
    variables: readonly BtfDataSecVariableInput[],
  ): number {
    const payload = Buffer.alloc(variables.length * 12);
    variables.forEach((variable, index) => {
      const at = index * 12;
      write32(payload, at, variable.type, this.little);
      write32(payload, at + 4, variable.offset, this.little);
      write32(payload, at + 8, variable.size, this.little);
    });
    return this.addRaw({
      name,
      kind: 15,
      vlen: variables.length,
      sizeOrType: size,
      payload,
    });
  }

  addFloat(name: string, size: number): number {
    return this.addRaw({ name, kind: 16, sizeOrType: size });
  }

  addDeclTag(name: string, type: number, componentIndex = -1): number {
    const payload = Buffer.alloc(4);
    write32(payload, 0, componentIndex >>> 0, this.little);
    return this.addRaw({ name, kind: 17, sizeOrType: type, payload });
  }

  addEnum64(
    name: string,
    size: number,
    values: readonly BtfEnum64ValueInput[],
    signed = false,
  ): number {
    const payload = Buffer.alloc(values.length * 12);
    values.forEach((value, index) => {
      const at = index * 12;
      write32(
        payload,
        at,
        value.nameOffset ?? this.name(value.name ?? ""),
        this.little,
      );
      const raw = BigInt.asUintN(64, value.value);
      write32(payload, at + 4, Number(raw & 0xffffffffn), this.little);
      write32(payload, at + 8, Number(raw >> 32n), this.little);
    });
    return this.addRaw({
      name,
      kind: 19,
      kindFlag: signed,
      vlen: values.length,
      sizeOrType: size,
      payload,
    });
  }

  addRaw(input: BtfRawTypeInput): number {
    const header = Buffer.alloc(12);
    write32(
      header,
      0,
      input.nameOffset ?? this.name(input.name ?? ""),
      this.little,
    );
    const info =
      ((input.vlen ?? 0) & 0xffff) |
      ((input.kind & 0x1f) << 24) |
      (input.kindFlag === true ? 0x80000000 : 0);
    write32(header, 4, info >>> 0, this.little);
    write32(header, 8, (input.sizeOrType ?? 0) >>> 0, this.little);
    this.#typeParts.push(header, input.payload ?? Buffer.alloc(0));
    this.#typeId += 1;
    return this.#typeId;
  }

  get typeCount(): number {
    return this.#typeId;
  }

  build(): Buffer {
    const types = Buffer.concat(this.#typeParts);
    const strings = this.stringBytes;
    const header = Buffer.alloc(24);
    write16(header, 0, BTF_MAGIC, this.little);
    header[2] = 1;
    header[3] = 0;
    write32(header, 4, 24, this.little);
    write32(header, 8, 0, this.little);
    write32(header, 12, types.length, this.little);
    write32(header, 16, types.length, this.little);
    write32(header, 20, strings.length, this.little);
    return Buffer.concat([header, types, strings]);
  }
}

export interface CanonicalBtfIds {
  readonly int: number;
  readonly pointer: number;
  readonly array: number;
  readonly struct: number;
  readonly union: number;
  readonly enumeration: number;
  readonly fwd: number;
  readonly typedef: number;
  readonly volatileInt: number;
  readonly constInt: number;
  readonly restrictPointer: number;
  readonly proto: number;
  readonly func: number;
  readonly variable: number;
  readonly dataSec: number;
  readonly float: number;
  readonly declTag: number;
  readonly typeTag: number;
  readonly enum64: number;
}

export interface CanonicalBtf {
  readonly fixture: BtfFixture;
  readonly bytes: Buffer;
  readonly ids: CanonicalBtfIds;
}

/** One image exercising every released kind, duplicate names and bitfields. */
export const canonicalBtf = (little = true): CanonicalBtf => {
  const fixture = new BtfFixture(little);
  const int = fixture.addInt("int", { encoding: 1, bits: 32, size: 4 });
  const pointer = fixture.addPtr("int_ptr", int);
  const array = fixture.addArray("int_array", int, int, 8);
  const struct = fixture.addStruct("sample", 16, [
    { name: "a", type: int, bitOffset: 0 },
    { name: "b", type: int, bitOffset: 32 },
  ]);
  const union = fixture.addStruct(
    "choice",
    4,
    [{ name: "u", type: int, bitOffset: 0 }],
    { isUnion: true },
  );
  const enumeration = fixture.addEnum("mode", 4, [
    { name: "off", value: 0 },
    { name: "on", value: 1 },
  ]);
  const fwd = fixture.addFwd("opaque");
  const typedef = fixture.addTypedef("int_alias", int);
  const volatileInt = fixture.addQualified(9, "volatile_int", int);
  const constInt = fixture.addQualified(10, "const_int", int);
  const restrictPointer = fixture.addQualified(11, "restrict_ptr", pointer);
  const proto = fixture.addFuncProto("work_proto", int, [
    { name: "x", type: int },
    { type: 0 },
  ]);
  const func = fixture.addFunc("do_work", proto, 1);
  const variable = fixture.addVar("counter", int, 1);
  const dataSec = fixture.addDataSec(".data", 4, [
    { type: variable, offset: 0, size: 4 },
  ]);
  const float = fixture.addFloat("ratio", 4);
  const declTag = fixture.addDeclTag("tag", struct, 0);
  const typeTag = fixture.addQualified(18, "tagged", int);
  const enum64 = fixture.addEnum64(
    "wide_mode",
    8,
    [
      { name: "neg", value: -1n },
      { name: "big", value: 0x100000000n },
    ],
    true,
  );
  fixture.addStruct("sample", 8, [{ name: "c", type: int, bitOffset: 0 }]);
  fixture.addStruct(
    "flags",
    4,
    [{ name: "low", type: int, bitOffset: 3 << 24 }],
    { kindFlag: true },
  );
  fixture.addStruct(
    "flags_high",
    4,
    [{ name: "high", type: int, bitOffset: (1 << 24) | 7 }],
    { kindFlag: true },
  );
  fixture.name(".text");
  fixture.name("src/main.c");
  fixture.name("int work(void)");
  fixture.name("bpf_core_field_offset");
  return {
    fixture,
    bytes: fixture.build(),
    ids: {
      int,
      pointer,
      array,
      struct,
      union,
      enumeration,
      fwd,
      typedef,
      volatileInt,
      constInt,
      restrictPointer,
      proto,
      func,
      variable,
      dataSec,
      float,
      declTag,
      typeTag,
      enum64,
    },
  };
};

export interface BtfExtGroup {
  readonly sectionNameOffset: number;
  readonly records: readonly Buffer[];
}

export interface BtfExtOptions {
  readonly little?: boolean;
  readonly hdrLen?: 24 | 32;
  readonly func?: readonly BtfExtGroup[];
  readonly line?: readonly BtfExtGroup[];
  readonly core?: readonly BtfExtGroup[];
}

const extSubsection = (
  recordBytes: number,
  groups: readonly BtfExtGroup[],
  little: boolean,
): Buffer => {
  const size = Buffer.alloc(4);
  write32(size, 0, recordBytes, little);
  const parts: Buffer[] = [size];
  for (const group of groups) {
    const identity = Buffer.alloc(8);
    write32(identity, 0, group.sectionNameOffset, little);
    write32(identity, 4, group.records.length, little);
    parts.push(identity, ...group.records);
  }
  return Buffer.concat(parts);
};

/** Encode a `.BTF.ext` section with an optional CO-RE tail. */
export const btfExtFixture = (options: BtfExtOptions = {}): Buffer => {
  const little = options.little ?? true;
  const hdrLen = options.hdrLen ?? 32;
  if (hdrLen === 24 && (options.core?.length ?? 0) > 0)
    throw new Error("A 24-byte BTF.ext header cannot declare CO-RE records.");
  const func =
    options.func === undefined
      ? Buffer.alloc(0)
      : extSubsection(8, options.func, little);
  const line =
    options.line === undefined
      ? Buffer.alloc(0)
      : extSubsection(16, options.line, little);
  const core =
    options.core === undefined
      ? Buffer.alloc(0)
      : extSubsection(16, options.core, little);
  const body = Buffer.concat([func, line, core]);
  const header = Buffer.alloc(hdrLen);
  write16(header, 0, BTF_MAGIC, little);
  header[2] = 1;
  header[3] = 0;
  write32(header, 4, hdrLen, little);
  write32(header, 8, 0, little);
  write32(header, 12, func.length, little);
  write32(header, 16, func.length, little);
  write32(header, 20, line.length, little);
  if (hdrLen >= 32) {
    write32(header, 24, func.length + line.length, little);
    write32(header, 28, core.length, little);
  }
  return Buffer.concat([header, body]);
};

export const btfFuncRecord = (
  insnOff: number,
  typeId: number,
  little = true,
): Buffer => {
  const bytes = Buffer.alloc(8);
  write32(bytes, 0, insnOff, little);
  write32(bytes, 4, typeId, little);
  return bytes;
};

export const btfLineRecord = (
  insnOff: number,
  fileNameOffset: number,
  sourceLineOffset: number,
  line: number,
  column: number,
  little = true,
): Buffer => {
  const bytes = Buffer.alloc(16);
  write32(bytes, 0, insnOff, little);
  write32(bytes, 4, fileNameOffset, little);
  write32(bytes, 8, sourceLineOffset, little);
  write32(bytes, 12, ((line << 10) | column) >>> 0, little);
  return bytes;
};

export const btfCoreRecord = (
  insnOff: number,
  typeId: number,
  accessOffset: number,
  kind: number,
  little = true,
): Buffer => {
  const bytes = Buffer.alloc(16);
  write32(bytes, 0, insnOff, little);
  write32(bytes, 4, typeId, little);
  write32(bytes, 8, accessOffset, little);
  write32(bytes, 12, kind, little);
  return bytes;
};

export interface BtfElfOptions {
  readonly ext?: Buffer;
  readonly hasBase?: boolean;
  readonly hasIds?: boolean;
  readonly sectionName?: string;
}

/** Minimal little-endian ELF64 relocatable object carrying `.BTF`. */
export const btfElfFixture = (
  btf: Buffer,
  options: BtfElfOptions = {},
): Buffer => {
  const sectionName = options.sectionName ?? ".BTF";
  const extra: { readonly name: string; readonly bytes: Buffer }[] = [];
  if (options.ext !== undefined)
    extra.push({ name: ".BTF.ext", bytes: options.ext });
  if (options.hasBase === true)
    extra.push({ name: ".BTF.base", bytes: Buffer.from([0, 0, 0, 0]) });
  if (options.hasIds === true)
    extra.push({ name: ".BTF_ids", bytes: Buffer.from([0, 0, 0, 0]) });
  const names = [
    "",
    sectionName,
    ...extra.map((item) => item.name),
    ".shstrtab",
  ];
  const shstrtab = Buffer.from(`${names.join("\0")}\0`, "latin1");
  const nameOffset = (target: string): number =>
    shstrtab.indexOf(Buffer.from(`${target}\0`, "latin1"));
  const contents = [btf, ...extra.map((item) => item.bytes), shstrtab];
  const start = 64;
  let at = start;
  const offsets = contents.map((content) => {
    const offset = at;
    at += content.length;
    return offset;
  });
  const shoff = at;
  const shnum = 2 + extra.length + 1;
  const bytes = Buffer.alloc(shoff + shnum * 64);
  bytes.writeUInt32LE(0x464c457f, 0);
  bytes[4] = 2;
  bytes[5] = 1;
  bytes[6] = 1;
  bytes.writeUInt16LE(1, 16);
  bytes.writeUInt16LE(247, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(BigInt(shoff), 40);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(0, 54);
  bytes.writeUInt16LE(0, 56);
  bytes.writeUInt16LE(64, 58);
  bytes.writeUInt16LE(shnum, 60);
  bytes.writeUInt16LE(shnum - 1, 62);
  contents.forEach((content, index) =>
    content.copy(bytes, offsets[index] ?? 0),
  );
  const writeSection = (
    index: number,
    name: string,
    type: number,
    offset: number,
    size: number,
    flags = 0n,
  ): void => {
    const header = shoff + index * 64;
    bytes.writeUInt32LE(nameOffset(name), header);
    bytes.writeUInt32LE(type, header + 4);
    bytes.writeBigUInt64LE(flags, header + 8);
    bytes.writeBigUInt64LE(0n, header + 16);
    bytes.writeBigUInt64LE(BigInt(offset), header + 24);
    bytes.writeBigUInt64LE(BigInt(size), header + 32);
    bytes.writeUInt32LE(0, header + 40);
    bytes.writeUInt32LE(0, header + 44);
    bytes.writeBigUInt64LE(1n, header + 48);
    bytes.writeBigUInt64LE(0n, header + 56);
  };
  writeSection(1, sectionName, 1, offsets[0] ?? 0, btf.length);
  extra.forEach((item, index) => {
    writeSection(
      index + 2,
      item.name,
      1,
      offsets[index + 1] ?? 0,
      item.bytes.length,
    );
  });
  writeSection(
    shnum - 1,
    ".shstrtab",
    3,
    offsets[offsets.length - 1] ?? 0,
    shstrtab.length,
  );
  return bytes;
};
