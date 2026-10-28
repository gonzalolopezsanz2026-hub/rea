import {
  MAX_INSPECT_BTF_FACET_ENTRIES,
  MAX_INSPECT_BTF_REFERENCES,
  btfKindName,
  type Btf,
  type BtfIntEncoding,
  type BtfReference,
  type BtfTypeEntry,
  type InspectBtfInput,
} from "../../domain/native/btf.js";
import type { BtfStrings } from "./BtfStrings.js";

/** One type-section header plus the absolute file offset of its payload. */
export interface BtfTypeIndexEntry {
  readonly id: number;
  readonly offset: number;
  readonly nameOffset: number;
  readonly kind: number;
  readonly kindFlag: boolean;
  readonly vlen: number;
  readonly sizeOrType: number;
  readonly payload: number;
}

export interface BtfTypeIndex {
  readonly entries: readonly BtfTypeIndexEntry[];
  readonly counts: ReadonlyMap<number, number>;
  readonly decodedBytes: number;
  readonly unknownKinds: Btf["coverage"]["unknown_kinds"];
}

/**
 * Payload bytes after the fixed 12-byte `btf_type` for one kind, or null for a
 * kind this reader does not decode. The header macros from
 * `include/uapi/linux/btf.h` are the contract: vlen is 16 bits, kind is 5 bits
 * at 24-28 and bit 31 is kind_flag. The published prose describes a wider
 * vlen/kind field, which disagrees with every released encoder; the reader
 * follows the macros rather than adapting at runtime.
 */
const payloadBytes = (kind: number, vlen: number): number | null => {
  switch (kind) {
    case 1:
      return 4;
    case 2:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 16:
    case 18:
      return 0;
    case 3:
      return 12;
    case 4:
    case 5:
      return vlen * 12;
    case 6:
      return vlen * 8;
    case 13:
      return vlen * 8;
    case 14:
      return 4;
    case 15:
      return vlen * 12;
    case 17:
      return 4;
    case 19:
      return vlen * 12;
    default:
      return null;
  }
};

/** Walk the type section once, keeping ids and payload boundaries. */
export const indexBtfTypes = (
  bytes: Buffer,
  typeStart: number,
  typeLength: number,
  little: boolean,
): BtfTypeIndex => {
  const u32 = (at: number) =>
    little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  const entries: BtfTypeIndexEntry[] = [];
  const counts = new Map<number, number>();
  const unknownKinds: Btf["coverage"]["unknown_kinds"] = [];
  let at = 0;
  while (at < typeLength) {
    if (typeLength - at < 12) break;
    const absolute = typeStart + at;
    const nameOffset = u32(absolute);
    const info = u32(absolute + 4);
    const sizeOrType = u32(absolute + 8);
    const vlen = info & 0xffff;
    const kind = (info >>> 24) & 0x1f;
    const kindFlag = info >>> 31 === 1;
    const payload = payloadBytes(kind, vlen);
    if (payload === null) {
      unknownKinds.push(
        Object.freeze({ type_id: entries.length + 1, kind, offset: at }),
      );
      break;
    }
    if (payload > typeLength - at - 12) break;
    entries.push({
      id: entries.length + 1,
      offset: at,
      nameOffset,
      kind,
      kindFlag,
      vlen,
      sizeOrType,
      payload: absolute + 12,
    });
    counts.set(kind, (counts.get(kind) ?? 0) + 1);
    at += 12 + payload;
  }
  return { entries, counts, decodedBytes: at, unknownKinds };
};

/** Kinds whose third header word is a byte size rather than a type id. */
const SIZE_KINDS: ReadonlySet<number> = new Set([1, 4, 5, 6, 15, 16, 19]);
/** Kinds whose third header word references another type. */
const TYPE_KINDS: ReadonlySet<number> = new Set([
  2, 8, 9, 10, 11, 12, 13, 14, 17, 18,
]);

const intEncodingNames = (encoding: number): BtfIntEncoding[] => {
  const flags = (encoding >>> 24) & 0x0f;
  const names: BtfIntEncoding[] = [];
  if ((flags & 0x1) !== 0) names.push("signed");
  if ((flags & 0x2) !== 0) names.push("char");
  if ((flags & 0x4) !== 0) names.push("bool");
  return names;
};

const varLinkageName = (linkage: number) =>
  linkage === 0
    ? "static"
    : linkage === 1
      ? "global_allocated"
      : linkage === 2
        ? "global_extern"
        : "unknown";

const funcLinkageName = (linkage: number) =>
  linkage === 0
    ? "static"
    : linkage === 1
      ? "global"
      : linkage === 2
        ? "extern"
        : "unknown";

export interface BtfTypeSelection {
  readonly selection: "page" | "id" | "name";
  readonly pageOffset: number;
  readonly pageLimit: number;
  readonly entries: readonly BtfTypeEntry[];
  readonly references: readonly BtfReference[];
  readonly referencesTruncated: boolean;
  readonly facetsTruncated: number;
}

interface DecodeContext {
  readonly bytes: Buffer;
  readonly index: BtfTypeIndex;
  readonly byId: ReadonlyMap<number, BtfTypeIndexEntry>;
  readonly strings: BtfStrings;
  readonly little: boolean;
  readonly references: Map<number, BtfReference>;
  readonly takeFacets: (count: number) => boolean;
}

const decodeEntry = (
  context: DecodeContext,
  entry: BtfTypeIndexEntry,
): BtfTypeEntry => {
  const { bytes, strings } = context;
  const u32 = (at: number) =>
    context.little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  const i32 = (at: number) =>
    context.little ? bytes.readInt32LE(at) : bytes.readInt32BE(at);
  const base: BtfTypeEntry = {
    id: entry.id,
    kind: btfKindName(entry.kind),
    kind_flag: entry.kindFlag,
    name: strings.resolve(entry.nameOffset),
    name_offset: entry.nameOffset,
    vlen: entry.vlen,
    size: SIZE_KINDS.has(entry.kind) ? entry.sizeOrType : null,
    type: TYPE_KINDS.has(entry.kind) ? entry.sizeOrType : null,
    int: null,
    array: null,
    members: null,
    params: null,
    enum_values: null,
    var: null,
    func: null,
    datasec: null,
    forward: null,
    decl_tag: null,
    facets_truncated: false,
  };
  const at = entry.payload;
  switch (entry.kind) {
    case 1: {
      const encoding = u32(at);
      return {
        ...base,
        int: {
          encoding: (encoding >>> 24) & 0x0f,
          encoding_names: intEncodingNames(encoding),
          offset_bits: (encoding >>> 16) & 0xff,
          bits: encoding & 0xff,
        },
      };
    }
    case 3: {
      const elementType = u32(at);
      const indexType = u32(at + 4);
      return {
        ...base,
        array: {
          element_type: elementType,
          index_type: indexType,
          elements: u32(at + 8),
        },
      };
    }
    case 4:
    case 5: {
      if (!context.takeFacets(entry.vlen))
        return { ...base, facets_truncated: true };
      const members: NonNullable<BtfTypeEntry["members"]> = [];
      for (let i = 0; i < entry.vlen; i += 1) {
        const memberAt = at + i * 12;
        const memberType = u32(memberAt + 4);
        const offset = u32(memberAt + 8);
        members.push({
          name: strings.resolve(u32(memberAt)),
          type: memberType,
          bit_offset: entry.kindFlag ? offset & 0xffffff : offset,
          bitfield_size: entry.kindFlag ? offset >>> 24 : null,
        });
      }
      return { ...base, members };
    }
    case 6: {
      if (!context.takeFacets(entry.vlen))
        return { ...base, facets_truncated: true };
      const values: NonNullable<BtfTypeEntry["enum_values"]> = [];
      for (let i = 0; i < entry.vlen; i += 1) {
        const valueAt = at + i * 8;
        const raw = i32(valueAt + 4);
        values.push({
          name: strings.resolve(u32(valueAt)),
          value: String(entry.kindFlag ? raw : raw >>> 0),
        });
      }
      return { ...base, enum_values: values };
    }
    case 7:
      return { ...base, forward: { is_union: entry.kindFlag } };
    case 12:
      return { ...base, func: { linkage: funcLinkageName(entry.vlen) } };
    case 13: {
      if (!context.takeFacets(entry.vlen))
        return { ...base, facets_truncated: true };
      const params: NonNullable<BtfTypeEntry["params"]> = [];
      for (let i = 0; i < entry.vlen; i += 1) {
        const paramAt = at + i * 8;
        const paramType = u32(paramAt + 4);
        params.push({
          name: strings.resolve(u32(paramAt)),
          type: paramType,
          variadic: paramType === 0 && u32(paramAt) === 0,
        });
      }
      return { ...base, params };
    }
    case 14:
      return { ...base, var: { linkage: varLinkageName(u32(at)) } };
    case 15: {
      if (!context.takeFacets(entry.vlen))
        return { ...base, facets_truncated: true };
      const variables: NonNullable<BtfTypeEntry["datasec"]> = [];
      for (let i = 0; i < entry.vlen; i += 1) {
        const variableAt = at + i * 12;
        variables.push({
          type: u32(variableAt),
          offset: u32(variableAt + 4),
          size: u32(variableAt + 8),
        });
      }
      return { ...base, datasec: variables };
    }
    case 17: {
      const componentIndex = u32(at);
      return {
        ...base,
        decl_tag: {
          component_index: componentIndex,
          applies_to_whole_type: componentIndex === 0xffffffff,
        },
      };
    }
    case 19: {
      if (!context.takeFacets(entry.vlen))
        return { ...base, facets_truncated: true };
      const values: NonNullable<BtfTypeEntry["enum_values"]> = [];
      for (let i = 0; i < entry.vlen; i += 1) {
        const valueAt = at + i * 12;
        const lo = BigInt(u32(valueAt + 4));
        const hi = BigInt(u32(valueAt + 8));
        const raw = (hi << 32n) | lo;
        values.push({
          name: strings.resolve(u32(valueAt)),
          value: (entry.kindFlag ? BigInt.asIntN(64, raw) : raw).toString(),
        });
      }
      return { ...base, enum_values: values };
    }
    default:
      return base;
  }
};

const collectReferences = (
  context: DecodeContext,
): { readonly truncated: boolean } => {
  let truncated = false;
  const add = (id: number): void => {
    if (context.references.has(id)) return;
    if (context.references.size >= MAX_INSPECT_BTF_REFERENCES) {
      truncated = true;
      return;
    }
    if (id === 0) {
      context.references.set(0, {
        id: 0,
        state: "resolved",
        name: "void",
        kind: "void",
      });
      return;
    }
    const referenced = context.byId.get(id);
    context.references.set(
      id,
      referenced === undefined
        ? { id, state: "unresolved", name: null, kind: "unknown" }
        : {
            id,
            state: "resolved",
            name: context.strings.resolve(referenced.nameOffset),
            kind: btfKindName(referenced.kind),
          },
    );
  };
  for (const entry of context.index.entries) {
    const { kind, sizeOrType } = entry;
    if (kind === 3) {
      add(sizeOrType);
      const arrayAt = entry.payload;
      add(
        context.little
          ? context.bytes.readUInt32LE(arrayAt + 4)
          : context.bytes.readUInt32BE(arrayAt + 4),
      );
    } else if (kind === 4 || kind === 5) {
      for (let i = 0; i < entry.vlen; i += 1) {
        const field = entry.payload + i * 12 + 4;
        add(
          context.little
            ? context.bytes.readUInt32LE(field)
            : context.bytes.readUInt32BE(field),
        );
      }
    } else if (kind === 15) {
      for (let i = 0; i < entry.vlen; i += 1) {
        const field = entry.payload + i * 12;
        add(
          context.little
            ? context.bytes.readUInt32LE(field)
            : context.bytes.readUInt32BE(field),
        );
      }
    } else if (kind === 13) {
      add(sizeOrType);
      for (let i = 0; i < entry.vlen; i += 1) {
        const field = entry.payload + i * 8;
        add(
          context.little
            ? context.bytes.readUInt32LE(field + 4)
            : context.bytes.readUInt32BE(field + 4),
        );
      }
    } else if (TYPE_KINDS.has(kind)) {
      add(sizeOrType);
    }
  }
  return { truncated };
};

/** Decode the requested page or selection, resolving one level of references. */
export const decodeBtfTypes = (
  bytes: Buffer,
  index: BtfTypeIndex,
  strings: BtfStrings,
  input: InspectBtfInput,
): BtfTypeSelection => {
  const byId = new Map(index.entries.map((entry) => [entry.id, entry]));
  const references = new Map<number, BtfReference>();
  let facetRemaining = MAX_INSPECT_BTF_FACET_ENTRIES;
  let facetsTruncated = 0;
  const context: DecodeContext = {
    bytes,
    index,
    byId,
    strings,
    little: bytes[0] === 0x9f && bytes[1] === 0xeb,
    references,
    takeFacets: (entries) => {
      if (entries > facetRemaining) {
        facetsTruncated += 1;
        return false;
      }
      facetRemaining -= entries;
      return true;
    },
  };
  // Collect references for every indexed type so a page's scalar facts always
  // carry the same reference summary regardless of which page is returned.
  const { truncated } = collectReferences(context);

  const selection =
    input.type_id !== undefined
      ? "id"
      : input.type_name !== undefined
        ? "name"
        : "page";
  const entries: BtfTypeEntry[] = [];
  let pageOffset = input.type_offset;
  if (selection === "id") {
    pageOffset = input.type_id ?? 1;
    const selected = byId.get(pageOffset);
    if (selected !== undefined) entries.push(decodeEntry(context, selected));
  } else if (selection === "name") {
    const target = Buffer.from(input.type_name ?? "", "latin1");
    const matches = index.entries.filter((entry) =>
      strings.equals(entry.nameOffset, target),
    );
    for (const match of matches.slice(
      input.type_offset - 1,
      input.type_offset - 1 + input.type_limit,
    ))
      entries.push(decodeEntry(context, match));
  } else {
    for (
      let id = input.type_offset;
      id <= input.type_offset + input.type_limit - 1;
      id += 1
    ) {
      const selected = byId.get(id);
      if (selected === undefined) break;
      entries.push(decodeEntry(context, selected));
    }
  }

  return {
    selection,
    pageOffset,
    pageLimit: selection === "id" ? 1 : input.type_limit,
    entries,
    references: [...references.values()].sort(
      (left, right) => left.id - right.id,
    ),
    referencesTruncated: truncated,
    facetsTruncated,
  };
};
