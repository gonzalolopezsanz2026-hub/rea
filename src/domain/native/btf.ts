import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";
import { ELF_OBJECT_TYPE_NAMES } from "./elfNotes.js";

const uint = z.number().int().min(0).max(0xffffffff);

/** Hard ceiling on the caller-selected input read budget. */
export const MAX_INSPECT_BTF_FILE_BYTES = 536870912;
/** Largest type page this operation returns in one result. */
export const MAX_INSPECT_BTF_TYPE_PAGE = 100;
/** Largest ext-record page this operation returns per subsection. */
export const MAX_INSPECT_BTF_EXT_PAGE = 200;
/**
 * Retained type, member, parameter and record name length. BTF names are C
 * identifiers; a longer name stays unretained and is reported as truncated
 * instead of being copied into every reference.
 */
export const MAX_INSPECT_BTF_NAME_BYTES = 512;
/**
 * Total facet entries (members, parameters, enumerators, data-section
 * variables) one result may decode. Real vmlinux data sections can hold tens of
 * thousands of variables, so a page of dense types could otherwise multiply
 * into an unbounded reply. Types beyond the budget keep their scalar facts.
 */
export const MAX_INSPECT_BTF_FACET_ENTRIES = 65536;
/** Distinct type references retained for one result. */
export const MAX_INSPECT_BTF_REFERENCES = 8192;
/** Total name bytes one result may retain across types and references. */
export const MAX_INSPECT_BTF_NAME_TEXT_BYTES = 4194304;

/**
 * Kind names indexed by the 5-bit kind field from
 * `include/uapi/linux/btf.h`. Index 0 is the label for type id 0; kind 0
 * itself is BTF_KIND_UNKN and is reported as unknown in the type section.
 */
export const BTF_KIND_NAMES = [
  "void",
  "int",
  "ptr",
  "array",
  "struct",
  "union",
  "enum",
  "fwd",
  "typedef",
  "volatile",
  "const",
  "restrict",
  "func",
  "func_proto",
  "var",
  "datasec",
  "float",
  "decl_tag",
  "type_tag",
  "enum64",
  "unknown",
] as const;

export type BtfKindName = (typeof BTF_KIND_NAMES)[number];

/** Map a type-section kind field to its released name; 0 and 20-31 stay unknown. */
export const btfKindName = (kind: number): BtfKindName => {
  if (kind < 1 || kind > 19) return "unknown";
  return BTF_KIND_NAMES[kind] ?? "unknown";
};

export const BTF_INT_ENCODINGS = ["signed", "char", "bool"] as const;
export type BtfIntEncoding = (typeof BTF_INT_ENCODINGS)[number];

export const BTF_VAR_LINKAGES = [
  "static",
  "global_allocated",
  "global_extern",
  "unknown",
] as const;

export const BTF_FUNC_LINKAGES = [
  "static",
  "global",
  "extern",
  "unknown",
] as const;

export const BTF_CORE_RELOCATION_KINDS = [
  "field_byte_offset",
  "field_byte_size",
  "field_exists",
  "field_signed",
  "field_lshift_u64",
  "field_rshift_u64",
  "type_id_local",
  "type_id_target",
  "type_exists",
  "type_size",
  "enumval_exists",
  "enumval_value",
  "type_matches",
  "unknown",
] as const;

const btfInputFields = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to a standalone BTF blob or an ELF image",
  ),
  section: z
    .string()
    .min(1)
    .max(255)
    .default(".BTF")
    .describe("ELF section name that carries the BTF blob"),
  type_id: z
    .number()
    .int()
    .min(1)
    .max(0xffffffff)
    .optional()
    .describe("Return one type by 1-based id instead of a page"),
  type_name: z
    .string()
    .min(1)
    .max(MAX_INSPECT_BTF_NAME_BYTES)
    .optional()
    .describe("Return every type with this exact name instead of a page"),
  type_offset: z
    .number()
    .int()
    .min(1)
    .max(0xffffffff)
    .default(1)
    .describe("First 1-based type id in the returned page"),
  type_limit: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_BTF_TYPE_PAGE)
    .default(25)
    .describe("Maximum types in the returned page"),
  include_ext: z
    .boolean()
    .default(true)
    .describe("Read the ELF .BTF.ext section when it is present"),
  ext_section: z
    .string()
    .min(1)
    .max(255)
    .optional()
    .describe("Return records for this ELF section instead of the ext summary"),
  ext_offset: z
    .number()
    .int()
    .min(0)
    .max(0xffffffff)
    .default(0)
    .describe("First record index in each selected ext subsection"),
  ext_limit: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_BTF_EXT_PAGE)
    .default(50)
    .describe("Maximum records per selected ext subsection"),
  max_file_bytes: z
    .number()
    .int()
    .min(64)
    .max(MAX_INSPECT_BTF_FILE_BYTES)
    .default(67108864)
    .describe("Maximum stable artifact bytes to read (default 64 MiB)"),
});

/** Shipped input field shapes, exposed for CLI option reuse. */
export const inspectBtfInputFields = btfInputFields.shape;

/**
 * One type selection or one page. `type_offset`/`type_limit` are the default;
 * an explicit id or exact name takes precedence.
 */
export const inspectBtfInputSchema = btfInputFields.superRefine(
  (input, ctx) => {
    if (input.type_id !== undefined && input.type_name !== undefined)
      ctx.addIssue({
        code: "custom",
        path: ["type_name"],
        message: "Select a type by id or by name, not both.",
      });
    if (!input.include_ext && input.ext_section !== undefined)
      ctx.addIssue({
        code: "custom",
        path: ["ext_section"],
        message: "ext_section requires include_ext.",
      });
  },
);

const range = z.strictObject({ offset: uint, bytes: uint });
const name = z.string();

const referenceSchema = z.strictObject({
  id: uint,
  state: z.enum(["resolved", "unresolved"]),
  name: name.nullable(),
  kind: z.enum(BTF_KIND_NAMES),
});

const typeEntrySchema = z.strictObject({
  id: uint,
  kind: z.enum(BTF_KIND_NAMES),
  kind_flag: z.boolean(),
  name: name.nullable(),
  name_offset: uint,
  vlen: uint,
  /** Size in bytes for INT, ENUM, STRUCT, UNION, DATASEC, FLOAT and ENUM64. */
  size: uint.nullable(),
  /** Referenced type id for PTR, TYPEDEF, qualifiers, FUNC, FUNC_PROTO and tags. */
  type: uint.nullable(),
  int: z
    .strictObject({
      encoding: uint,
      encoding_names: z.array(z.enum(BTF_INT_ENCODINGS)),
      offset_bits: uint,
      bits: uint,
    })
    .nullable(),
  array: z
    .strictObject({
      element_type: uint,
      index_type: uint,
      elements: uint,
    })
    .nullable(),
  members: z
    .array(
      z.strictObject({
        name: name.nullable(),
        type: uint,
        bit_offset: uint,
        bitfield_size: uint.nullable(),
      }),
    )
    .nullable(),
  params: z
    .array(
      z.strictObject({
        name: name.nullable(),
        type: uint,
        variadic: z.boolean(),
      }),
    )
    .nullable(),
  enum_values: z
    .array(z.strictObject({ name: name.nullable(), value: z.string() }))
    .nullable(),
  var: z.strictObject({ linkage: z.enum(BTF_VAR_LINKAGES) }).nullable(),
  func: z.strictObject({ linkage: z.enum(BTF_FUNC_LINKAGES) }).nullable(),
  datasec: z
    .array(z.strictObject({ type: uint, offset: uint, size: uint }))
    .nullable(),
  forward: z.strictObject({ is_union: z.boolean() }).nullable(),
  decl_tag: z
    .strictObject({
      component_index: uint,
      applies_to_whole_type: z.boolean(),
    })
    .nullable(),
  /** True when the per-result facet budget omitted this entry's payload. */
  facets_truncated: z.boolean(),
});

const extSubsectionSchema = z.strictObject({
  record_bytes: uint,
  total_records: uint,
  sections: z.array(z.strictObject({ name: name.nullable(), records: uint })),
});

const extSelectionSchema = z.strictObject({
  section: z.string(),
  offset: uint,
  limit: uint,
  func: z.array(
    z.strictObject({
      insn_off: uint,
      type_id: uint,
      function: name.nullable(),
    }),
  ),
  func_total: uint,
  line: z.array(
    z.strictObject({
      insn_off: uint,
      file: name.nullable(),
      source_line: name.nullable(),
      line: uint,
      column: uint,
    }),
  ),
  line_total: uint,
  core: z.array(
    z.strictObject({
      insn_off: uint,
      type_id: uint,
      access: name.nullable(),
      kind: uint,
      kind_name: z.enum(BTF_CORE_RELOCATION_KINDS),
    }),
  ),
  core_total: uint,
});

/** Complete bounded inspection of one BTF blob and its optional BTF.ext. */
export const btfSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  carrier: z.enum(["standalone", "elf_section"]),
  elf: z
    .strictObject({
      format: z.enum(["elf32", "elf64"]),
      machine: uint,
      type: uint,
      type_name: z.enum(ELF_OBJECT_TYPE_NAMES),
      has_btf_base: z.boolean(),
      has_btf_ids: z.boolean(),
    })
    .nullable(),
  section: z.strictObject({ name: z.string(), location: range }).nullable(),
  header: z.strictObject({
    magic: z.literal("0xeb9f"),
    byte_order: z.enum(["little", "big"]),
    version: uint,
    flags: uint,
    hdr_len: uint,
    type: range,
    string: range,
  }),
  strings: z.strictObject({
    bytes: uint,
    count: uint,
    first_empty: z.boolean(),
  }),
  types: z.strictObject({
    total: uint,
    counts: z.array(
      z.strictObject({ kind: z.enum(BTF_KIND_NAMES), count: uint }),
    ),
    selection: z.enum(["page", "id", "name"]),
    page: z.strictObject({ offset: uint, limit: uint, returned: uint }),
    entries: z.array(typeEntrySchema),
  }),
  references: z.array(referenceSchema),
  ext: z
    .strictObject({
      header: z.strictObject({
        version: uint,
        flags: uint,
        hdr_len: uint,
        func_info: range,
        line_info: range,
        core_relo: range.nullable(),
      }),
      func_info: extSubsectionSchema,
      line_info: extSubsectionSchema,
      core_relo: extSubsectionSchema.nullable(),
      selection: extSelectionSchema.nullable(),
    })
    .nullable(),
  coverage: z.strictObject({
    status: z.enum(["complete", "partial"]),
    decoded_type_bytes: uint,
    undecoded_bytes: uint,
    unknown_kinds: z.array(
      z.strictObject({ type_id: uint, kind: uint, offset: uint }),
    ),
    unresolved_references: uint,
    references_truncated: z.boolean(),
    names_truncated: uint,
    facets_truncated: uint,
  }),
  limitations: z.array(z.string()),
});

export type Btf = z.infer<typeof btfSchema>;
export type InspectBtfInput = z.infer<typeof inspectBtfInputSchema>;
export type BtfTypeEntry = z.infer<typeof typeEntrySchema>;
export type BtfReference = z.infer<typeof referenceSchema>;
