import { z } from "zod";

import { evidenceInputSchema } from "../evidenceReference.js";
import { dexDescriptorSchema } from "./dexTypes.js";

/**
 * One request projects at most this many methods. Each method yields four names
 * plus its overload count, so a larger selection is split by class or method
 * group instead of growing one response without bound.
 */
const JNI_NAME_METHOD_LIMIT = 2000;

/** JVM constant-pool text limit for one class name, method name or descriptor. */
const JNI_SYMBOL_TEXT_LIMIT = 65_535;

/**
 * Projected symbol text allowed per call. Every method repeats the mangled
 * class prefix in its short and long name, echoes its full descriptor, and
 * mangling expands a UTF-16 unit to at most six ASCII characters, so the input
 * size does not bound the result. The budget is checked on the projected length
 * before any name is built.
 */
const JNI_SYMBOL_OUTPUT_TEXT_LIMIT = 4_194_304;

/** `Java_` prefix of every projected symbol. */
const JNI_SYMBOL_PREFIX_LENGTH = "Java_".length;

/** `__` between a long name and its argument descriptor. */
const JNI_LONG_NAME_SEPARATOR_LENGTH = 2;

/** One caller-selected DEX method awaiting native-symbol correlation. */
export const jniMethodInputSchema = z.strictObject({
  method_name: z.string().min(1).max(JNI_SYMBOL_TEXT_LIMIT),
  /** Omitted and explicit null both mean "project the short name only". */
  dex_descriptor: dexDescriptorSchema
    .max(JNI_SYMBOL_TEXT_LIMIT)
    .nullable()
    .optional(),
});

/** Caller-selected class plus the DEX methods to project. */
export const androidJniNamesInputSchema = z
  .strictObject({
    class_name: z
      .string()
      .min(1)
      .max(JNI_SYMBOL_TEXT_LIMIT)
      .describe(
        "DEX binary class name, e.g. pkg.Outer$Inner; nested classes keep the $ separator",
      ),
    methods: z
      .array(jniMethodInputSchema)
      .min(1)
      .max(JNI_NAME_METHOD_LIMIT)
      .describe(
        `At most ${String(JNI_NAME_METHOD_LIMIT)} methods per call; split a larger selection by class or method group`,
      ),
    source_evidence: evidenceInputSchema
      .optional()
      .describe(
        "inspect_android_class Evidence these members came from, as its retained reference or inline record; its artifact subject and identity are linked, and the class and every method must match it",
      ),
  })
  .superRefine((input, context) => {
    const projected = projectedSymbolLength(input);
    if (projected > JNI_SYMBOL_OUTPUT_TEXT_LIMIT)
      context.addIssue({
        code: "custom",
        path: ["methods"],
        message: `Projected symbol text is ${String(projected)} characters; at most ${String(JNI_SYMBOL_OUTPUT_TEXT_LIMIT)} are produced per call. Shorten the class or method names, or split the selection by class or method group.`,
      });
  });

/** Expected native symbol spellings for one DEX method. */
export const jniNameProjectionSchema = z.strictObject({
  method_name: z.string(),
  dex_descriptor: dexDescriptorSchema.nullable(),
  jni_short_name: z.string(),
  jni_long_name: z.string().nullable(),
  jna_expected_name: z.string(),
  overload_group_size: z.number().int().min(1),
});

/** Deterministic JNI/JNA name projection over caller-selected methods. */
export const androidJniNamesResultSchema = z.strictObject({
  class_name: z.string(),
  methods: z.array(jniNameProjectionSchema),
  coverage: z.literal("complete"),
  unknowns: z.array(z.string()),
});

export type AndroidJniNamesInput = z.infer<typeof androidJniNamesInputSchema>;
export type AndroidJniNamesResult = z.infer<typeof androidJniNamesResultSchema>;

/** Names cover only statically exported JNI symbols. */
export const STATIC_EXPORT_ONLY_NOTE =
  "Expected names cover statically exported JNI symbols only; RegisterNatives dynamic registration is unknown.";

/** A name match never establishes loading or invocation. */
export const NAME_MATCH_NOTE =
  "A name match against a native library does not establish that the library is loaded or the method is called.";

/** Overload groups come from the selection, not the class inventory. */
export const SELECTION_SCOPED_OVERLOADS_NOTE =
  "overload_group_size counts the distinct descriptors you selected; a class can declare more overloads than were supplied, and the short name stays ambiguous without every overload.";

/** Guidance for selected methods without a descriptor. */
export const MISSING_DESCRIPTOR_NOTE =
  "Methods without a dex_descriptor report only the short name; supply the dex_descriptor that inspect_android_class reports per method to get the long name.";

/**
 * Guidance for `jna_expected_name`: it is the default JNA lookup spelling.
 * A custom `FunctionMapper` or an explicitly named function maps elsewhere.
 */
export const JNA_DEFAULT_MAPPING_NOTE =
  "jna_expected_name is the symbol JNA's default mapper derives from the DEX method name; a custom FunctionMapper or an explicitly named native function maps to another symbol and is not represented here.";

/** Guidance for identities copied from decompiler display names. */
export const DISPLAY_NAME_NOTE =
  "Supply raw DEX identities: inspect_android_class reports each method's dex_method_name and the class's dex_class_name, because its display names can be decompiler aliases or dotted nested names that do not match a native export.";

/** Length of `mangle(value)` without allocating the mangled string. */
const mangledLength = (value: string): number => {
  let length = 0;
  for (let index = 0; index < value.length; index += 1) {
    const char = value.charAt(index);
    length +=
      char === "/" || /^[A-Za-z0-9]$/u.test(char)
        ? 1
        : char === "_" || char === ";" || char === "["
          ? 2
          : 6;
  }
  return length;
};

/** Characters the projection would emit for one selection, counted cheaply. */
const projectedSymbolLength = (input: AndroidJniNamesInput): number => {
  const classPart = mangledLength(input.class_name.replaceAll(".", "/"));
  // The result echoes the raw class name once at the top level.
  let total = input.class_name.length;
  for (const method of input.methods) {
    const methodPart = mangledLength(method.method_name);
    const shortName = JNI_SYMBOL_PREFIX_LENGTH + classPart + 1 + methodPart;
    // The raw name is emitted twice: method_name and jna_expected_name.
    total += shortName + 2 * method.method_name.length;
    if (method.dex_descriptor !== null && method.dex_descriptor !== undefined) {
      const descriptor = method.dex_descriptor;
      const args = descriptor.slice(1, descriptor.indexOf(")"));
      total +=
        shortName +
        JNI_LONG_NAME_SEPARATOR_LENGTH +
        mangledLength(args) +
        // The complete descriptor is echoed per method, return type included.
        descriptor.length;
    }
  }
  return total;
};

const hex4 = (code: number): string => code.toString(16).padStart(4, "0");

/**
 * Escape one internal-form UTF-16 code unit per the JNI mangling rules:
 * ASCII alphanumerics pass through, `_` becomes `_1`, `;` becomes `_2`,
 * `[` becomes `_3`, and anything else becomes `_0xxxx`.
 */
const escapeChar = (char: string): string => {
  if (/^[A-Za-z0-9]$/u.test(char)) return char;
  if (char === "_") return "_1";
  if (char === ";") return "_2";
  if (char === "[") return "_3";
  const code = char.charCodeAt(0);
  return `_0${hex4(code)}`;
};

/**
 * Walk UTF-16 code units, not code points: `javac -h` mangles each half of a
 * supplementary character separately (`𐐀` becomes `_0d801_0dc00`).
 */
const mangle = (value: string): string =>
  value
    .split("")
    .map((char) => (char === "/" ? "_" : escapeChar(char)))
    .join("");

/** `pkg.Cls` (binary name, `$` for nested classes) becomes the JNI class part. */
const mangleClass = (className: string): string =>
  mangle(className.replaceAll(".", "/"));

const argumentDescriptor = (descriptor: string): string => {
  const args = descriptor.slice(1, descriptor.indexOf(")"));
  return mangle(args);
};

/**
 * Project expected JNI short/long names plus the JNA exact name.
 * Pure string projection; it never reads an APK or native library.
 */
export const projectJniNames = (
  input: AndroidJniNamesInput,
): AndroidJniNamesResult => {
  const parsed = androidJniNamesInputSchema.parse(input);
  const classPart = mangleClass(parsed.class_name);
  // Normalize an omitted descriptor once, so every later step sees null.
  const methods = parsed.methods.map((method) => ({
    method_name: method.method_name,
    dex_descriptor: method.dex_descriptor ?? null,
  }));
  // Distinct descriptors identify one overload; a repeated or omitted
  // descriptor cannot be told apart, so it counts once.
  const overloadGroups = new Map<string, Set<string | null>>();
  for (const method of methods) {
    const group = overloadGroups.get(method.method_name) ?? new Set();
    group.add(method.dex_descriptor);
    overloadGroups.set(method.method_name, group);
  }
  return androidJniNamesResultSchema.parse({
    class_name: parsed.class_name,
    methods: methods.map((method) => {
      const methodPart = mangle(method.method_name);
      return {
        method_name: method.method_name,
        dex_descriptor: method.dex_descriptor,
        jni_short_name: `Java_${classPart}_${methodPart}`,
        jni_long_name:
          method.dex_descriptor === null
            ? null
            : `Java_${classPart}_${methodPart}__${argumentDescriptor(method.dex_descriptor)}`,
        jna_expected_name: method.method_name,
        overload_group_size: overloadGroups.get(method.method_name)?.size ?? 1,
      };
    }),
    coverage: "complete",
    unknowns: [
      STATIC_EXPORT_ONLY_NOTE,
      NAME_MATCH_NOTE,
      SELECTION_SCOPED_OVERLOADS_NOTE,
      JNA_DEFAULT_MAPPING_NOTE,
      DISPLAY_NAME_NOTE,
      ...(methods.some((method) => method.dex_descriptor === null)
        ? [MISSING_DESCRIPTOR_NOTE]
        : []),
    ],
  });
};
