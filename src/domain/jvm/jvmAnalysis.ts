import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";
import { digestSchema } from "../digests.js";

/** Caller-selected JVM bytecode and durable source destination. */
export const jvmInputSchemas = {
  inspect_jvm_decompiler: z.strictObject({}),
  decompile_jvm_artifact: z.strictObject({
    path: localPathStringSchema.describe(
      "Absolute path to a regular .class, .jar, or .zip file; never executed",
    ),
    output_directory: localPathStringSchema.describe(
      "Absolute, absent destination with an existing parent; never overwritten",
    ),
    classpath: z
      .array(localPathStringSchema)
      .default([])
      .describe(
        "Explicit regular JAR or class files used only to resolve dependencies",
      ),
    class_prefix: localPathStringSchema
      .min(1)
      .regex(
        /^[^.\x2f\\\s][^.\\\s]*$/u,
        "Use a JVM slash-name prefix, for example org/example/Widget",
      )
      .optional(),
  }),
} as const;

export type JvmOperation = keyof typeof jvmInputSchemas;
export type JvmRequest = {
  [Name in JvmOperation]: {
    operation: Name;
    input: z.infer<(typeof jvmInputSchemas)[Name]>;
  };
}[JvmOperation];
export const jvmRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("inspect_jvm_decompiler"),
    input: jvmInputSchemas.inspect_jvm_decompiler,
  }),
  z.strictObject({
    operation: z.literal("decompile_jvm_artifact"),
    input: jvmInputSchemas.decompile_jvm_artifact,
  }),
]);
const client = z.strictObject({
  command: z.string().min(1),
  command_source: z.enum(["environment", "path"]),
  version: z.string().min(1),
});
const file = z.strictObject({
  path: localPathStringSchema,
  sha256: digestSchema,
  bytes: z.number().int().nonnegative(),
});

/** Source inventory describes emitted files, not semantic or class coverage. */
export const jvmResultSchemas = {
  inspect_jvm_decompiler: z.strictObject({ client }),
  decompile_jvm_artifact: z.strictObject({
    client,
    target: file,
    dependencies: z.array(file),
    class_prefix: z.string().nullable(),
    sources: z.array(file.extend({ relative_path: z.string().min(1) })),
    manifest: file,
    diagnostics: z.strictObject({
      stdout: z.string(),
      stderr: z.string(),
      exit_code: z.number().int(),
      truncated: z.boolean(),
    }),
    source_inventory_complete: z
      .boolean()
      .describe(
        "All emitted Java source files were inventoried; not a claim that all input classes or methods were decompiled",
      ),
    compilation_status: z.literal("not_attempted"),
    runtime_equivalence: z.literal("unknown"),
    limitations: z.array(z.string()),
  }),
} as const;
export type JvmDecompilationInput = z.infer<
  typeof jvmInputSchemas.decompile_jvm_artifact
>;
export type JvmDecompilationResult = z.infer<
  typeof jvmResultSchemas.decompile_jvm_artifact
>;
