import {
  jvmInputSchemas,
  jvmResultSchemas,
} from "../../domain/jvm/jvmAnalysis.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/** Static JVM source recovery with an explicitly configured local decompiler. */
export const JVM_TOOL_CONTRACTS = [
  {
    name: "inspect_jvm_decompiler",
    ...toolContractMetadata("inspect_jvm_decompiler"),
    description:
      "Inspect the local Vineflower command, selection source, and version without decompiling an artifact. Select REA_VINEFLOWER_COMMAND (absolute executable) or vineflower on PATH. REA installs neither Vineflower nor Java.",
    kind: "jvm-provider",
    inputSchema: jvmInputSchemas.inspect_jvm_decompiler,
    outputSchema: evidenceResultOf(jvmResultSchemas.inspect_jvm_decompiler),
    examples: [{ title: "Check the JVM decompiler", input: {} }],
  },
  {
    name: "decompile_jvm_artifact",
    ...toolContractMetadata("decompile_jvm_artifact"),
    description:
      "Recover Java source from one local .class, .jar, or .zip with Vineflower without executing the target. Publish sources and a manifest to the caller-selected absent output directory. Return input and dependency SHA-256 hashes, tool version, source paths and hashes, and diagnostics. Dependencies and class-prefix filtering are explicit. An exhaustive output inventory does not establish input-class coverage, compilability, or runtime equivalence.",
    kind: "jvm-provider",
    inputSchema: jvmInputSchemas.decompile_jvm_artifact,
    outputSchema: evidenceResultOf(jvmResultSchemas.decompile_jvm_artifact),
    examples: [
      {
        title: "Recover sources from a JAR",
        input: {
          path: "/targets/example.jar",
          output_directory: "/analysis/example-sources",
        },
      },
      {
        title: "Recover a package with explicit dependencies",
        input: {
          path: "/targets/example.jar",
          output_directory: "/analysis/example-package",
          classpath: ["/targets/dependency.jar"],
          class_prefix: "org/example/",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
