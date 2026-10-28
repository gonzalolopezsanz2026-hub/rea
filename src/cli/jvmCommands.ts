import { z } from "incur";
import { projectCliAnalysisResult } from "./projectCliAnalysisResult.js";
import type { Logger } from "pino";
import { JvmAnalysisService } from "../application/jvm/JvmAnalysisService.js";
import type { JvmAnalysisPort } from "../application/jvm/JvmAnalysisPort.js";
import { createJvmAnalysisProvider } from "../composition/jvm.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { JvmOperation } from "../domain/jvm/jvmAnalysis.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { CliInstance } from "./types.js";

/** The same source-recovery requests as MCP, with caller-owned output paths. */
export const registerJvmCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
  provider: JvmAnalysisPort = createJvmAnalysisProvider(environment),
): void => {
  const service = new JvmAnalysisService(provider);
  const execute = (name: string, operation: JvmOperation, input: unknown) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, () =>
        finishAnalysisCommand(
          () => service.execute(operation, input, { signal }),
          { close: () => provider.close() },
          "vineflower",
          operation,
          signal,
        ).then(projectCliAnalysisResult),
      ),
    );
  cli.command(CLI_COMMANDS.inspectJvmDecompiler, {
    description:
      "Inspect the selected local JVM decompiler command and version",
    args: z.object({}),
    run: () =>
      execute(CLI_COMMANDS.inspectJvmDecompiler, "inspect_jvm_decompiler", {}),
  });
  cli.command(CLI_COMMANDS.decompileJvmArtifact, {
    description:
      "Recover Java sources and a manifest into a new directory with Vineflower",
    args: z.object({
      path: z
        .string()
        .min(1)
        .describe("Absolute path to a .class, .jar, or .zip file"),
      output_directory: z
        .string()
        .min(1)
        .describe("Absolute, absent output directory with an existing parent"),
    }),
    options: z.object({
      classpath: z
        .array(z.string().min(1))
        .optional()
        .describe("Absolute dependency file path (repeatable)"),
      "class-prefix": z
        .string()
        .min(1)
        .optional()
        .describe("JVM slash-name prefix, for example org/example/Widget"),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.decompileJvmArtifact, "decompile_jvm_artifact", {
        path: args.path,
        output_directory: args.output_directory,
        classpath: options.classpath ?? [],
        ...(options["class-prefix"] === undefined
          ? {}
          : { class_prefix: options["class-prefix"] }),
      }),
  });
};
