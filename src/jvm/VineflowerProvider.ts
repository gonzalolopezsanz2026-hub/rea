import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, isAbsolute, join, relative } from "node:path";
import type { JvmAnalysisPort } from "../application/jvm/JvmAnalysisPort.js";
import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
  type ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { artifactFileCancellationCause } from "../artifacts/ArtifactFileOperation.js";
import { createAnalysisExecutionEvidence } from "../domain/analysisObservation.js";
import type { Evidence } from "../domain/evidence.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { retainOwnedCommandCleanup } from "../providers/OwnedCommandCleanup.js";
import { SafeOutputTree } from "../artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../artifacts/SafeOutputTreeCreationFailure.js";
import {
  assertPathIdentity,
  readDirectoryIdentity,
  type DirectoryIdentity,
} from "../artifacts/SafeOutputTreeIdentity.js";
import {
  AnalysisError,
  type AnalysisCapturedOutput,
} from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  jvmResultSchemas,
  type JvmDecompilationInput,
  type JvmRequest,
  type JvmOperation,
} from "../domain/jvm/jvmAnalysis.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  OwnedCommandFailure,
  prepareOwnedCommand,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import type { ProviderProcessSnapshot } from "../process/ProviderProcess.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  parseVineflowerVersion,
  resolveVineflowerCommand,
  type VineflowerCommand,
} from "./VineflowerConfiguration.js";
import {
  checkJvmCancellation,
  JvmMetadataBudget,
  jvmInputFailure,
  publishJvmSources,
  snapshotJvmFile,
  verifyJvmSnapshots,
  writeJvmManifest,
  type JvmSnapshot,
} from "./VineflowerFiles.js";

export const VINEFLOWER_PROVIDER_IDENTITY = {
  id: "vineflower",
  name: "Vineflower",
  version: null,
} as const;
// Match the existing external-decompiler lifecycle and diagnostic retention policy.
const TIMEOUT_MS = 600_000;
const DIAGNOSTIC_BYTES = 4 * 1024 * 1024;
const LIMITATIONS = [
  "Java source is derived from JVM bytecode; original source text, names, comments, and build configuration are not recovered.",
  "The source inventory covers emitted .java files only. Exit status and file count do not establish complete class or method reconstruction; review diagnostics and source-level decompiler failure comments.",
  "Generated sources were not compiled or executed. Runtime equivalence is unknown; no target bytecode is executed by REA.",
  "Dependency resolution uses the explicitly selected classpath and the local decompiler runtime. Missing dependencies can limit reconstruction.",
] as const;

type Resources = {
  operation: JvmOperation;
  scope: ArtifactResourceScope;
  lease?: AnalysisCleanupLease;
  publishedEvidence?: Evidence;
  commandTimeoutMs?: number;
  capturedOutput?: AnalysisCapturedOutput;
  root?: string;
  rootIdentity?: DirectoryIdentity;
  inputs?: SafeOutputTree;
  output?: SafeOutputTree;
};

/** Serial, local-only adapter retaining all resources whose cleanup remains uncertain. */
export class VineflowerProvider implements JvmAnalysisPort {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  #tail: Promise<void> = Promise.resolve();
  #closing = false;
  #pending: Resources | undefined;

  constructor(
    options: {
      readonly environment?: Readonly<Record<string, string | undefined>>;
    } = {},
  ) {
    this.#environment = snapshotEnvironment(options.environment ?? process.env);
  }

  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    if (signal?.aborted)
      throw new AnalysisCancelledError("inspect_jvm_decompiler", {
        cause: signal.reason,
      });
    if (this.#closing || this.#pending !== undefined)
      return {
        status: "unavailable",
        code: "runtime_missing",
        reason: this.#closing
          ? "Provider is closed"
          : "Provider resource cleanup remains pending",
        diagnostics: { cleanup_pending: this.#pending !== undefined },
      };
    try {
      const selected = await resolveVineflowerCommand(this.#environment);
      if (signal?.aborted)
        throw new AnalysisCancelledError("inspect_jvm_decompiler", {
          cause: signal.reason,
        });
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          command: selected.command,
          command_source: selected.commandSource,
          version_probe: "not_attempted",
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof AnalysisCancelledError) throw cause;
      const configured = this.#environment.REA_VINEFLOWER_COMMAND;
      return {
        status: "unavailable",
        code:
          configured !== undefined &&
          configured.trim() !== "" &&
          !isAbsolute(configured)
            ? "not_configured"
            : "executable_missing",
        reason:
          cause instanceof AnalysisCapabilityUnavailableError
            ? cause.reason
            : message(cause),
        diagnostics: {},
      };
    }
  }

  execute(
    request: JvmRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const run = this.#tail.then(() =>
      this.#closing
        ? err(
            new AnalysisCapabilityUnavailableError(
              "vineflower",
              request.operation,
              "Provider is closed",
            ),
          )
        : this.#execute(request, options),
    );
    this.#tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async #execute(
    request: JvmRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const previous = await this.#retire();
    if (previous !== undefined) return err(previous);
    const resources: Resources = {
      operation: request.operation,
      scope: new ArtifactResourceScope(),
    };
    const timeoutMs =
      request.operation === "inspect_jvm_decompiler" ? 20_000 : TIMEOUT_MS;
    let deadline: AbortSignal | undefined;
    let signal = options?.signal;
    let result: AnalysisExecution | undefined;
    let failure: AnalysisError | undefined;
    try {
      if (signal?.aborted)
        throw new AnalysisCancelledError(request.operation, {
          cause: signal.reason,
        });
      // Reserve the absent destination before starting any provider process.
      if (request.operation === "decompile_jvm_artifact") {
        try {
          resources.output = await SafeOutputTree.create(
            request.input.output_directory,
          );
        } catch (cause: unknown) {
          if (cause instanceof SafeOutputTreeCreationFailure)
            resources.output = cause.tree;
          throw jvmInputFailure(
            "output_directory",
            `Cannot create the requested absent output directory: ${message(cause)}`,
            cause,
          );
        }
      }
      const command = await resolveVineflowerCommand(
        this.#environment,
        request.operation,
      );
      // Native helper compilation has its own deadline, outside the execution budget.
      await prepareOwnedCommand(signal);
      deadline = AbortSignal.timeout(timeoutMs);
      signal =
        options?.signal === undefined
          ? deadline
          : AbortSignal.any([options.signal, deadline]);
      const versionRun = await this.#run(
        command,
        ["--help"],
        resources,
        "inspect_jvm_decompiler",
        signal,
      );
      const version = parseVineflowerVersion(
        versionRun.stdout.text,
        versionRun.stderr.text,
        request.operation,
      );
      const client = {
        command: command.command,
        command_source: command.commandSource,
        version,
      };
      if (request.operation === "inspect_jvm_decompiler")
        result = createAnalysisExecution(
          jvmResultSchemas.inspect_jvm_decompiler.parse({ client }),
          { ...VINEFLOWER_PROVIDER_IDENTITY, version },
        );
      else {
        result = await this.#decompile(
          request.input,
          command,
          client,
          resources,
          signal,
        );
        await this.#cleanupWorkspace(resources);
        checkJvmCancellation(signal);
        await resources.output!.commit(signal);
      }
    } catch (cause: unknown) {
      retainOwnedCommandCleanup(
        cause,
        {
          retain: (owner, resource) =>
            resources.scope.retain({
              kind: "lease",
              resource,
              lease: AnalysisCleanupLease.forCloseOwner(owner, resource),
            }),
          run: (operation) => resources.scope.run(operation),
        },
        "vineflower",
        request.operation,
      );
      failure = normalizeFailure(
        cause,
        request.operation,
        signal,
        resources.commandTimeoutMs,
      );
      if (resources.capturedOutput !== undefined)
        failure.retainCapturedOutput(resources.capturedOutput);
      if (deadline?.aborted && !options?.signal?.aborted)
        failure = new AnalysisTimeoutError(request.operation, timeoutMs, {
          cause: failure,
          ...(failure.capturedOutput === undefined
            ? {}
            : { capturedOutput: failure.capturedOutput }),
        });
    }
    this.#pending = resources;
    const cleanup = await this.#retire();
    if (cleanup !== undefined) {
      if (result !== undefined && resources.output?.published) {
        resources.publishedEvidence = createAnalysisExecutionEvidence(
          request.operation,
          request.input,
          result,
          "derived",
        );
        cleanup.retainPartialObservation(resources.publishedEvidence);
        failure?.retainPartialObservation(resources.publishedEvidence);
      }
      return err(
        failure === undefined
          ? cleanup
          : analysisErrorWithCleanupFailure(
              failure,
              cleanup,
              request.operation,
            ).bindCleanupDependencies([failure, cleanup]),
      );
    }
    if (
      failure !== undefined &&
      !(resources.output?.published && result !== undefined)
    )
      return err(failure);
    return result === undefined
      ? err(
          new AnalysisOutputError(
            request.operation,
            "No provider result was produced",
          ),
        )
      : ok(result);
  }

  async #decompile(
    input: JvmDecompilationInput,
    command: VineflowerCommand,
    client: {
      command: string;
      command_source: "environment" | "path";
      version: string;
    },
    resources: Resources,
    signal?: AbortSignal,
  ): Promise<AnalysisExecution> {
    resources.root = await mkdtemp(join(tmpdir(), "rea-vineflower-"));
    resources.rootIdentity = await readDirectoryIdentity(resources.root);
    resources.root = await realpath(resources.root);
    try {
      resources.inputs = await SafeOutputTree.create(
        join(resources.root, "inputs"),
      );
    } catch (cause: unknown) {
      if (cause instanceof SafeOutputTreeCreationFailure)
        resources.inputs = cause.tree;
      throw cause;
    }
    const archiveOutput = extname(input.path).toLowerCase() !== ".class";
    const outputName = archiveOutput ? "generated.zip" : "generated";
    const staging = join(resources.root, outputName);
    // Archive output preserves case-distinct classes; upstream file saving requires an archive input.
    if (!archiveOutput) await mkdir(staging, { mode: 0o700 });
    const stagingIdentity = archiveOutput
      ? undefined
      : await readDirectoryIdentity(staging);
    const target = await snapshotJvmFile(
      resources.scope,
      resources.inputs,
      { path: input.path, name: "target", dependency: false },
      signal,
    );
    const dependencies: JvmSnapshot[] = [];
    const budget = new JvmMetadataBudget();
    for (const [index, path] of input.classpath.entries()) {
      budget.add(path);
      dependencies.push(
        await snapshotJvmFile(
          resources.scope,
          resources.inputs,
          { path, name: `dependency-${String(index)}`, dependency: true },
          signal,
        ),
      );
    }
    const arguments_ = [
      archiveOutput ? "--file" : "--folder",
      "--remove-synthetic=0",
      "--decompile-inner=0",
      "--skip-extra-files=1",
      "--bytecode-source-mapping=1",
      "--log-level=warn",
      ...(input.class_prefix === undefined
        ? []
        : [`--only=${input.class_prefix}`]),
      ...dependencies.map(
        (dependency) =>
          `--add-external=${relative(resources.root!, dependency.snapshot.path)}`,
      ),
      relative(resources.root, target.snapshot.path),
      outputName,
    ];
    const run = await this.#run(
      command,
      arguments_,
      resources,
      "decompile_jvm_artifact",
      signal,
    );
    resources.capturedOutput = captureOutput(run);
    await assertPathIdentity(resources.root, resources.rootIdentity);
    if (stagingIdentity !== undefined)
      await assertPathIdentity(staging, stagingIdentity);
    await verifyJvmSnapshots(
      resources.scope,
      [target, ...dependencies],
      signal,
    );
    const output = resources.output!;
    const sources = await publishJvmSources(
      resources.scope,
      { path: staging, format: archiveOutput ? "zip" : "directory" },
      output,
      signal,
    );
    if (stagingIdentity !== undefined)
      await assertPathIdentity(staging, stagingIdentity);
    const details = {
      client,
      target: target.original,
      dependencies: dependencies.map((dependency) => dependency.original),
      class_prefix: input.class_prefix ?? null,
      sources,
      diagnostics: {
        stdout: run.stdout.text,
        stderr: run.stderr.text,
        exit_code: run.exitCode ?? 0,
        truncated: run.diagnosticTruncated === true,
      },
      source_inventory_complete: true,
      compilation_status: "not_attempted" as const,
      runtime_equivalence: "unknown" as const,
      limitations: [
        ...LIMITATIONS,
        ...(sources.length === 0
          ? ["Vineflower emitted no Java source files for this selection."]
          : []),
      ],
    };
    const manifest = await writeJvmManifest(output, details, signal);
    const result = jvmResultSchemas.decompile_jvm_artifact.parse({
      ...details,
      manifest,
    });
    return createAnalysisExecution(
      result,
      { ...VINEFLOWER_PROVIDER_IDENTITY, version: client.version },
      {
        subject: {
          path: target.original.path,
          sha256: target.original.sha256,
          format:
            extname(input.path).toLowerCase() === ".class" ? "file" : "zip",
        },
        limitations: result.limitations,
        locations: [
          { kind: "artifact-path", path: target.original.path },
          ...result.sources.map((source) => ({
            kind: "artifact-path" as const,
            path: source.path,
          })),
          { kind: "artifact-path", path: manifest.path },
        ],
      },
    );
  }

  #run(
    command: VineflowerCommand,
    arguments_: readonly string[],
    resources: Resources,
    operation: string,
    signal?: AbortSignal,
  ): Promise<ProviderProcessSnapshot> {
    const timeoutMs =
      operation === "inspect_jvm_decompiler" ? 20_000 : TIMEOUT_MS;
    resources.commandTimeoutMs = timeoutMs;
    return runOwnedCommand(
      {
        command: command.command,
        expectedCommand: null,
        arguments: arguments_,
        runId: randomUUID(),
        hostEnvironment: { ...this.#environment },
        ...(resources.root === undefined ? {} : { cwd: resources.root }),
      },
      {
        timeoutMs,
        diagnosticBytes: DIAGNOSTIC_BYTES,
      },
      signal === undefined ? {} : { signal },
    );
  }

  async close(): Promise<void> {
    this.#closing = true;
    await this.#tail;
    const failure = await this.#retire();
    if (failure !== undefined) throw failure;
  }

  async #cleanupWorkspace(resources: Resources): Promise<void> {
    await resources.scope.close();
    if (resources.inputs !== undefined) {
      await resources.inputs.rollback();
      delete resources.inputs;
    }
    if (resources.root !== undefined) {
      if (resources.rootIdentity === undefined)
        throw new Error("Private workspace identity could not be established");
      await assertPathIdentity(resources.root, resources.rootIdentity);
      await rm(resources.root, { recursive: true, force: true });
      delete resources.root;
      delete resources.rootIdentity;
    }
  }

  async #retire(): Promise<ProviderCleanupError | undefined> {
    const resources = this.#pending;
    if (resources === undefined) return undefined;
    const lease = (resources.lease ??= new AnalysisCleanupLease(
      async () => {
        await this.#cleanupWorkspace(resources);
        await resources.output?.rollback();
      },
      {
        get cleanupResources() {
          if (resources.lease?.released === true) return [];
          return [
            ...resources.scope.cleanupResources,
            ...(resources.root === undefined ? [] : [resources.root]),
            ...(resources.output === undefined
              ? []
              : [resources.output.outputRoot]),
          ];
        },
      },
    ));
    try {
      await lease.release();
      this.#pending = undefined;
      return undefined;
    } catch (cause: unknown) {
      const failure = new ProviderCleanupError(
        "vineflower",
        lease.cleanupResources ?? [],
        {
          reason: message(cause),
        },
        {
          operation: resources.operation,
          cause,
          ...(resources.publishedEvidence === undefined
            ? {}
            : { partialObservation: resources.publishedEvidence }),
        },
      ).bindCleanupResourceOwner(lease);
      lease.bindCleanupError(failure);
      return resources.capturedOutput === undefined
        ? failure
        : failure.retainCapturedOutput(resources.capturedOutput);
    }
  }
}

const message = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);
const normalizeFailure = (
  cause: unknown,
  operation: string,
  signal?: AbortSignal,
  commandTimeoutMs?: number,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof OwnedCommandFailure) {
    const snapshot = cause.snapshot;
    const capturedOutput =
      snapshot === null ? undefined : captureOutput(snapshot);
    const options = {
      cause,
      ...(capturedOutput === undefined ? {} : { capturedOutput }),
    };
    if (cause.reason === "cancelled")
      return new AnalysisCancelledError(operation, {
        ...options,
        cause:
          cause.cancellation === undefined
            ? signal?.aborted
              ? signal.reason
              : cause
            : cause.cancellation.reason,
      });
    if (cause.reason === "timeout") {
      const timeoutMs =
        commandTimeoutMs ??
        (operation === "inspect_jvm_decompiler" ? 20_000 : TIMEOUT_MS);
      return new AnalysisTimeoutError(operation, timeoutMs, {
        ...options,
        remediationAction: `The Vineflower ${timeoutMs === 20_000 ? "version probe" : "decompilation command"} reached its fixed ${String(timeoutMs)} ms deadline (no runtime override). Check the selected launcher and Java installation; for decompilation, select a smaller complete artifact when that preserves the requested analysis.`,
      });
    }
    if (cause.reason === "output-limit")
      return new AnalysisResourceConstraintError(
        operation,
        "memory",
        "Vineflower diagnostics exceeded the retained output budget",
        { diagnostic_bytes: DIAGNOSTIC_BYTES },
        {
          ...options,
          ...fixedAllowanceOptions(
            `Vineflower diagnostic capture allowance of ${String(DIAGNOSTIC_BYTES)} bytes (no runtime override)`,
            "capture",
          ),
        },
      );
    return new AnalysisOutputError(
      operation,
      `Vineflower execution failed: ${message(cause)}`,
      options,
    );
  }
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(operation, {
      cause: artifactFileCancellationCause(cause),
    });
  if (signal?.aborted)
    return new AnalysisCancelledError(operation, { cause: signal.reason });
  return new ProviderAdapterError("vineflower", operation, {
    cause,
    userMessage: message(cause),
    diagnostics: { reason: message(cause) },
  });
};

const captureOutput = (
  snapshot: ProviderProcessSnapshot,
): AnalysisCapturedOutput => ({
  stdout: snapshot.stdout.text,
  stderr: snapshot.stderr.text,
  truncated: snapshot.diagnosticTruncated === true,
  exit_code: snapshot.exitCode ?? null,
  signal: snapshot.signal ?? null,
});
