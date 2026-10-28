import { createHash } from "node:crypto";
import type { Stats } from "node:fs";
import { chmod, lstat } from "node:fs/promises";
import { extname, isAbsolute, join } from "node:path";
import { Readable } from "node:stream";
import { getHeapStatistics } from "node:v8";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  ArtifactResourceScope,
  type ArtifactResourceOwner,
} from "../artifacts/ArtifactResourceScope.js";
import { hashReadable } from "../artifacts/ArtifactHash.js";
import { DirectoryArtifactReader } from "../artifacts/DirectoryArtifactReader.js";
import {
  ArtifactPathRegistry,
  normalizeArtifactPath,
} from "../artifacts/ArtifactPaths.js";
import { SafeOutputTree } from "../artifacts/SafeOutputTree.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import {
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type { JvmDecompilationResult } from "../domain/jvm/jvmAnalysis.js";
import { hasZipSignature } from "../domain/zipPackageFormat.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  openRegularFile,
  RegularFileAdmissionFailure,
  sameRegularFileState,
} from "../filesystem/RegularFile.js";

const OPERATION = "decompile_jvm_artifact";
/** Reserve at most 1/32 of the V8 heap for each inventory and its JSON expansion. */
export const JVM_METADATA_BYTES = Math.floor(
  getHeapStatistics().heap_size_limit / 32,
);

export const checkJvmCancellation = (signal?: AbortSignal): void => {
  if (signal?.aborted)
    throw new AnalysisCancelledError(OPERATION, { cause: signal.reason });
};
export const jvmInputFailure = (
  field: string,
  message: string,
  cause?: unknown,
): AnalysisInputError =>
  new AnalysisInputError(OPERATION, { cause }, [
    { path: [field], reason: "invalid_value", message },
  ]);

/** Account for worst-case JSON escaping before retaining another inventory record. */
export class JvmMetadataBudget {
  #used = 0;
  add(...values: readonly string[]): void {
    this.#used +=
      512 + values.reduce((sum, value) => sum + value.length * 6, 0);
    if (this.#used > JVM_METADATA_BYTES)
      throw new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        "JVM inventory exceeds its heap-derived metadata budget",
        { metadata_bytes: JVM_METADATA_BYTES },
        {
          retryable: false,
          remediationAction: `The JVM metadata allowance is ${String(JVM_METADATA_BYTES)} bytes, derived as 1/32 of the V8 heap at REA startup. Set NODE_OPTIONS=--max-old-space-size=<MiB> to a larger Node.js heap and restart REA to raise it, or select a smaller complete artifact. Worker memory settings do not change this already captured allowance; do not truncate required input bytes.`,
        },
      );
  }
}

type FileIdentity = JvmDecompilationResult["target"];
export type JvmSnapshot = {
  readonly original: FileIdentity;
  readonly originalState: Stats;
  readonly snapshot: FileIdentity;
};

/** Hold the admitted descriptor until its stable bytes have been consumed. */
const withRegularFile = async <T>(
  scope: ArtifactResourceScope,
  path: string,
  signal: AbortSignal | undefined,
  consume: (handle: OwnedFileHandle) => Promise<T>,
): Promise<T> => {
  let owner: OwnedFileHandle;
  try {
    const source = await openRegularFile(path, { symlinks: "reject", signal });
    owner = new OwnedFileHandle(source.handle);
  } catch (cause: unknown) {
    if (cause instanceof RegularFileAdmissionFailure) {
      const released = await scope.release({
        kind: "file-handle",
        resource: path,
        handle: cause.owner,
      });
      if (released.kind === "failed")
        throw ArtifactReaderFailure.withCleanup(
          cause,
          ArtifactReaderFailure.cleanupObservation(released.cause, path),
        );
    }
    throw cause;
  }
  return useResource(
    scope,
    { kind: "file-handle", resource: path, handle: owner },
    () => consume(owner),
  );
};

/** Stream file fingerprints; never allocate input- or output-sized buffers. */
export const fingerprintJvmFile = async (
  scope: ArtifactResourceScope,
  path: string,
  signal?: AbortSignal,
) =>
  withRegularFile(scope, path, signal, async (owner) => {
    const before = await owner.handle.stat();
    const result = await hashReadable(
      owner.handle.createReadStream({ autoClose: false }),
      signal,
    );
    if (
      result.bytes !== before.size ||
      !sameRegularFileState(before, await owner.handle.stat()) ||
      !sameRegularFileState(before, await lstat(path))
    )
      throw new AnalysisArtifactChangedError(
        OPERATION,
        path,
        `File identity or content changed while reading: ${path}`,
      );
    return {
      path,
      sha256: result.sha256,
      bytes: result.bytes,
      prefix: result.prefix,
      state: before,
    };
  });

/** Validate ZIP entry names and CRCs before giving the snapshot to Vineflower. */
const validateArchive = async (
  scope: ArtifactResourceScope,
  path: string,
  signal?: AbortSignal,
): Promise<void> => {
  const reader = new ZipArtifactReader(path, "zip", JVM_METADATA_BYTES);
  await useResource(
    scope,
    { kind: "reader", resource: path, reader },
    async () => {
      const paths = new ArtifactPathRegistry();
      const budget = new JvmMetadataBudget();
      for await (const entry of reader.entries(signal)) {
        budget.add(entry.path);
        // Normalize only the safety/collision key; the archive snapshot keeps member spellings.
        paths.add(normalizeArtifactPath(entry.path), entry.kind);
        if (entry.kind === "symlink" || entry.encrypted)
          throw new ArtifactReaderFailure(
            "format",
            `JVM archive contains an unsupported symlink or encrypted entry: ${entry.path}`,
          );
        if (entry.kind === "file") {
          const digest = await hashReadable(
            await reader.open(entry, signal),
            signal,
          );
          if (digest.bytes !== entry.declaredSize)
            throw new ArtifactReaderFailure(
              "integrity",
              `Archive entry size changed: ${entry.path}`,
            );
        }
      }
    },
  );
};

export const snapshotJvmFile = async (
  scope: ArtifactResourceScope,
  tree: SafeOutputTree,
  selection: { path: string; name: string; dependency: boolean },
  signal?: AbortSignal,
): Promise<JvmSnapshot> => {
  const { path, name, dependency } = selection;
  if (!isAbsolute(path))
    throw jvmInputFailure(
      dependency ? "classpath" : "path",
      `Select an absolute regular JVM file: ${path}`,
    );
  const extension = extname(path).toLowerCase();
  if (
    !(dependency ? [".jar", ".class"] : [".jar", ".zip", ".class"]).includes(
      extension,
    )
  )
    throw new AnalysisUnsupportedTargetError(
      OPERATION,
      path,
      dependency
        ? "Classpath entries must be JAR or class files"
        : "Select a .class, .jar, or .zip file",
    );
  const original = await fingerprintJvmFile(scope, path, signal);
  const classHeader =
    original.prefix.length >= 10 &&
    original.prefix.readUInt32BE(0) === 0xcafebabe &&
    original.prefix.readUInt16BE(8) > 0;
  if (extension === ".class" ? !classHeader : !hasZipSignature(original.prefix))
    throw new AnalysisUnsupportedTargetError(
      OPERATION,
      path,
      "The file header does not match the selected JVM format",
    );
  const relativePath = `${name}${extension}`;
  await withRegularFile(scope, path, signal, async (owner) => {
    if (!sameRegularFileState(original.state, await owner.handle.stat()))
      throw new AnalysisArtifactChangedError(
        OPERATION,
        path,
        "Input changed before snapshot",
      );
    await tree.write(
      relativePath,
      owner.handle.createReadStream({ autoClose: false }),
      original,
      signal,
    );
    if (
      !sameRegularFileState(original.state, await owner.handle.stat()) ||
      !sameRegularFileState(original.state, await lstat(path))
    )
      throw new AnalysisArtifactChangedError(
        OPERATION,
        path,
        "Input changed while snapshotting",
      );
  });
  const snapshotPath = join(tree.outputRoot, relativePath);
  await chmod(snapshotPath, 0o400);
  if (extension !== ".class")
    await validateArchive(scope, snapshotPath, signal);
  return {
    original: { path, sha256: original.sha256, bytes: original.bytes },
    originalState: original.state,
    snapshot: {
      path: snapshotPath,
      sha256: original.sha256,
      bytes: original.bytes,
    },
  };
};

export const verifyJvmSnapshots = async (
  scope: ArtifactResourceScope,
  files: readonly JvmSnapshot[],
  signal?: AbortSignal,
): Promise<void> => {
  for (const file of files) {
    const original = await fingerprintJvmFile(
      scope,
      file.original.path,
      signal,
    );
    const snapshot = await fingerprintJvmFile(
      scope,
      file.snapshot.path,
      signal,
    );
    if (
      !sameRegularFileState(file.originalState, original.state) ||
      original.sha256 !== file.original.sha256 ||
      snapshot.sha256 !== file.snapshot.sha256
    )
      throw new AnalysisArtifactChangedError(
        OPERATION,
        file.original.path,
        "Original input or immutable snapshot changed during decompilation",
      );
  }
};

/** Exhaustively inventory generated Java files before publication; reject unsafe output. */
export const publishJvmSources = async (
  scope: ArtifactResourceScope,
  staging: { path: string; format: "zip" | "directory" },
  tree: SafeOutputTree,
  signal?: AbortSignal,
): Promise<JvmDecompilationResult["sources"]> => {
  const archive =
    staging.format === "zip"
      ? await fingerprintJvmFile(scope, staging.path, signal)
      : undefined;
  const reader =
    staging.format === "zip"
      ? new ZipArtifactReader(staging.path, "zip", JVM_METADATA_BYTES)
      : new DirectoryArtifactReader(staging.path);
  const sources: JvmDecompilationResult["sources"] = [];
  const budget = new JvmMetadataBudget();
  const paths = new ArtifactPathRegistry();
  await useResource(
    scope,
    { kind: "reader", resource: staging.path, reader },
    async () => {
      for await (const entry of reader.entries(signal)) {
        budget.add(entry.path, tree.outputRoot);
        const normalized = normalizeArtifactPath(entry.path);
        if (normalized !== entry.path.replace(/\/$/u, ""))
          throw new AnalysisOutputError(
            OPERATION,
            `Vineflower output path changes during normalization: ${entry.path}`,
          );
        paths.add(normalized, entry.kind);
        if (entry.kind !== "file" && entry.kind !== "directory")
          throw new AnalysisOutputError(
            OPERATION,
            `Vineflower produced a symlink or special entry: ${entry.path}`,
          );
        if (entry.encrypted)
          throw new AnalysisOutputError(
            OPERATION,
            `Vineflower produced an encrypted entry: ${entry.path}`,
          );
        if (entry.kind === "file" && entry.path.endsWith(".java")) {
          const digest = await hashReadable(
            await reader.open(entry, signal),
            signal,
          );
          const file = await tree.write(
            `sources/${entry.path}`,
            await reader.open(entry, signal),
            digest,
            signal,
          );
          sources.push({
            path: join(tree.outputRoot, file.relativePath),
            relative_path: file.relativePath,
            sha256: file.sha256,
            bytes: file.bytesWritten,
          });
        }
      }
    },
  );
  if (archive !== undefined) {
    const after = await fingerprintJvmFile(scope, staging.path, signal);
    if (
      after.sha256 !== archive.sha256 ||
      !sameRegularFileState(archive.state, after.state)
    )
      throw new AnalysisOutputError(
        OPERATION,
        "Vineflower output archive changed during publication",
      );
  }
  return sources.sort((a, b) =>
    a.relative_path.localeCompare(b.relative_path, "en"),
  );
};

export const writeJvmManifest = async (
  tree: SafeOutputTree,
  details: Omit<JvmDecompilationResult, "manifest">,
  signal?: AbortSignal,
): Promise<FileIdentity> => {
  const budget = new JvmMetadataBudget();
  budget.add(
    details.diagnostics.stdout,
    details.diagnostics.stderr,
    details.target.path,
    details.client.command,
  );
  for (const file of [...details.sources, ...details.dependencies])
    budget.add(
      file.path,
      "relative_path" in file ? String(file.relative_path) : "",
    );
  const bytes = Buffer.from(`${JSON.stringify(details, null, 2)}\n`);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const file = await tree.write(
    "manifest.json",
    Readable.from([bytes]),
    { sha256, bytes: bytes.length },
    signal,
  );
  return {
    path: join(tree.outputRoot, file.relativePath),
    sha256,
    bytes: file.bytesWritten,
  };
};

const useResource = async <T>(
  scope: ArtifactResourceScope,
  owner: ArtifactResourceOwner,
  consume: () => Promise<T>,
): Promise<T> => {
  let outcome: { ok: true; value: T } | { ok: false; cause: unknown };
  try {
    outcome = { ok: true, value: await consume() };
  } catch (cause: unknown) {
    outcome = { ok: false, cause };
  }
  const released = await scope.release(owner);
  if (released.kind === "failed")
    throw ArtifactReaderFailure.withCleanup(
      outcome.ok ? released.cause : outcome.cause,
      ArtifactReaderFailure.cleanupObservation(released.cause, owner.resource),
    );
  if (!outcome.ok) throw outcome.cause;
  return outcome.value;
};
