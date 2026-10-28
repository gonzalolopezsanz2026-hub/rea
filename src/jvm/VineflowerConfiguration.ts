import { constants } from "node:fs";
import { access, stat } from "node:fs/promises";
import { delimiter, isAbsolute, resolve } from "node:path";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";

export const VINEFLOWER_COMMAND_ENV = "REA_VINEFLOWER_COMMAND";
export type VineflowerCommand = {
  readonly command: string;
  readonly commandSource: "environment" | "path";
};

/** Resolve the selected local launcher without installs, downloads, or fallback overrides. */
export const resolveVineflowerCommand = async (
  environment: Readonly<Record<string, string | undefined>>,
  operation = "inspect_jvm_decompiler",
): Promise<VineflowerCommand> => {
  const configured = environment[VINEFLOWER_COMMAND_ENV];
  if (configured !== undefined && configured.trim() !== "") {
    if (!isAbsolute(configured))
      throw unavailable(
        operation,
        `${VINEFLOWER_COMMAND_ENV} must name an absolute executable path`,
      );
    try {
      if (!(await stat(configured)).isFile())
        throw new Error("Selected launcher is not a regular file");
      await access(configured, constants.X_OK);
    } catch (cause: unknown) {
      throw unavailable(
        operation,
        `Selected Vineflower executable is unavailable: ${configured}`,
        cause,
      );
    }
    return { command: configured, commandSource: "environment" };
  }
  for (const directory of (environment.PATH ?? "").split(delimiter)) {
    if (directory === "") continue;
    const path = resolve(
      directory,
      process.platform === "win32" ? "vineflower.exe" : "vineflower",
    );
    try {
      if (!(await stat(path)).isFile()) continue;
      await access(path, constants.X_OK);
      return { command: path, commandSource: "path" };
    } catch {
      /* Continue the caller's PATH search. */
    }
  }
  throw unavailable(
    operation,
    `Vineflower was not found on PATH. Install a local launcher and set ${VINEFLOWER_COMMAND_ENV} to its absolute path`,
  );
};

/** Reject unrelated executables instead of treating an arbitrary help line as a version. */
export const parseVineflowerVersion = (
  stdout: string,
  stderr: string,
  operation = "inspect_jvm_decompiler",
): string => {
  const match =
    /(?:^|\n)[^\r\n]*\bVineflower\s+(?:Decompiler\s+)?(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?)(?:\s|$)/iu.exec(
      `${stdout}\n${stderr}`,
    );
  if (match?.[1] === undefined)
    throw unavailable(
      operation,
      "The selected launcher did not report a Vineflower version in --help output",
    );
  return match[1];
};

const unavailable = (
  operation: string,
  reason: string,
  cause?: unknown,
): AnalysisCapabilityUnavailableError =>
  new AnalysisCapabilityUnavailableError("vineflower", operation, reason, {
    cause,
    userMessage: reason,
  });
