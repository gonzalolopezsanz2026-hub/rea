import { Cli } from "incur";
import { afterEach, expect, it, vi } from "vitest";
import { createAnalysisExecution } from "../../src/application/AnalysisProvider.js";
import type { JvmAnalysisPort } from "../../src/application/jvm/JvmAnalysisPort.js";
import { registerJvmCommands } from "../../src/cli/jvmCommands.js";
import { AnalysisOutputError } from "../../src/domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../src/domain/providerCleanupError.js";
import { err, ok } from "../../src/domain/result.js";
import { silentLogger } from "../../src/logger.js";

const host = vi.hoisted(() => ({
  listeners: new Map<string, () => void>(),
  exitCode: undefined as number | string | null | undefined,
  on(signal: string, listener: () => void) {
    this.listeners.set(signal, listener);
  },
  off(signal: string, listener: () => void) {
    if (this.listeners.get(signal) === listener) this.listeners.delete(signal);
  },
}));

vi.mock("../../src/cli/commandCancellation.js", async (importOriginal) => {
  const original =
    await importOriginal<
      typeof import("../../src/cli/commandCancellation.js")
    >();
  return {
    ...original,
    withCommandCancellation: <Value>(
      operation: (signal: AbortSignal) => Promise<Value>,
    ) => original.withCommandCancellation(operation, host),
  };
});

const originalExitCode = process.exitCode;
afterEach(() => {
  process.exitCode = originalExitCode;
  host.listeners.clear();
  host.exitCode = undefined;
});

it.each([false, true])(
  "retains %s operation outcome when final CLI cleanup also fails",
  async (succeeded) => {
    const operation = "inspect_jvm_decompiler";
    const captured = {
      stdout: "",
      stderr: "invalid provider output",
      exit_code: 7,
      truncated: false,
    };
    const client = {
      command: "/tools/vineflower",
      command_source: "environment",
      version: "1.12.0",
    };
    const provider: JvmAnalysisPort = {
      async inspectAvailability() {
        return {
          status: "available",
          code: null,
          reason: null,
          diagnostics: {},
        };
      },
      async execute() {
        return succeeded
          ? ok(
              createAnalysisExecution(
                { client },
                { id: "vineflower", name: "Vineflower", version: "1.12.0" },
              ),
            )
          : err(
              new AnalysisOutputError(operation, "primary failure", {
                capturedOutput: captured,
              }),
            );
      },
      async close() {
        throw new ProviderCleanupError(
          "vineflower",
          ["/owned/workspace"],
          { reason: "close failed" },
          { operation },
        );
      },
    };
    const cli = Cli.create("rea-jvm-lifecycle", { sync: false });
    registerJvmCommands(cli, silentLogger, {}, provider);
    let stdout = "";
    await cli.serve(["inspect-jvm-decompiler", "--json"], {
      env: {},
      stdout: (text) => {
        stdout += text;
      },
      exit: () => undefined,
    });
    const projected: unknown = JSON.parse(stdout);
    expect(projected).toMatchObject({
      code: "cleanup_incomplete",
      details: { resources: ["/owned/workspace"] },
    });
    if (succeeded)
      expect(projected).toMatchObject({
        details: {
          partial_observation: { operation, normalized_result: { client } },
        },
      });
    else
      expect(projected).toMatchObject({
        details: { captured_output: captured },
      });
  },
);

it("retains the completed JVM observation when interrupted during final close", async () => {
  const client = {
    command: "/tools/vineflower",
    command_source: "environment",
    version: "1.12.0",
  };
  let closed = false;
  const provider: JvmAnalysisPort = {
    async inspectAvailability() {
      return { status: "available", code: null, reason: null, diagnostics: {} };
    },
    async execute() {
      return ok(
        createAnalysisExecution(
          { client },
          { id: "vineflower", name: "Vineflower", version: "1.12.0" },
        ),
      );
    },
    async close() {
      host.listeners.get("SIGINT")?.();
      closed = true;
    },
  };
  const cli = Cli.create("rea-jvm-finalization", { sync: false });
  registerJvmCommands(cli, silentLogger, {}, provider);
  let stdout = "";
  await cli.serve(["inspect-jvm-decompiler", "--json"], {
    env: {},
    stdout: (text) => {
      stdout += text;
    },
    exit: () => undefined,
  });
  expect(closed).toBe(true);
  expect(host.exitCode).toBe(130);
  expect(host.listeners.size).toBe(0);
  expect(JSON.parse(stdout)).toMatchObject({
    code: "cancelled",
    details: {
      partial_observation: {
        operation: "inspect_jvm_decompiler",
        normalized_result: { client },
      },
    },
  });
});
