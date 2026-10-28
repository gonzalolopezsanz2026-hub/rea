import { mkdtemp, readlink, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  NativeFixtureRunner,
  nativeMachoTarget,
} from "../../tests/fixtures/nativeCommands.js";
import { NativeMacOSProvider } from "./NativeMacOSProvider.js";
import type { NativeCallTracer } from "./LldbCallTracer.js";
import { NativeCommandFailure } from "./CommandRunner.js";
import { err } from "../domain/result.js";

const tracer: NativeCallTracer = {
  trace: async () => {
    throw new Error("unexpected trace");
  },
  close: async () => ({ ok: true, value: null }),
};

describe("private otool operand lifecycle", () => {
  it("uses a private alias only for otool and removes it after all commands settle", async () => {
    const path = await mkdtemp(join(tmpdir(), "rea-macho-operand-test-"));
    const target = "/fixture/app(foo)";
    const calls: { tool: string; operand: string | undefined }[] = [];
    const fixture = new NativeFixtureRunner();
    const runner = {
      async run(tool: string, args: readonly string[]) {
        calls.push({ tool, operand: args.at(-1) });
        if (tool === "otool") expect(await readlink(args.at(-1)!)).toBe(target);
        return fixture.run(tool, args);
      },
    };
    const client = new NativeMacOSProvider(
      {},
      runner,
      "darwin",
      () => tracer,
      async () => ({
        path,
        close: async () => {
          await rm(path, { recursive: true, force: true });
        },
      }),
    ).createClient(nativeMachoTarget(target));
    try {
      const result = await client.execute("inspect_macho", {});
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("expected inspection result");
      expect(JSON.stringify(result.value.result)).toContain(
        join(path, "artifact.macho"),
      );
      expect(calls.find(({ tool }) => tool === "otool")?.operand).toBe(
        join(path, "artifact.macho"),
      );
      expect(
        calls
          .filter(({ tool }) => tool !== "otool")
          .every(({ operand }) => operand === target),
      ).toBe(true);
      await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await client.close();
      await rm(path, { recursive: true, force: true });
    }
  });

  it("retains the alias until command cleanup is confirmed", async () => {
    const path = await mkdtemp(join(tmpdir(), "rea-macho-operand-test-"));
    let unresolved = true;
    class Runner extends NativeFixtureRunner {
      async retryCleanup() {
        if (unresolved) throw new Error("command remains owned");
        return [];
      }
    }
    const client = new NativeMacOSProvider(
      {},
      new Runner(),
      "darwin",
      () => tracer,
      async () => ({
        path,
        close: async () => {
          await rm(path, { recursive: true, force: true });
        },
      }),
    ).createClient(nativeMachoTarget("/fixture/app(foo)"));
    try {
      const result = await client.execute("inspect_macho", {});
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected cleanup failure");
      expect(result.error.cleanupIncomplete).toBe(true);
      expect(result.error.partialObservation).toMatchObject({
        format: "mach-o-universal",
      });
      expect((await stat(path)).isDirectory()).toBe(true);
      expect((await client.close()).ok).toBe(false);
      expect((await stat(path)).isDirectory()).toBe(true);
      unresolved = false;
      expect((await client.close()).ok).toBe(true);
      expect(result.error.cleanupIncomplete).toBe(false);
      await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      unresolved = false;
      await client.close();
      await rm(path, { recursive: true, force: true });
    }
  });
});

describe("private otool operand cleanup", () => {
  it.each([false, true])(
    "preserves exact failed output with cleanup failure %s",
    async (cleanupFails) => {
      const path = await mkdtemp(join(tmpdir(), "rea-macho-operand-test-"));
      const message = `otool failed for ${join(path, "artifact.macho")}\n`;
      const fixture = new NativeFixtureRunner();
      const runner = {
        async run(tool: string, args: readonly string[]) {
          if (tool === "otool")
            return err(
              new NativeCommandFailure("otool", "nonzero-exit", 1, undefined, {
                stdout: "",
                stderr: message,
                stdoutBytes: 0,
                stderrBytes: Buffer.byteLength(message),
                exitCode: 1,
                signal: null,
                truncated: false,
              }),
            );
          return fixture.run(tool, args);
        },
      };
      let attempts = 0;
      const client = new NativeMacOSProvider(
        {},
        runner,
        "darwin",
        () => tracer,
        async () => ({
          path,
          close: async () => {
            if (cleanupFails && ++attempts === 1)
              throw new Error("fixture cleanup refusal");
            await rm(path, { recursive: true, force: true });
          },
        }),
      ).createClient(nativeMachoTarget("/fixture/app(foo)"));
      try {
        const result = await client.execute("inspect_macho", {});
        expect(result.ok).toBe(false);
        if (result.ok) throw new Error("expected native failure");
        expect(result.error.capturedOutput?.stderr).toBe(message);
        expect(result.error.cleanupIncomplete).toBe(cleanupFails);
        if (cleanupFails) {
          expect(result.error.cleanupResources).toContain(path);
          expect((await client.close()).ok).toBe(true);
          expect(result.error.cleanupIncomplete).toBe(false);
        }
      } finally {
        await client.close();
        await rm(path, { recursive: true, force: true });
      }
    },
  );

  it("retains a failed root cleanup and retries it on close", async () => {
    const path = await mkdtemp(join(tmpdir(), "rea-macho-operand-test-"));
    let attempts = 0;
    const client = new NativeMacOSProvider(
      {},
      new NativeFixtureRunner(),
      "darwin",
      () => tracer,
      async () => ({
        path,
        close: async () => {
          if (++attempts < 2) throw new Error("fixture cleanup refusal");
          await rm(path, { recursive: true, force: true });
        },
      }),
    ).createClient(nativeMachoTarget("/fixture/app(foo)"));
    try {
      const result = await client.execute("inspect_macho", {});
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected cleanup failure");
      expect(result.error.cleanupIncomplete).toBe(true);
      expect(result.error.cleanupResources).toContain(path);
      expect((await stat(path)).isDirectory()).toBe(true);
      expect((await client.close()).ok).toBe(true);
      expect(result.error.cleanupIncomplete).toBe(false);
    } finally {
      await client.close();
      await rm(path, { recursive: true, force: true });
    }
  });

  it("reports cancellation during final root cleanup", async () => {
    const path = await mkdtemp(join(tmpdir(), "rea-macho-operand-test-"));
    const controller = new AbortController();
    const client = new NativeMacOSProvider(
      {},
      new NativeFixtureRunner(),
      "darwin",
      () => tracer,
      async () => ({
        path,
        close: async () => {
          controller.abort("cancelled while removing alias");
          await rm(path, { recursive: true, force: true });
        },
      }),
    ).createClient(nativeMachoTarget("/fixture/app(foo)"));
    try {
      const result = await client.execute(
        "inspect_macho",
        {},
        { signal: controller.signal },
      );
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected cancellation");
      expect(result.error._tag).toBe("AnalysisCancelledError");
      expect(result.error.partialObservation).toMatchObject({
        format: "mach-o-universal",
      });
    } finally {
      await client.close();
      await rm(path, { recursive: true, force: true });
    }
  });
});
