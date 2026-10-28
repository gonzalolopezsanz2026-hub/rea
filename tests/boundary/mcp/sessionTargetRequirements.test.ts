import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";

import { buildCapabilityInventory } from "../../../src/application/CapabilityInventory.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { expandToolAvailability } from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { zipWith } from "../../fixtures/apkSignature/v1SignatureBlock.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it("advertises closed-session address and explicit-path APK tools according to their actual prerequisites", async () => {
  const root = await createTestTempDirectory(
    "rea-session-target-requirements-",
  );
  const path = join(root, "unsigned.zip");
  await writeFile(path, await zipWith([{ name: "sample.txt", data: "hello" }]));
  const { call } = await connectLocalToolsMcp();
  const status = async () => {
    const reply = await call("binary_session", {});
    expect(reply.isError).not.toBe(true);
    const result = toolContract("binary_session").outputSchema.parse(
      reply.structuredContent,
    ).result;
    expect(result).toMatchObject({ open: false, cleanup_pending: false });
    return expandToolAvailability(result.tool_availability);
  };
  const availability = (
    tools: Awaited<ReturnType<typeof status>>,
    name: string,
  ) => {
    const entry = tools.find((tool) => tool.name === name);
    expect(entry, `missing ${name} in binary_session`).toBeDefined();
    return entry;
  };

  const before = await status();
  expect(availability(before, "get_navigation_context")).toMatchObject({
    available: false,
    reason: "target_required",
  });
  expect.soft(availability(before, "inspect_address_context")).toMatchObject({
    available: false,
    reason: "target_required",
  });
  const owningAvailability = buildCapabilityInventory(
    { open: false, capabilities: [] },
    { processCaptureEnabled: false },
  );
  expect(availability(before, "inspect_address_context")?.remediation).toBe(
    owningAvailability.find((tool) => tool.name === "inspect_address_context")
      ?.remediation,
  );
  expect.soft(availability(before, "inspect_apk_signature")).toMatchObject({
    available: true,
    reason: "available",
    remediation: null,
  });

  const address = await call("inspect_address_context", { address: "0x1000" });
  expect(address.isError).toBe(true);
  expect(parseMcpToolError(address)).toMatchObject({
    error: { code: "target_unavailable" },
  });
  const apk = await call("inspect_apk_signature", { path });
  expect(apk.isError, JSON.stringify(apk)).not.toBe(true);
  expect(apk.structuredContent).toMatchObject({
    operation: "inspect_analysis_view",
  });

  const after = await status();
  expect(availability(after, "inspect_address_context")).toMatchObject({
    available: false,
    reason: "target_required",
  });
  expect(availability(after, "inspect_apk_signature")).toMatchObject({
    available: true,
    reason: "available",
  });
});
