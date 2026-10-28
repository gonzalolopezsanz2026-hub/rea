import { join } from "node:path";
import { expect, it } from "vitest";
import { createMarkdownRenderer } from "vitepress";
import { parseFragment, type DefaultTreeAdapterTypes } from "parse5";

import { renderCliDocument } from "../../../src/cliOutput.js";
import { writeOrderedZip } from "../../fixtures/artifactEntryOrder.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { workspaceCliTest } from "../../support/cli/workspaceCliFixture.js";

it("retains nested facts in standalone Markdown table cells and mixed arrays", async () => {
  const value = [
    {
      details: { path: "alpha.txt" },
      entries: [{ path: "sub/beta.txt" }],
      mixed: ["selected", { nested: "caller|value" }],
    },
  ];
  const markdown = renderCliDocument(value, "md", false);
  const renderer = await createMarkdownRenderer(process.cwd(), {
    linkify: false,
  });
  const text = (node: DefaultTreeAdapterTypes.Node): string =>
    node.nodeName === "#text" && "value" in node
      ? node.value
      : "childNodes" in node
        ? node.childNodes.map(text).join("")
        : "";
  const rendered = text(parseFragment(renderer.render(markdown)));
  expect(rendered).toContain('{"path":"alpha.txt"}');
  expect(rendered).toContain('[{"path":"sub/beta.txt"}]');
  expect(rendered).toContain("caller|value");
  expect(rendered).not.toContain("[object Object]");
  const mixed = renderCliDocument(
    { mixed: [1, { path: "retained" }] },
    "md",
    false,
  );
  expect(text(parseFragment(renderer.render(mixed)))).toContain(
    '{"path":"retained"}',
  );
  expect(JSON.parse(renderCliDocument(value, "json", false))).toEqual(value);
});

workspaceCliTest(
  "preserves archive inventory facts through public Markdown and JSON output",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-markdown-archive-facts-");
    const archive = join(root, "fixture.zip");
    await writeOrderedZip(archive, ["alpha.txt", "sub/beta.txt"]);
    const markdown = await cli.run({
      arguments: ["inspect-artifact", archive, "--format", "md"],
    });
    const json = await cli.run({
      arguments: ["inspect-artifact", archive, "--json"],
    });
    expect(markdown.exitCode).toBe(0);
    expect(json.exitCode).toBe(0);
    for (const entry of ["alpha.txt", "sub/beta.txt"]) {
      expect(markdown.stdout).toContain(entry);
      expect(json.stdout).toContain(entry);
    }
    expect(markdown.stdout).not.toContain("[object Object]");
  },
);
