import { expect, it } from "vitest";
import { graphForJavaScript } from "../../../tests/fixtures/javascriptSemanticGraph.js";
import { queryJavaScriptSemanticGraph } from "../../domain/javascript/javascriptSemanticQuery.js";
import { resolveJavaScriptSemanticQuerySeeds } from "../../domain/javascript/javascriptSemanticQueryIdentity.js";
import { javaScriptSemanticQueryInputSchema } from "../../domain/javascript/javascriptSemanticQuerySchemas.js";
import { parseJavaScriptSource } from "../../domain/javascript/javascriptSourceParser.js";
import { analyzeParsedJavaScriptSemanticsSteps } from "../../domain/javascript/javascriptSemanticAnalysis.js";
import { completeSemanticSteps } from "../../domain/javascript/javascriptSemanticTraversal.js";

const trace = (body: string) => {
  const graph = graphForJavaScript(
    `const base = "https://example.test"; ${body}`,
  );
  return queryJavaScriptSemanticGraph(
    graph,
    javaScriptSemanticQueryInputSchema.parse({
      seed: { kind: "literal", value: "https://example.test" },
      direction: "forward-influence",
    }),
  );
};

it.each([
  ["declaration", 'const url = base + "/x"; fetch(url);'],
  ["assignment", 'let url; url = base + "/x"; fetch(url);'],
  ["nested operator", 'const url = (base + "/x") + "/y"; fetch(url);'],
  ["call argument", 'fetch(base + "/x");'],
  ["template", "fetch(`${base}/x`);"],
])("follows transformed input to a %s without opt-in", (_name, body) => {
  const result = trace(body);
  expect(result.nodes.map((node) => node.label)).toContain("argument 0");
  expect(result.relations.some((edge) => edge.relation === "influences")).toBe(
    true,
  );
});

it("explains an unmodeled dynamic call result at the reached argument", () => {
  const result = trace('const url = wrap(base + "/x"); fetch(url);');
  expect(result.unknowns.map((unknown) => unknown.detail)).toContain(
    "The dynamic call's return dependency on this argument is unknown.",
  );
});

it.each([
  'const obj = { url: wrap(base + "/x") }; fetch(obj.url);',
  'function address() { return wrap(base + "/x"); }',
  'consume(wrap(base + "/x"));',
])("keeps nested dynamic call return influence unknown: %s", (body) => {
  const result = trace(body);
  expect(result.status).not.toBe("found");
  expect(result.unknowns.map((unknown) => unknown.detail)).toContain(
    "The dynamic call's return dependency on this argument is unknown.",
  );
});

it("does not report an unused dynamic call result as a missing value", () => {
  const result = trace('consume(base + "/x");');
  expect(
    result.unknowns.some(
      (unknown) =>
        unknown.detail ===
        "The dynamic call's return dependency on this argument is unknown.",
    ),
  ).toBe(false);
});

it("bounds operator production before graph admission and reports truncation", () => {
  const expressions = Array.from({ length: 500 }, () => "${base}").join("");
  const source = `const base = "value"; const value = \`${expressions}\`;`;
  const parsed = parseJavaScriptSource(source, "app.js");
  if (parsed === null) throw new Error("Expected parsed source");
  const ir = completeSemanticSteps(
    analyzeParsedJavaScriptSemanticsSteps(parsed, "import", 4),
  );
  expect(ir.expressionFlowsTruncated).toBe(true);
  expect(ir.expressionFlows.length).toBeLessThanOrEqual(4);
  expect(
    ir.expressionFlows.reduce((count, flow) => count + flow.operands.length, 0),
  ).toBeLessThanOrEqual(4);
  expect(ir.coverage).toMatchObject({ status: "partial", omittedCount: null });
  expect(graphForJavaScript(source, ir).coverage.truncated).toBe(true);
});

it("follows a transformed return expression", () => {
  const result = trace('function address() { return base + "/x"; }');
  expect(result.nodes.map((node) => node.label)).toContain("return");
});

it("does not treat a deferred callback body as an enclosing call argument value", () => {
  const graph = graphForJavaScript(
    'const base = "https://example.test"; consume(() => base + "/x");',
  );
  const base = graph.nodes.find(
    (node) => node.kind === "binding" && node.label === "base",
  );
  const argument = graph.nodes.find(
    (node) => node.kind === "expression" && node.label === "argument 0",
  );
  expect(base).toBeDefined();
  expect(argument).toBeDefined();
  const result = queryJavaScriptSemanticGraph(
    graph,
    javaScriptSemanticQueryInputSchema.parse({
      seed: { kind: "literal", value: "https://example.test" },
      direction: "forward-influence",
      include_ambiguous_dynamic_edges: true,
    }),
  );
  expect(result.nodes.map((node) => node.node_id)).not.toContain(
    argument?.node_id,
  );
});

it.each(['"/unique"', "`/unique`"])(
  "seeds an exact literal operand %s and reaches the receiving argument",
  (operand) => {
    const graph = graphForJavaScript(
      `const prefix = "root"; const path = prefix + ${operand}; fetch(path);`,
    );
    const result = queryJavaScriptSemanticGraph(
      graph,
      javaScriptSemanticQueryInputSchema.parse({
        seed: { kind: "literal", value: "/unique" },
        direction: "forward-influence",
      }),
    );
    expect(result.nodes.map((node) => node.label)).toContain("argument 0");
  },
);

it("marks a short-circuited operand as conditional without claiming alias identity", () => {
  const graph = graphForJavaScript(
    'const base = "unique"; const maybe = ready && base; fetch(maybe);',
  );
  const conditional = graph.relations.filter(
    (edge) =>
      edge.relation === "influences" && edge.properties.conditional === true,
  );
  expect(conditional).toHaveLength(1);
  expect(
    graph.nodes.find((node) => node.node_id === conditional[0]?.source_node_id)
      ?.label,
  ).toBe("base");
});

it("reports uncertainty on a read inside an unsupported operand", () => {
  const result = trace('const url = format(base) + "/x"; fetch(url);');
  expect(result.status).toBe("partial");
  expect(
    result.unknowns.some((unknown) =>
      unknown.detail.includes("unmodeled operator operand"),
    ),
  ).toBe(true);
});

it.each([
  'function answer() { return "return-only"; }',
  'const answer = () => "return-only";',
])("seeds a literal returned directly: %s", (source) => {
  const graph = graphForJavaScript(source);
  const result = queryJavaScriptSemanticGraph(
    graph,
    javaScriptSemanticQueryInputSchema.parse({
      seed: { kind: "literal", value: "return-only" },
      direction: "forward-influence",
    }),
  );
  expect(result.summary.total_seed_matches).toBeGreaterThan(0);
  expect(result.nodes.map((node) => node.label)).toContain("return");
});

it("marks a logical assignment's transformed input conditional", () => {
  const graph = graphForJavaScript(
    'const base = "unique"; let value; value ||= base + "/x";',
  );
  const conditional = graph.relations.find(
    (edge) =>
      edge.relation === "influences" &&
      edge.properties.conditional === true &&
      graph.nodes.find((node) => node.node_id === edge.target_node_id)
        ?.label === "value",
  );
  expect(conditional).toBeDefined();
});

it("keeps sequence side effects unknown instead of attributing earlier values directly", () => {
  const result = trace('const url = (touch(base), "fixed"); fetch(url);');
  expect(result.status).toBe("partial");
  expect(
    result.unknowns.some((unknown) =>
      unknown.detail.includes("unmodeled operator operand"),
    ),
  ).toBe(true);
});

it("seeds a direct argument at its occurrence and reaches the call", () => {
  const graph = graphForJavaScript('consume("only-direct");');
  const result = queryJavaScriptSemanticGraph(
    graph,
    javaScriptSemanticQueryInputSchema.parse({
      seed: { kind: "literal", value: "only-direct" },
      direction: "forward-influence",
    }),
  );
  expect(result.summary.total_seed_matches).toBe(1);
  expect(
    result.nodes.find((node) => node.node_id === result.seed_node_ids[0])
      ?.label,
  ).toBe("argument 0");
  expect(result.nodes.some((node) => node.kind === "call-site")).toBe(true);
});

it("keeps older call-site literal evidence searchable when argument literals are absent", () => {
  const graph = graphForJavaScript('consume("only-direct");');
  const legacy = {
    ...graph,
    nodes: graph.nodes.filter(
      (node) =>
        node.properties.literal_argument_call_site_node_id === undefined,
    ),
  };
  const seeds = resolveJavaScriptSemanticQuerySeeds(
    legacy,
    javaScriptSemanticQueryInputSchema.parse({
      seed: { kind: "literal", value: "only-direct" },
      direction: "forward-influence",
    }),
  );
  const call = graph.nodes.find((node) => node.kind === "call-site");
  expect(seeds).toEqual([call?.node_id]);
});

it("does not treat literals inside a spread or deferred callback as direct arguments", () => {
  const graph = graphForJavaScript(
    'consume(...["spread-only"], () => "deferred-only");',
  );
  for (const value of ["spread-only", "deferred-only"]) {
    const result = queryJavaScriptSemanticGraph(
      graph,
      javaScriptSemanticQueryInputSchema.parse({
        seed: { kind: "literal", value },
        direction: "forward-influence",
      }),
    );
    expect(
      result.nodes.filter(
        (node) =>
          node.properties.literal_argument_call_site_node_id !== undefined,
      ),
    ).toEqual([]);
  }
});

it.each([
  'const obj = { url: base + "/x" }; fetch(obj.url);',
  'const values = [base + "/x"]; fetch(values[0]);',
  'const url = wrap(base + "/x"); fetch(url);',
])("reports unknown when a consumer boundary is unmodeled: %s", (body) => {
  const result = trace(body);
  expect(result.status).not.toBe("found");
  expect(result.unknowns.length).toBeGreaterThan(0);
});
