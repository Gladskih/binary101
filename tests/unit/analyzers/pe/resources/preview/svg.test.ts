import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { addSvgTextPreview } from "../../../../../../analyzers/pe/resources/preview/svg.js";
import { parseManifestTestXmlDocument } from "../../../../../helpers/manifest-test-parser.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

void test("rejects long malformed transform lists without blocking SVG parsing", () => {
  // Isolate the CodeQL #14 regression so a synchronous regexp hang can be terminated.
  const child = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", `
    import assert from "node:assert/strict";
    import { addSvgTextPreview } from ${JSON.stringify(new URL(
    "../../../../../../analyzers/pe/resources/preview/svg.ts", import.meta.url).href)};
    import { parseManifestTestXmlDocument } from ${JSON.stringify(new URL(
    "../../../../../helpers/manifest-test-parser.ts", import.meta.url).href)};
    const transform = "scale(\\t) ".repeat(10000) + "!";
    const result = addSvgTextPreview('<svg><g transform="' + transform +
      '" style="transform:' + transform + '"/></svg>', parseManifestTestXmlDocument);
    assert.deepEqual(result?.preview?.vector?.nodes[0]?.attributes, []);
    assert.deepEqual(result?.issues, [
      "SVG preview omits attribute transform, style declarations."
    ]);
  `], { timeout: 10000, encoding: "utf8" });

  assert.equal(child.status, 0, child.error?.message ?? child.stderr);
});

void test("rebuilds a drawing from geometry and presentation attributes", () => {
  const result = addSvgTextPreview('<svg viewBox="-10 -20 100 200"><g transform="translate(1 2)">' +
    '<path d="M0 0 L10 20" fill="none" stroke="#ff0000"/></g></svg>', parseManifestTestXmlDocument);
  const vector = expectDefined(result?.preview?.vector);

  assert.deepEqual(vector.bounds, { x: -10, y: -20, width: 100, height: 200 });
  assert.equal(vector.nodes[0]?.children[0]?.tag, "path");
  assert.equal(result?.issues, undefined);
});

void test("omits active content, external references and URL paint servers", () => {
  const result = addSvgTextPreview('<svg width="100" height="100" onload="run()">' +
    '<script>run()</script><foreignObject><iframe src="https://example.invalid"/></foreignObject>' +
    '<image href="https://example.invalid/image.png"/><rect width="50" height="50" ' +
    'fill="url(https://example.invalid/paint)" style="stroke:blue;filter:url(#unsafe)"/></svg>',
  parseManifestTestXmlDocument);
  const vector = expectDefined(result?.preview?.vector);

  assert.deepEqual(vector.nodes.map(node => node.tag), ["rect"]);
  assert.deepEqual(vector.nodes[0]?.attributes, [
    { name: "width", value: "50" }, { name: "height", value: "50" }, { name: "stroke", value: "blue" }
  ]);
  assert.match(result?.issues?.join(" ") ?? "", /omits/);
});

void test("reports malformed XML, parser failures and finite fallback bounds", () => {
  assert.ok(addSvgTextPreview("<svg>", () => parseManifestTestXmlDocument("<parsererror/>"))?.issues?.length);
  assert.ok(addSvgTextPreview("<svg/>", () => { throw new Error("parser"); })?.issues?.length);
  assert.equal(addSvgTextPreview("<html/>", parseManifestTestXmlDocument), null);
});

void test("retains SVG mixed text order while omitting unsupported nodes and malformed attributes", () => {
  const result = addSvgTextPreview('<svg width="20px" height="30"><title>Title</title><desc>Description</desc>'+
    '<metadata>Data</metadata><text>A<tspan>B</tspan>C</text><rect x="NaN" width="10" style="bad;fill:red"/>'+
    '<!-- comment --></svg>',parseManifestTestXmlDocument);
  const vector = expectDefined(result?.preview?.vector);

  assert.deepEqual(vector.bounds,{x:0,y:0,width:20,height:30});
  assert.deepEqual(vector.nodes[0]?.children.map(node=>node.text),["A",null,"C"]);
  assert.deepEqual(vector.nodes[0]?.children[1]?.children.map(node=>node.text),["B"]);
  assert.match(result?.issues?.join(" ") ?? "",/attribute x.*style declarations/su);
});

for (const transform of [
  "matrix(1 0 0 1 0 0)", "translate(1 2)", "scale(2)", "rotate(45)", "skewX(1)", "skewY(2)",
  "translate(1)scale(2)", "translate(1) \t scale(2)", "scale(2)\t", "scale(\t)".repeat(10)
]) {
  void test(`retains allowed SVG transforms: ${JSON.stringify(transform)}`, () => {
    const result = addSvgTextPreview(`<svg><g transform="${transform}"/></svg>`,
      parseManifestTestXmlDocument);

    assert.equal(result?.issues, undefined);
    assert.deepEqual(result?.preview?.vector?.nodes[0]?.attributes,
      [{ name: "transform", value: transform.trim().replaceAll("\t", " ") }]);
  });
}

for (const transform of [
  "", " ", "scale()", "Scale(1)", "unknown(1)", "scale(1", "scale(1))", "scale((1))",
  "bad scale(1)", "scale(1) bad", "scale(1);rotate(2)",
  `${"scale(\t) ".repeat(10)}!`
]) {
  void test(`omits malformed SVG transforms: ${JSON.stringify(transform)}`, () => {
    const result = addSvgTextPreview(`<svg><g transform="${transform}"/></svg>`,
      parseManifestTestXmlDocument);

    assert.deepEqual(result?.preview?.vector?.nodes[0]?.attributes, []);
    assert.deepEqual(result?.issues, ["SVG preview omits attribute transform."]);
  });
}
