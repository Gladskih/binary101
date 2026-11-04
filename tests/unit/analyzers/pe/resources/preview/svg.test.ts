import assert from "node:assert/strict";
import { test } from "node:test";
import { addSvgTextPreview } from "../../../../../../analyzers/pe/resources/preview/svg.js";
import { parseManifestTestXmlDocument } from "../../../../../helpers/manifest-test-parser.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";

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
