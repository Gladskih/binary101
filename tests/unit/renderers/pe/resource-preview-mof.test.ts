import assert from "node:assert/strict";
import { test } from "node:test";
import { renderBinaryMofPreview } from "../../../../renderers/pe/resource-preview-mof.js";

void test("renders MOF class details in a table and escapes untrusted text", () => {
  const html = renderBinaryMofPreview({ classes: [{ name: "<Class>", guid: "{guid}",
    namespace: "root/test", superclass: null,
    properties: [{ name: "<Property>", type: "UInt32" }], methods: ["<Method>"] }],
  flavorCount: 2 });

  assert.match(html, /<table/);
  assert.match(html, /<th>GUID<\/th>/);
  assert.match(html, /1 classes, 2 qualifier flavors/);
  assert.match(html, /&lt;Class>/);
  assert.match(html, /&lt;Property>: UInt32/);
  assert.match(html, /&lt;Method>/);
  assert.doesNotMatch(html, /<Class>|<Method>/);
});

void test("renders empty classes and missing optional metadata", () => {
  const empty = renderBinaryMofPreview({ classes: [], flavorCount: 0 });
  const unnamed = renderBinaryMofPreview({ classes: [{ name: null, guid: null,
    namespace: null, superclass: null, properties: [], methods: [] }], flavorCount: 0 });
  assert.match(empty, /0 classes/);
  assert.match(unnamed, /<td class="mono">–<\/td>/);
  assert.doesNotMatch(unnamed, /undefined|null/);
});
