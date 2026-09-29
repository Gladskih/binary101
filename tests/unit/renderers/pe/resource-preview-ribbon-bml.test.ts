import assert from "node:assert/strict";
import { test } from "node:test";
import { renderRibbonBmlPreview } from "../../../../renderers/pe/resource-preview-ribbon-bml.js";

void test("renders compiled Ribbon commands and escapes internal strings", () => {
  const html = renderRibbonBmlPreview({ strings: ["<Small>"], commands: [
    { id: 100, resources: [
      { kind: "Label <title>", resourceId: 200 },
      { kind: "Small image", resourceId: 201, minimumDpi: 96 }
    ] }, { id: 101, resources: [] }
  ] });
  assert.match(html, /2 commands, 1 internal strings/);
  assert.match(html, /&lt;Small>/);
  assert.match(html, /Label &lt;title>/);
  assert.match(html, /201<\/td><td class="peNumeric">96/);
  assert.match(html, /101<\/td><td>–/);
});

void test("renders a compiled Ribbon control hierarchy", () => {
  const html = renderRibbonBmlPreview({ strings: [], commands: [], tree: {
    kind: "Type 36", commandId: null, children: [{ kind: "<Button>",
      commandId: 42, children: [] }]
  } });
  assert.match(html, /Control hierarchy/);
  assert.match(html, /<th>Level<\/th>/);
  assert.match(html, /&lt;Button>/);
  assert.match(html, /42/);
  assert.doesNotMatch(html, /<Button>/);
});

void test("limits very large control tables", () => {
  const html = renderRibbonBmlPreview({ strings: [], commands: [], tree: {
    kind: "Root", commandId: null,
    children: Array.from({ length: 1001 }, () =>
      ({ kind: "Button", commandId: null, children: [] }))
  } });
  assert.match(html, /Only the first 1000 controls are shown/);
});
