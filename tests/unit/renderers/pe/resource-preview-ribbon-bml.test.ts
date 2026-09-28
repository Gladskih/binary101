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
