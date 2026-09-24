"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDynamicFunctionOverrides } from
  "../../../../renderers/pe/dynamic-function-overrides.js";

void test("renderDynamicFunctionOverrides shows function mappings and BDD nodes", () => {
  const html = renderDynamicFunctionOverrides({ functions: [{
    originalRva: 0x1010,
    bddOffset: 0,
    overridingRvas: [0x2010, 0x3010],
    baseRelocations: [{ pageRva: 0x1000, typeOffsets: [0x1010] }]
  }], bddInfos: [{ offset: 0, version: 1, nodes: [{ left: 0, right: 1, value: 2 }] }] });

  assert.match(html, /Original RVA/);
  assert.match(html, /0x00001010/);
  assert.match(html, /0x00002010, 0x00003010/);
  assert.match(html, /BDD \+0x00000000, v1, 1 node/);
  assert.match(html, /0x00001010.*0x00002010/s);
  assert.match(html, /<th>Left<\/th><th>Right<\/th><th>Value<\/th>/);
});

void test("renderLoadConfigDynamicRelocations includes decoded function overrides", async () => {
  const { renderLoadConfigDynamicRelocations } = await import(
    "../../../../renderers/pe/load-config-widgets.js"
  );
  const html = renderLoadConfigDynamicRelocations({ version: 1, dataSize: 40,
    entries: [{ kind: "v1", symbol: 7n, baseRelocSize: 32, availableBytes: 32,
      fixup: { functions: [{ originalRva: 0x1010, bddOffset: 0,
        overridingRvas: [0x2010], baseRelocations: [] }],
      bddInfos: [{ offset: 0, version: 1, nodes: [] }] } }] });

  assert.match(html, /Function override/);
  assert.match(html, /0x00001010/);
  assert.match(html, /0x00002010/);
});
