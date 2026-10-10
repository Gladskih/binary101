import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNativeAotMethodGc } from "../../../../renderers/native-aot/method-gc.js";

void test("renders explained method GC statistics and escapes malformed-data warnings", () => {
  const html = renderNativeAotMethodGc({ methods: [], warnings: ["<truncated>"] });

  assert.match(html, /Methods with GC maps/);
  assert.match(html, /&lt;truncated>/);
  assert.doesNotMatch(html, /<truncated>/);
  assert.equal(renderNativeAotMethodGc(undefined), "");
  assert.doesNotMatch(renderNativeAotMethodGc({ methods: [], warnings: [] }), /<ul/);
});
