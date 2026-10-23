import assert from "node:assert/strict";
import { test } from "node:test";
import { hllSymbolName, hllTypeName } from "../../../../renderers/pe/hll-kinds.js";

void test("HLL record labels keep their own namespace and unknown values", () => {
  assert.equal(hllSymbolName(4), "Stack variable");
  assert.equal(hllSymbolName(24), "External name mapping");
  assert.equal(hllSymbolName(255), "HLL symbol record 0xff");
  assert.equal(hllTypeName(0x40), "Class");
  assert.equal(hllTypeName(0x46), "Class member");
  assert.equal(hllTypeName(255), "HLL type record 0xff");
});
