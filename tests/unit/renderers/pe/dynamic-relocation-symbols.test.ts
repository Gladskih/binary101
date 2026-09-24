"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getDynamicRelocationSymbolName } from
  "../../../../renderers/pe/dynamic-relocation-symbols.js";

void test("getDynamicRelocationSymbolName identifies Windows SDK symbols", () => {
  // winnt.h defines IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE as 7.
  assert.equal(getDynamicRelocationSymbolName(7n), "FUNCTION_OVERRIDE");
  assert.equal(getDynamicRelocationSymbolName(0xffffn), "UNKNOWN");
});
