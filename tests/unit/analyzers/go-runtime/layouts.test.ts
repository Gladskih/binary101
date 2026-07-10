"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  findGoRuntimeLayout,
  SUPPORTED_GO_RUNTIME_LAYOUTS
} from "../../../../analyzers/go-runtime/layouts.js";

void test("supported Go runtime layouts explicitly cover current magic families", () => {
  // Official PCLnTab magic constants and corresponding runtime layouts:
  // https://github.com/golang/go/blob/go1.26.4/src/internal/abi/symtab.go
  assert.deepEqual(SUPPORTED_GO_RUNTIME_LAYOUTS.map(layout => [layout.id, layout.magic]), [
    ["go1.16-1.17", 0xffff_fffa],
    ["go1.18-1.19", 0xffff_fff0],
    ["go1.20+", 0xffff_fff1]
  ]);
  assert.equal(findGoRuntimeLayout(0xffff_fff1)?.functabFieldSize(8), 4);
  assert.equal(findGoRuntimeLayout(0xffff_fffa)?.functabFieldSize(8), 8);
  assert.equal(findGoRuntimeLayout(0xffff_fffb), null);
});
