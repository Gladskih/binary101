"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeGfidsFlags,
  GFIDS_FLAG_MASK
} from "../../../../../analyzers/pe/load-config/gfids.js";

void test("decodeGfidsFlags decodes every Windows SDK GFIDS flag", () => {
  assert.deepEqual(decodeGfidsFlags(0x0f), [
    "FID_SUPPRESSED",
    "EXPORT_SUPPRESSED",
    "FID_LANGEXCPTHANDLER",
    "FID_XFG"
  ]);
  assert.deepEqual(decodeGfidsFlags(0x80), []);
  assert.equal(GFIDS_FLAG_MASK, 0x0f);
});
