"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { crc32, finishCrc32, updateCrc32 } from "../../../analyzers/crc32.js";

void test("crc32 matches the standard check value and supports incremental input", () => {
  const bytes = new TextEncoder().encode("123456789");
  const firstState = updateCrc32(0xffffffff, bytes.subarray(0, 4));

  assert.equal(crc32(bytes), 0xcbf43926);
  assert.equal(finishCrc32(updateCrc32(firstState, bytes.subarray(4))), 0xcbf43926);
});
