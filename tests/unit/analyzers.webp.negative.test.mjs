"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWebp } from "../../analyzers/webp/index.js";

const buildWebp = bytes => ({
  arrayBuffer: async () => new Uint8Array(bytes).buffer,
  size: bytes.length
});

test("parseWebp returns null for short files", async () => {
  const webp = await parseWebp(buildWebp([0x52, 0x49]));
  assert.strictEqual(webp, null);
});
