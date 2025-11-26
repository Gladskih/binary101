"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWebp } from "../../analyzers/webp/index.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseWebp returns null for short files", async () => {
  const webp = await parseWebp(new MockFile(new Uint8Array([0x52, 0x49]), "short.webp", "image/webp"));
  assert.strictEqual(webp, null);
});
