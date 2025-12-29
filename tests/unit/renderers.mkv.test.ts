"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseForUi } from "../../analyzers/index.js";
import { renderMkv } from "../../renderers/index.js";
import { createMkvFile } from "../fixtures/mkv-base-fixtures.js";

void test("renderMkv renders Matroska and attachments", async () => {
  const result = await parseForUi(createMkvFile());
  assert.strictEqual(result.analyzer, "mkv");
  const html = renderMkv(result.parsed);
  assert.match(html, /Matroska/);
  assert.match(html, /Attachments/);
  assert.match(html, /cover\.jpg/);
});
