"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseForUi } from "../../analyzers/index.js";
import type { WebmParseResult } from "../../analyzers/webm/types.js";
import { createWebmWithTags } from "../fixtures/webm-tags-fixtures.js";

void test("parseForUi surfaces tags with names and values", async () => {
  const file = createWebmWithTags();
  const result = await parseForUi(file);
  assert.equal(result.analyzer, "webm");
  const parsed = result.parsed as WebmParseResult;
  const segment = parsed.segment;
  assert.ok(segment && segment.tags);
  assert.equal(segment?.tags?.length, 1);
  const [tag] = segment?.tags ?? [];
  assert.ok(tag);
  assert.equal(tag?.name, "TITLE");
  assert.equal(tag?.value, "Example title");
  assert.equal(tag?.language, "eng");
  assert.equal(tag?.targetTrackUid, 1);
  assert.equal(tag?.defaultFlag, true);
});
