"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAsf } from "../../analyzers/asf/index.js";
import { renderAsf } from "../../renderers/asf/index.js";
import { createSampleAsfFile } from "../fixtures/asf-fixtures.js";

void test("renderAsf outputs readable summary and fields", async () => {
  const file = createSampleAsfFile();
  const parsed = await parseAsf(file);
  const html = renderAsf(parsed);
  assert.match(html, /ASF \/ Windows Media/);
  assert.match(html, /Streams/);
  assert.match(html, /Codec list/);
  assert.match(html, /Windows Media Audio 9\.2/);
  assert.match(html, /Stream 1/);
  assert.match(html, /Frame size/);
  assert.match(html, /Extended content descriptors/);
  assert.match(html, /Album/);
});
