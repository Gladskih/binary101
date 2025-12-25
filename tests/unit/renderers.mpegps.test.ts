"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseMpegPs } from "../../analyzers/mpegps/index.js";
import { createMpegPsFile } from "../fixtures/mpegps-fixtures.js";
import { renderMpegPs } from "../../renderers/mpegps/index.js";

void test("renderMpegPs renders an overview and stream summaries", async () => {
  const parsed = await parseMpegPs(createMpegPsFile());
  assert.ok(parsed);

  const html = renderMpegPs(parsed);
  assert.match(html, /MPEG Program Stream/i);
  assert.match(html, /PES/i);
  assert.match(html, /0xe0/i);
});
