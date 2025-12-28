"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseIso9660 } from "../../analyzers/iso9660/index.js";
import { renderIso9660 } from "../../renderers/iso9660/index.js";
import { createIso9660PrimaryFile } from "../fixtures/iso9660-fixtures.js";

void test("renderIso9660 renders ISO overview and root directory", async () => {
  const file = createIso9660PrimaryFile();
  const parsed = await parseIso9660(file);
  assert.ok(parsed);
  const html = renderIso9660(parsed);
  assert.ok(html.includes("ISO-9660 overview"));
  assert.ok(html.includes("Primary Volume Descriptor"));
  assert.ok(html.includes("Root directory"));
  assert.ok(html.includes("TESTVOL"));
});

