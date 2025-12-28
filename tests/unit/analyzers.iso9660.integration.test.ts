"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseForUi } from "../../analyzers/index.js";
import { createIso9660PrimaryFile } from "../fixtures/iso9660-fixtures.js";

void test("parseForUi returns iso9660 analyzer for ISO images", async () => {
  const file = createIso9660PrimaryFile();
  const { analyzer, parsed } = await parseForUi(file);
  assert.strictEqual(analyzer, "iso9660");
  assert.ok(parsed);
});

