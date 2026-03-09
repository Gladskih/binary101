"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseForUi } from "../../analyzers/parse-for-ui.js";
import { createTruncatedFatMachOBytes } from "../fixtures/macho-fixtures.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseForUi keeps truncated fat Mach-O wrappers visible", async () => {
  const parsed = await parseForUi(new MockFile(createTruncatedFatMachOBytes()));

  assert.equal(parsed.analyzer, "macho");
  assert.ok(parsed.parsed);
  assert.equal(parsed.parsed.kind, "fat");
  assert.match(parsed.parsed.issues[0] ?? "", /Fat header is truncated/i);
});
