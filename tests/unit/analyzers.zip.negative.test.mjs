"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseZip } from "../../analyzers/zip/index.js";
import { createZipWithBadCdOffset, createZipWithMissingZip64 } from "../fixtures/zip-fixtures.mjs";

test("parseZip handles central directory offset beyond file", async () => {
  const zip = await parseZip(createZipWithBadCdOffset());
  assert.ok(zip);
  assert.ok(zip.issues.some(issue => issue.toLowerCase().includes("zip64 locator")));
});

test("parseZip warns when ZIP64 locator is present but record missing", async () => {
  const zip = await parseZip(createZipWithMissingZip64());
  assert.strictEqual(zip, null);
});
