"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { isPeRomParseResult, parsePe } from "../../analyzers/pe/index.js";
import { createPeRomFile } from "../fixtures/sample-files-pe.js";

void test("parsePe keeps PE ROM images visible without inventing Windows data directories", async () => {
  const result = await parsePe(createPeRomFile());

  assert.ok(result, "parsePe should return a parsed object for a PE ROM image");
  assert.ok(isPeRomParseResult(result));
  assert.deepStrictEqual(result.dirs, []);
  assert.ok(!("imports" in result));
  assert.ok(!("loadcfg" in result));
  assert.ok(!("security" in result));
  assert.ok(!("iat" in result));
  assert.strictEqual(result.entrySection?.name, ".text");
  assert.strictEqual(result.rvaToOff(0x1000), 0x200);
  assert.strictEqual(result.overlaySize, 0);
  assert.strictEqual(result.imageSizeMismatch, false);
});
