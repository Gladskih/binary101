"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";
import { isPeRomOptionalHeader } from "../../analyzers/pe/optional-header-kind.js";
import { createPeRomFile } from "../fixtures/sample-files-pe.js";

void test("parsePe keeps PE ROM images visible without inventing Windows data directories", async () => {
  const result = await parsePe(createPeRomFile());

  assert.ok(result, "parsePe should return a parsed object for a PE ROM image");
  assert.ok(isPeRomOptionalHeader(result.opt));
  assert.deepStrictEqual(result.dirs, []);
  assert.deepStrictEqual(result.imports, { entries: [] });
  assert.strictEqual(result.loadcfg, null);
  assert.strictEqual(result.security, null);
  assert.strictEqual(result.iat, null);
  assert.strictEqual(result.entrySection?.name, ".text");
  assert.strictEqual(result.rvaToOff(0x1000), 0x200);
  assert.strictEqual(result.overlaySize, 0);
  assert.strictEqual(result.imageSizeMismatch, false);
});
