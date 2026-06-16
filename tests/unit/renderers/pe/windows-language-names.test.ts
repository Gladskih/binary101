"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { formatWindowsLanguageName } from "../../../../renderers/pe/windows-language-names.js";

void test("formatWindowsLanguageName renders common LANGIDs in human-readable form", () => {
  assert.strictEqual(formatWindowsLanguageName(1033), "American English (en-US, 0x0409)");
  assert.strictEqual(formatWindowsLanguageName(1031), "German (Germany) (de-DE, 0x0407)");
  assert.strictEqual(formatWindowsLanguageName(2057), "British English (en-GB, 0x0809)");
  assert.strictEqual(formatWindowsLanguageName(3082), "European Spanish (es-ES, 0x0c0a)");
  assert.strictEqual(formatWindowsLanguageName(1025), "Arabic (Saudi Arabia) (ar-SA, 0x0401)");
  assert.strictEqual(formatWindowsLanguageName(null), "-");
});
