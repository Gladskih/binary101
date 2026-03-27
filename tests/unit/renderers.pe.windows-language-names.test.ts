"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { formatWindowsLanguageName } from "../../renderers/pe/windows-language-names.js";

void test("formatWindowsLanguageName renders common LANGIDs in human-readable form", () => {
  assert.strictEqual(formatWindowsLanguageName(1033), "English (United States) (0x0409)");
  assert.strictEqual(formatWindowsLanguageName(1031), "German (Germany) (0x0407)");
  assert.strictEqual(formatWindowsLanguageName(2057), "English (United Kingdom) (0x0809)");
  assert.strictEqual(formatWindowsLanguageName(3082), "Spanish (Spain) (0x0c0a)");
  assert.strictEqual(formatWindowsLanguageName(null), "-");
});
