"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  RESOURCE_DIRECTORY_HIGH_BIT,
  RESOURCE_DIRECTORY_OFFSET_MASK
} from "../../analyzers/pe/resources/directory-format.js";

void test("resource directory constants match the PE resource-directory structures", () => {
  // Microsoft PE/COFF, ".rsrc Section": IMAGE_RESOURCE_DIRECTORY is 16 bytes.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  assert.strictEqual(IMAGE_RESOURCE_DIRECTORY_SIZE, 16);
  // Microsoft PE/COFF, ".rsrc Section": IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  assert.strictEqual(IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE, 8);
  // Microsoft PE/COFF, "Resource Directory Entries": the high bit is the flag bit.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  assert.strictEqual(RESOURCE_DIRECTORY_HIGH_BIT, 0x80000000);
  assert.strictEqual(RESOURCE_DIRECTORY_OFFSET_MASK, 0x7fffffff);
});
