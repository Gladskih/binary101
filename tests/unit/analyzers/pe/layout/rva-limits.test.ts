import assert from "node:assert/strict";
import { test } from "node:test";
import { isRvaField, isRvaRangeInsideSizeOfImage }
  from "../../../../../analyzers/pe/layout/rva-limits.js";

void test("RVA fields accept both unsigned 32-bit boundaries", () => {
  // PE32/PE32+ RVA fields occupy four bytes.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
  assert.equal(isRvaField(0), true);
  assert.equal(isRvaField(0xffff_ffff), true);
});

for (const value of [-1, 0.5, NaN, Infinity, -Infinity, 0x1_0000_0000,
  Number.MAX_SAFE_INTEGER + 1]) {
  void test(`RVA fields reject ${value}`, () => {
    assert.equal(isRvaField(value), false);
  });
}

void test("Image ranges require a positive size and permit the exact image end", () => {
  assert.equal(isRvaRangeInsideSizeOfImage(0, 4, 4), true);
  assert.equal(isRvaRangeInsideSizeOfImage(1, 4, 4), false);
  assert.equal(isRvaRangeInsideSizeOfImage(0, 0, 4), false);
  assert.equal(isRvaRangeInsideSizeOfImage(-1, 4, 4), false);
  assert.equal(isRvaRangeInsideSizeOfImage(0, -1, 4), false);
  assert.equal(isRvaRangeInsideSizeOfImage(0, 4, NaN), false);
  // The exclusive RVA bound itself is not a valid DWORD SizeOfImage field.
  assert.equal(isRvaRangeInsideSizeOfImage(0xffff_fffc, 4, 0x1_0000_0000), false);
});
