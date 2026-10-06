import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfAttributeMeaning } from "../../../../renderers/dwarf/attribute-meanings.js";

void test("attribute meanings decode source-level enums with a numeric fallback for extensions", () => {
  // DWARF 5 7.8/7.9/7.14: signed encoding, C++ language, private accessibility.
  assert.equal(dwarfAttributeMeaning(0x3e, 5n), "signed integer");
  assert.equal(dwarfAttributeMeaning(0x13, 4n), "C++");
  assert.equal(dwarfAttributeMeaning(0x32, 3n), "private");
  assert.equal(dwarfAttributeMeaning(0x32, 99n), "99");
  assert.equal(dwarfAttributeMeaning(0x1234, 1n), "1");
  assert.equal(dwarfAttributeMeaning(0x13, -1n), "-1");
  assert.equal(dwarfAttributeMeaning(0x13, 1n << 60n), (1n << 60n).toString());
});
