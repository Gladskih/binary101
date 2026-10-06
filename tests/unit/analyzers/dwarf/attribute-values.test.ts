import assert from "node:assert/strict";
import { test } from "node:test";
import {
  dwarfAttributeValue, dwarfNumericValue, dwarfStringValue, dwarfUnitRoot
} from "../../../../analyzers/dwarf/attribute-values.js";
import { createListUnit, listAttribute } from "../../../fixtures/dwarf-lists-fixture.js";

void test("attribute values distinguish numbers, strings, flags, and missing values", () => {
  assert.equal(dwarfNumericValue({ kind: "unsigned", value: 7n }), 7n);
  assert.equal(dwarfNumericValue({ kind: "signed", value: -7n }), -7n);
  assert.equal(dwarfNumericValue({ kind: "flag", value: true }), null);
  assert.equal(dwarfNumericValue(undefined), null);
  assert.equal(dwarfStringValue({ kind: "string", value: "name" }), "name");
  assert.equal(dwarfStringValue({ kind: "unsigned", value: 7n }), null);
  assert.equal(dwarfStringValue(undefined), null);
  assert.equal(dwarfAttributeValue(undefined, 0x03), undefined);
});

void test("unit metadata omits invalid language numbers and negative statement list offsets", () => {
  const unit = createListUnit(5, [listAttribute(0x13, 0x0d, -1n), listAttribute(0x10, 0x17, -1n)]);

  assert.deepEqual(dwarfUnitRoot(unit), { tag: 0x11 });
  assert.equal(dwarfUnitRoot(undefined), null);
  assert.equal(dwarfUnitRoot({ ...unit, dies: [] }), null);
  unit.dies[0]!.attributes[0]!.value = { kind: "unsigned", value: 1n << 64n };
  assert.deepEqual(dwarfUnitRoot(unit), { tag: 0x11 });
});
