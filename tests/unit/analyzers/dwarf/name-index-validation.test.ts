import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfNameIndexUnit, validateDwarfNameIndex } from "../../../../analyzers/dwarf/name-index-validation.js";
import type { DwarfNameIndex, DwarfNameIndexEntry } from "../../../../analyzers/dwarf/name-index-types.js";
import { createListUnit, listAttribute } from "../../../fixtures/dwarf-lists-fixture.js";

const table = (): DwarfNameIndex => ({ offset: 0, format: 32, augmentation: "",
  compileUnits: [0n], localTypeUnits: [100n], foreignTypeUnits: [7n], buckets: [], names: [] });
const entry = (attributes: DwarfNameIndexEntry["attributes"]): DwarfNameIndexEntry => ({
  offset: 0, tag: 0x11, attributes
});
const units = () => [createListUnit(5), { ...createListUnit(5), offset: 100 },
  { ...createListUnit(5), offset: 200, typeSignature: 7n }];

void test("name indexes distinguish compile units, local TUs, and foreign TU signatures", () => {
  const source = units();
  const index = table();

  assert.equal(dwarfNameIndexUnit(index, entry([]), source), source[0]);
  assert.equal(dwarfNameIndexUnit(index, entry([listAttribute(1, 0x0b, 0n)]), source), source[0]);
  assert.equal(dwarfNameIndexUnit(index, entry([listAttribute(2, 0x0b, 0n)]), source), source[1]);
  assert.equal(dwarfNameIndexUnit(index, entry([listAttribute(2, 0x0b, 1n)]), source), source[2]);
  assert.equal(dwarfNameIndexUnit(index, entry([listAttribute(2, 0x0b, 2n)]), source), undefined);
  assert.equal(dwarfNameIndexUnit(index, entry([listAttribute(1, 0x0b, -1n)]), source), undefined);
  assert.equal(dwarfNameIndexUnit({ ...index, compileUnits: [0n, 100n] }, entry([]), source), undefined);
  assert.equal(dwarfNameIndexUnit(index, entry([]), []), undefined);
});

void test("name index validation checks tag, parent entry boundaries, CU references, and hash buckets", () => {
  const index = table();
  index.names = [{ name: { kind: "string", value: "first" }, hash: 0,
    entries: [entry([listAttribute(3, 0x13, 12n), listAttribute(4, 0x13, 99n), listAttribute(1, 0x0b, 9n)])] },
  { name: { kind: "string", value: "second" }, hash: 1, entries: [{ ...entry([listAttribute(3, 0x13, 12n)]), tag: 0x2e }] },
  { name: { kind: "string", value: "third" }, hash: 2, entries: [] }];
  index.buckets = [1, 2];
  const issues: string[] = [];

  validateDwarfNameIndex(index, [createListUnit(5)], issues);

  assert.match(issues.join(" "), /not contiguous/);
  assert.match(issues.join(" "), /indexed tag disagrees/);
  assert.match(issues.join(" "), /parent.*boundary/);
  assert.match(issues.join(" "), /invalid related compilation-unit/);
  assert.match(issues.join(" "), /missing compilation\/type unit/);
  validateDwarfNameIndex({ ...index, compileUnits: [] }, [], issues);
  assert.match(issues.join(" "), /no compilation units/);
});
