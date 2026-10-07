import assert from "node:assert/strict";
import { test } from "node:test";
import { validateDwarfPackageUnits } from "../../../../analyzers/dwarf/package-unit-validation.js";
import type { DwarfPackageIndex } from "../../../../analyzers/dwarf/package-types.js";
import { createListUnit, listAttribute } from "../../../fixtures/dwarf-lists-fixture.js";

const table = (): DwarfPackageIndex => ({ sectionName: ".debug_cu_index", version: 5,
  slots: [{ signature: 2n, row: 1 }], columns: [1], rows: [[{ offset: 0, size: 4 }]] });
const unit = () => ({ ...createListUnit(5), sectionName: ".debug_info.dwo", dwoId: 2n });

void test("package unit validation matches the indexed signature, abbreviation offset and exact length", () => {
  const issues: string[] = [];
  validateDwarfPackageUnits([table()], [unit()], issues);
  validateDwarfPackageUnits([{ ...table(), columns: [] }], [], issues);
  assert.deepEqual(issues, []);
});

void test("package validation reports missing units and inconsistent signatures", () => {
  const missing: string[] = [];
  const signature: string[] = [];
  const noSlot: string[] = [];
  const noId: string[] = [];
  validateDwarfPackageUnits([table()], [], missing);
  validateDwarfPackageUnits([table()], [{ ...unit(), dwoId: 3n }], signature);
  validateDwarfPackageUnits([{ ...table(), slots: [] }], [unit()], noSlot);
  validateDwarfPackageUnits([table()], [{ ...createListUnit(5), sectionName: ".debug_info.dwo" }], noId);
  assert.match(missing.join(" "), /no decoded unit/);
  assert.match(signature.join(" "), /signature disagrees/);
  assert.match(noSlot.join(" "), /signature disagrees/);
  assert.match(noId.join(" "), /signature disagrees/);
});

void test("package unit encoding notices cover nonzero abbreviation offsets and both length formats", () => {
  const issues: string[] = [];
  const valid64: string[] = [];
  validateDwarfPackageUnits([table()], [{ ...unit(), abbreviationOffset: 1n, length: 1n }], issues);
  validateDwarfPackageUnits([{ ...table(), rows: [[{ offset: 0, size: 12 }]] }],
    [{ ...unit(), format: 64 }], valid64);
  assert.match(issues.join(" "), /nonzero abbreviation offset/);
  assert.match(issues.join(" "), /length disagrees/);
  assert.deepEqual(valid64, []);
});

void test("GNU compilation and type indexes use their respective unit identities", () => {
  const issues: string[] = [];
  validateDwarfPackageUnits([{ ...table(), version: 2 }], [
    { ...createListUnit(4, [listAttribute(0x2131, 7, 2n)]), sectionName: ".debug_info.dwo" }], issues);
  validateDwarfPackageUnits([{ ...table(), version: 2, sectionName: ".debug_tu_index", columns: [2] }],
    [{ ...unit(), sectionName: ".debug_types.dwo", typeSignature: 2n }], issues);
  assert.deepEqual(issues, []);
});

void test("GNU2 type and standard5 type signatures cannot bypass per-unit verification", () => {
  const gnu: string[] = [];
  const standard: string[] = [];
  validateDwarfPackageUnits([{ ...table(), version: 2, sectionName: ".debug_tu_index", columns: [2] }],
    [{ ...unit(), sectionName: ".debug_types.dwo", typeSignature: 3n }], gnu);
  validateDwarfPackageUnits([{ ...table(), sectionName: ".debug_tu_index" }],
    [{ ...unit(), typeSignature: 3n }], standard);
  assert.match(gnu.join(" "), /signature disagrees/);
  assert.match(standard.join(" "), /signature disagrees/);
});
