import assert from "node:assert/strict";
import { test } from "node:test";
import { validateDwarfPackageIndex } from "../../../../analyzers/dwarf/package-index-validation.js";
import type { DwarfPackageIndex } from "../../../../analyzers/dwarf/package-types.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";

const index = (): DwarfPackageIndex => ({ sectionName: ".debug_cu_index", version: 5,
  slots: [{ signature: 2n, row: 1 }, { signature: 0n, row: 0 }], columns: [1, 3],
  rows: [[{ offset: 0, size: 8 }, { offset: 0, size: 8 }]] });
const validate = (table: DwarfPackageIndex) => {
  const issues: string[] = [];
  validateDwarfPackageIndex(table, dwarfMacroSources([
    { name: ".debug_info.dwo", bytes: new Array<number>(8).fill(0) },
    { name: ".debug_abbrev.dwo", bytes: new Array<number>(8).fill(0) }
  ]), issues);
  return issues;
};

void test("valid package indexes cover every row and accept contribution ranges ending at the section boundary", () => {
  assert.deepEqual(validate(index()), []);
  assert.deepEqual(validate({ sectionName: ".debug_cu_index", version: 5, slots: [], columns: [], rows: [] }), []);
});

void test("package hash probes use high signature bits and stop at the first empty slot", () => {
  const table = index();
  table.slots = [{ signature: 4n, row: 1 }, { signature: 0n, row: 0 },
    { signature: (2n << 32n) | 4n, row: 2 }, { signature: 0n, row: 0 }];
  table.rows.push(table.rows[0]!);
  assert.match(validate(table).join(" "), /unreachable/);
  table.slots[2] = { signature: 0n, row: 0 };
  table.slots[3] = { signature: (2n << 32n) | 4n, row: 2 };
  assert.deepEqual(validate(table), []);
});

void test("package indexes report duplicate signatures, repeated rows and nonzero unused slots", () => {
  const duplicate = index();
  duplicate.slots[1] = { signature: 2n, row: 1 };
  const unused = index();
  unused.slots[1] = { signature: 9n, row: 0 };
  assert.match(validate(duplicate).join(" "), /duplicate unit signature/);
  assert.match(validate(duplicate).join(" "), /repeated row index/);
  assert.match(validate(unused).join(" "), /unused signature slot/);
});

void test("package row slots cannot refer past the matrix or omit populated contribution rows", () => {
  const outside = index();
  outside.slots[0]!.row = 2;
  const omitted = index();
  omitted.slots[0] = { signature: 0n, row: 0 };
  assert.match(validate(outside).join(" "), /invalid or repeated row/);
  assert.match(validate(omitted).join(" "), /missing signature slots/);
});

void test("package slot counts validate power of two and the strict load factor", () => {
  const power = index();
  power.slots.push({ signature: 0n, row: 0 });
  const load = index();
  load.slots.pop();
  assert.match(validate(power).join(" "), /power of two or load factor/);
  assert.match(validate(load).join(" "), /power of two or load factor/);
});

void test("package contributions validate known columns, required columns and each section boundary", () => {
  const unknown = index();
  unknown.columns[0] = 99;
  const duplicate = index();
  duplicate.columns[0] = 3;
  const outside = index();
  outside.rows[0]![0]!.offset = 1;
  const missing = index();
  missing.columns[0] = 4;
  assert.match(validate(unknown).join(" "), /unknown or duplicate section/);
  assert.match(validate(duplicate).join(" "), /unknown or duplicate section/);
  assert.match(validate(duplicate).join(" "), /required information/);
  assert.match(validate(outside).join(" "), /outside its section/);
  assert.match(validate(missing).join(" "), /missing or outside/);
});

void test("empty contributions need no source and GNU type indexes require the type column", () => {
  const empty = index();
  empty.columns.push(4);
  empty.rows[0]!.push({ offset: 0, size: 0 });
  const types = index();
  types.version = 2;
  types.sectionName = ".debug_tu_index";
  types.columns[0] = 2;
  types.rows[0]![0]!.size = 0;
  assert.deepEqual(validate(empty), []);
  assert.deepEqual(validate(types), []);
});

void test("malformed non-power-of-two hash tables stop even when the probe repeats an occupied slot", () => {
  const table = index();
  table.slots = [{ signature: 0n, row: 1 }, { signature: 2n << 32n, row: 2 },
    { signature: 7n, row: 3 }];
  table.rows.push(table.rows[0]!, table.rows[0]!);
  assert.match(validate(table).join(" "), /unreachable/);
});
