import assert from "node:assert/strict";
import { test } from "node:test";
import { validateDwarfLines } from "../../../../analyzers/dwarf/line-validation.js";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { createDwarfSemanticFixture } from "../../../fixtures/dwarf-semantic-fixture.js";

void test("line validation checks file/directory references and statement-list boundaries", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const program = dwarf.linePrograms[0]!;
  const issues: string[] = [];
  program.files[0]!.directoryIndex = 99n;
  program.rows[0]!.file = 99n;
  program.rows[0]!.line = -1n;
  program.rows[1]!.address = program.rows[0]!.address - 1n;

  validateDwarfLines(dwarf.linePrograms, dwarf.units, issues);

  assert.match(issues.join(" "), /missing directory 99/);
  assert.match(issues.join(" "), /missing source file 99/);
  assert.match(issues.join(" "), /negative source line -1/);
  assert.match(issues.join(" "), /move backwards/);
  const missing: string[] = [];
  validateDwarfLines([], dwarf.units, missing);
  assert.match(missing.join(" "), /statement list 0/);
});

void test("line sequences reset validation and compare operation indexes at the same address", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const program = dwarf.linePrograms[0]!;
  const issues: string[] = [];
  const first = program.rows[0]!;
  first.operationIndex = 1n;
  program.rows = [first, { ...first, operationIndex: 0n },
    { ...first, endSequence: true, file: 999n }, { ...first, address: 0n }];
  program.files[0]!.directoryIndex = 0n;

  validateDwarfLines(dwarf.linePrograms, [], issues);

  assert.equal(issues.length, 1);
  assert.match(issues[0]!, /move backwards/);
});

void test("DWARF 5 line tables validate zero-based files and directories", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const program = dwarf.linePrograms[0]!;
  program.version = 5;
  program.rows = [{ ...program.rows[0]!, file: 0n }];
  program.files[0]!.directoryIndex = null;
  const issues: string[] = [];

  validateDwarfLines(dwarf.linePrograms, dwarf.units, issues);

  assert.deepEqual(issues, []);
  program.rows[0]!.file = -1n;
  program.files[0]!.directoryIndex = -1n;
  validateDwarfLines(dwarf.linePrograms, [], issues);
  assert.equal(issues.length, 2);
});
