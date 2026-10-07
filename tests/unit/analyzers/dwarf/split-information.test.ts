import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { dwarfUnitRoot } from "../../../../analyzers/dwarf/attribute-values.js";
import { createDwarfDieIndex, resolveDwarfReference } from "../../../../analyzers/dwarf/references.js";
import { dwarfLineProgramForUnit } from "../../../../analyzers/dwarf/unit-sections.js";
import { createDwarfSplitFixture, createDwarfPackageFixture, createDwarfSplitContents,
  splitSkeleton, splitSkeletonAbbreviations, splitTypeInformation } from "../../../fixtures/dwarf-split-fixture.js";
import { createDwarfSectionFile } from "../../../fixtures/dwarf-semantic-fixture.js";
import { concatenateBytes, encodeUint32, encodeUint64 } from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("standalone DWARF 5 DWO resolves implicit string bases using the table's DWARF64 width", async () => {
  const fixture = createDwarfSplitFixture();
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(dwarfUnitRoot(parsed.units[0])?.name, "main.c");
  assert.equal(parsed.units[0]?.dies[2]?.attributes[0]?.value.kind, "string");
  assert.deepEqual(parsed.macros![0]!.entries[1]!.operands[1], { kind: "string", value: "COUNT 42" });
  assert.equal(dwarfLineProgramForUnit(parsed, parsed.units[0]!)?.files[0]?.path, "main.c");
  assert.deepEqual(parsed.issues, []);
});

void test("GNU v4 DWO resolves its headerless string table and legacy identity", async () => {
  const fixture = createDwarfSplitFixture(4);
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(dwarfUnitRoot(parsed.units[0])?.name, "main.c");
  assert.equal(parsed.units[0]?.dies.length, 3);
  assert.deepEqual(parsed.issues, []);
});

void test("DWP contributions isolate abbreviation, string, macro and line tables for multiple units", async () => {
  const fixture = createDwarfPackageFixture();
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);
  const second = parsed.units[1]!;
  const index = createDwarfDieIndex(parsed.units);
  const record = index.records.find(record => record.unit === second && record.die.tag === 0x2e)!;

  assert.deepEqual(parsed.units.map(unit => dwarfUnitRoot(unit)?.name), ["main.c", "other.c"]);
  assert.equal(second.dies[2]?.attributes[0]?.value.kind, "string");
  assert.ok(second.offset > 0);
  assert.equal(second.dies[1]?.parentOffset, second.dies[0]?.offset);
  assert.equal(resolveDwarfReference(index, record, record.die.attributes[1])?.die, second.dies[1]);
  assert.equal(dwarfLineProgramForUnit(parsed, second), parsed.linePrograms[1]);
  assert.deepEqual(parsed.macros?.map(macro => macro.entries[1]?.operands[1]),
    [{ kind: "string", value: "COUNT 42" }, { kind: "string", value: "COUNT 42" }]);
  assert.equal(parsed.packageIndexes?.length, 1);
  assert.equal(parsed.macros![1]!.entries[1]!.offset, parsed.macros![1]!.offset + 10);
  assert.deepEqual(parsed.issues, []);
});

void test("split skeleton filenames are reported when external information is absent", async () => {
  const fixture = createDwarfSectionFile([
    { name: ".debug_info", bytes: splitSkeleton() },
    { name: ".debug_abbrev", bytes: splitSkeletonAbbreviations() }
  ]);
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.match(parsed.issues.join(" "), /main.dwo.*not present/);
});

void test("a matching split unit in the same file satisfies its skeleton reference", async () => {
  const fixture = createDwarfSectionFile([
    { name: ".debug_info", bytes: splitSkeleton() },
    { name: ".debug_abbrev", bytes: splitSkeletonAbbreviations() }, ...createDwarfSplitContents()
  ]);
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(parsed.units.length, 2);
  assert.deepEqual(parsed.issues, []);
});

void test("legacy split type sections decode their signature and type DIE header", async () => {
  const fixture = createDwarfSectionFile([
    { name: ".debug_types.dwo", bytes: splitTypeInformation() },
    { name: ".debug_abbrev.dwo", bytes: [1, 0x41, 0, 0, 0, 0] }
  ]);
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(parsed.units[0]?.typeSignature, 7n);
  assert.equal(parsed.units[0]?.typeOffset, 23n);
  assert.equal(parsed.units[0]?.dies[0]?.tag, 0x41);
  assert.deepEqual(parsed.issues, []);
});

void test("GNU package type indexes isolate and decode their legacy type-unit contribution", async () => {
  const information = splitTypeInformation();
  const abbreviations = [1, 0x41, 0, 0, 0, 0];
  const fixture = createDwarfSectionFile([
    { name: ".debug_tu_index", bytes: concatenateBytes([2, 2, 1, 2].flatMap(encodeUint32),
      [0n, 7n].flatMap(encodeUint64),
      [0, 1, 2, 3, 0, 0, information.length, abbreviations.length].flatMap(encodeUint32)) },
    { name: ".debug_types.dwo", bytes: information },
    { name: ".debug_abbrev.dwo", bytes: abbreviations }
  ]);
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);
  assert.equal(parsed.units[0]?.typeSignature, 7n);
  assert.equal(parsed.packageIndexes?.[0]?.sectionName, ".debug_tu_index");
  assert.deepEqual(parsed.issues, []);
});

void test("DWP integration reports a mismatched indexed signature after decoding the unit", async () => {
  const fixture = createDwarfPackageFixture();
  // First signature slot starts after header16 plus two unused uint64 slots.
  fixture.file.data[32] = 6;
  const parsed = await analyzeDwarf(new MockFile(fixture.file.data), fixture.sections, true);
  assert.match(parsed.issues.join(" "), /signature disagrees/);
});
