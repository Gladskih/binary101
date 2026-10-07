import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { dwarfLineProgramForUnit, dwarfSectionContributionAt,
  dwarfUnitContribution } from "../../../../analyzers/dwarf/unit-sections.js";
import { createDwarfPackageFixture, createDwarfSplitFixture } from "../../../fixtures/dwarf-split-fixture.js";
import { createDwarf4SectionsFixture } from "../../../fixtures/dwarf-sections-fixture.js";

void test("unit contributions identify a package row by its information offset and section provenance", async () => {
  const fixture = createDwarfPackageFixture();
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);
  const unit = parsed.units[1]!;
  assert.equal(dwarfUnitContribution(parsed, unit, ".debug_line"), parsed.packageIndexes![0]!.rows[1]![2]);
  assert.equal(dwarfUnitContribution(parsed, unit, ".debug_missing"), null);
  assert.equal(dwarfUnitContribution(parsed, { ...unit, sectionName: ".debug_info" }, ".debug_line"), null);
  assert.equal(dwarfUnitContribution(parsed, { ...unit, offset: -1 }, ".debug_line"), null);
  assert.equal(dwarfUnitContribution(parsed, { ...unit, sectionName: ".debug_types.dwo" }, ".debug_line"), null);
});

void test("line associations disambiguate regular and split programs at the same section offset", async () => {
  const regularFixture = createDwarf4SectionsFixture();
  const splitFixture = createDwarfSplitFixture();
  const regular = await analyzeDwarf(regularFixture.file, regularFixture.sections, true);
  const split = await analyzeDwarf(splitFixture.file, splitFixture.sections, true);
  const combined = { ...regular, units: [...regular.units, ...split.units],
    linePrograms: [...regular.linePrograms, ...split.linePrograms] };
  assert.equal(dwarfLineProgramForUnit(combined, regular.units[0]!), regular.linePrograms[0]);
  assert.equal(dwarfLineProgramForUnit(combined, split.units[0]!), split.linePrograms[0]);
  assert.equal(dwarfLineProgramForUnit(combined, { ...regular.units[0]!, dies: [] }), undefined);
  assert.equal(dwarfUnitContribution(split, split.units[0]!, ".debug_line"), null);
});

void test("package contribution lookup includes starts and excludes ends without crossing section kinds", async () => {
  const fixture = createDwarfPackageFixture();
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);
  const contribution = parsed.packageIndexes![0]!.rows[1]![4]!;
  assert.equal(dwarfSectionContributionAt(parsed, ".debug_macro.dwo", contribution.offset), contribution);
  assert.equal(dwarfSectionContributionAt(parsed, ".debug_macro.dwo", contribution.offset + contribution.size), null);
  assert.equal(dwarfSectionContributionAt(parsed, ".debug_macro.dwo", -1), null);
  assert.equal(dwarfSectionContributionAt(parsed, ".debug_missing.dwo", 0), null);
  assert.equal(dwarfSectionContributionAt(parsed, ".debug_macro.dwo", contribution.offset, ".debug_missing.dwo"), null);
  assert.equal(dwarfSectionContributionAt(parsed, ".debug_macro.dwo", contribution.offset, ".debug_line.dwo"),
    parsed.packageIndexes![0]!.rows[1]![2]);
  assert.equal(dwarfSectionContributionAt({ sections: [], units: [], linePrograms: [], issues: [] },
    ".debug_macro.dwo", 0), null);
});

void test("unit associations accept a contributing section in column zero and tolerate unknown identifiers", async () => {
  const fixture = createDwarfPackageFixture();
  const parsed = await analyzeDwarf(fixture.file, fixture.sections, true);
  const unit = parsed.units[0]!;
  assert.equal(dwarfUnitContribution(parsed, unit, ".debug_info"), parsed.packageIndexes![0]!.rows[0]![0]);
  assert.equal(dwarfSectionContributionAt(parsed, ".debug_info.dwo", 0), parsed.packageIndexes![0]!.rows[0]![0]);
  parsed.packageIndexes![0]!.columns.push(99);
  assert.equal(dwarfUnitContribution(parsed, unit, ".debug_missing"), null);
});
