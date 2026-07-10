"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import {
  createDwarf4SectionsFixture,
  createDwarf5SectionsFixture
} from "../../../fixtures/dwarf-sections-fixture.js";
import {
  TEST_DWARF,
  withDwarf32InitialLength
} from "../../../fixtures/dwarf-fixture-encoding.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("analyzeDwarf parses DWARF 4 units, root metadata, and DIE counts", async () => {
  const fixture = createDwarf4SectionsFixture();

  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(dwarf.units.length, 1);
  assert.deepEqual(dwarf.units[0]?.root, {
    tag: TEST_DWARF.tag.compileUnit,
    name: "main.c",
    producer: "fixture compiler",
    language: TEST_DWARF.language.c99
  });
  assert.deepEqual(dwarf.units[0]?.tagCounts, [
    { tag: TEST_DWARF.tag.compileUnit, count: 1 },
    { tag: TEST_DWARF.tag.subprogram, count: 1 }
  ]);
  assert.equal(dwarf.units[0]?.maxDepth, 1);
  assert.equal(dwarf.issues.length, 0);
});

void test("analyzeDwarf parses DWARF 5 headers and implicit constants", async () => {
  const fixture = createDwarf5SectionsFixture();

  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(dwarf.units[0]?.version, TEST_DWARF.version.five);
  assert.equal(dwarf.units[0]?.unitType, TEST_DWARF.unitType.compile);
  assert.equal(dwarf.units[0]?.root?.language, TEST_DWARF.language.rust);
  assert.equal(dwarf.units[0]?.root?.name, "lib.rs");
});

void test("analyzeDwarf inventories compressed sections without decoding them", async () => {
  const fixture = createDwarf4SectionsFixture();
  fixture.sections[0] = { ...fixture.sections[0]!, compressed: true };

  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);

  assert.equal(dwarf.units.length, 0);
  assert.equal(dwarf.sections[0]?.status, "compressed-unsupported");
  assert.ok(dwarf.issues.some(issue => issue.includes("Compressed DWARF section")));
});

void test("analyzeDwarf reports truncated units instead of throwing", async () => {
  const fixture = createDwarf4SectionsFixture();
  const bytes = withDwarf32InitialLength(
    fixture.file.data,
    TEST_DWARF.initialLength.reservedMinimum
  );

  const dwarf = await analyzeDwarf(new MockFile(bytes), fixture.sections, true);

  assert.equal(dwarf.units.length, 0);
  assert.ok(dwarf.issues.some(issue => issue.includes("reserved initial length")));
});

void test("analyzeDwarf reports missing abbreviations and duplicate sections", async () => {
  const fixture = createDwarf4SectionsFixture();
  const info = fixture.sections[0]!;

  const missing = await analyzeDwarf(fixture.file, [info], true);
  const duplicate = await analyzeDwarf(
    fixture.file,
    [...fixture.sections, { ...info }],
    true
  );

  assert.ok(missing.issues.some(issue => issue.includes(".debug_abbrev is required")));
  assert.ok(duplicate.issues.some(issue => issue.includes("duplicate DWARF section")));
});

void test("analyzeDwarf validates section ranges and unknown abbreviation codes", async () => {
  const fixture = createDwarf4SectionsFixture();
  const invalidRange = await analyzeDwarf(fixture.file, [{
    name: ".debug_info",
    offset: -1,
    size: Number.POSITIVE_INFINITY,
    compressed: false
  }], true);
  const unknownCodeFixture = createDwarf4SectionsFixture(TEST_DWARF.invalid.abbreviationCode);
  const unknownCode = await analyzeDwarf(
    unknownCodeFixture.file,
    unknownCodeFixture.sections,
    true
  );

  assert.ok(invalidRange.issues.some(issue => issue.includes("safe non-negative")));
  assert.ok(unknownCode.issues.some(issue => issue.includes("Unknown abbreviation code")));
});
