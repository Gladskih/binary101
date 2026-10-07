import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfSplitScopes } from "../../../../analyzers/dwarf/split-sources.js";
import { readDwarfPackageIndex } from "../../../../analyzers/dwarf/package-index.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { createDwarfSplitContents, createDwarfPackageFixture } from "../../../fixtures/dwarf-split-fixture.js";
import type { DwarfPackageIndex } from "../../../../analyzers/dwarf/package-types.js";

void test("standalone split scopes normalize their tables while retaining information provenance", () => {
  const sections = dwarfMacroSources(createDwarfSplitContents());
  const issues: string[] = [];
  const scopes = [...dwarfSplitScopes(sections, [], issues)];
  assert.equal(scopes.length, 1);
  assert.equal(scopes[0]?.sections.get(".debug_info")?.section.name, ".debug_info.dwo");
  assert.equal(scopes[0]?.sections.get(".debug_str")?.section.name, ".debug_str");
  assert.equal(scopes[0]?.contributions.size, 0);
  assert.deepEqual([...dwarfSplitScopes(new Map(), [], issues)], []);
  assert.deepEqual(issues, []);
});

void test("package scopes bound all section views and share the global strings and address source", async () => {
  const fixture = createDwarfPackageFixture();
  const sections = new Map(fixture.sections.map(section => [section.name,
    { section, summary: section, reader: fixture.file, decoded: true }]));
  const addresses = sections.get(".debug_str.dwo")!;
  sections.set(".debug_addr", addresses);
  const issues: string[] = [];
  const table = await readDwarfPackageIndex(sections.get(".debug_cu_index")!, sections, "little", issues);
  const scopes = [...dwarfSplitScopes(sections, [table!], issues)];
  assert.equal(scopes.length, 2);
  assert.equal(scopes[0]?.sections.get(".debug_str"), scopes[1]?.sections.get(".debug_str"));
  assert.equal(scopes[1]?.sections.get(".debug_addr"), addresses);
  assert.equal(scopes[1]?.sections.get(".debug_info")?.section.offset,
    sections.get(".debug_info.dwo")!.section.offset + table!.rows[1]![0]!.offset);
  assert.equal(scopes[1]?.sections.get(".debug_info")?.section.size, table!.rows[1]![0]!.size);
  assert.deepEqual(issues, []);
});

void test("invalid package rows never fall back to decoding the entire combined section", async () => {
  const fixture = createDwarfPackageFixture();
  const sections = new Map(fixture.sections.map(section => [section.name,
    { section, summary: section, reader: fixture.file, decoded: true }]));
  const issues: string[] = [];
  const table = await readDwarfPackageIndex(sections.get(".debug_cu_index")!, sections, "little", issues);
  assert.deepEqual([...dwarfSplitScopes(sections, [], issues)], []);
  table!.rows[0]![0]!.size = Number.MAX_SAFE_INTEGER;
  table!.rows[1]![1]!.size = 0;
  table!.columns.push(99);
  assert.deepEqual([...dwarfSplitScopes(sections, [table!], issues)], []);
  table!.rows[0]![0]!.size = 0;
  assert.deepEqual([...dwarfSplitScopes(sections, [table!], issues)], []);
  assert.match(issues.join(" "), /no readable information or abbreviation/);
});

void test("overlapping package information contributions are diagnosed and never parsed repeatedly", async () => {
  const fixture = createDwarfPackageFixture();
  const sections = new Map(fixture.sections.map(section => [section.name,
    { section, summary: section, reader: fixture.file, decoded: true }]));
  const issues: string[] = [];
  const table = await readDwarfPackageIndex(sections.get(".debug_cu_index")!, sections, "little", issues);
  table!.rows[1]![0]!.offset = 1;
  assert.deepEqual([...dwarfSplitScopes(sections, [table!], issues)], []);
  assert.match(issues.join(" "), /overlapping package information/);
});

void test("package scope boundaries reject missing section sources and oversized isolated contributions", async () => {
  const fixture = createDwarfPackageFixture();
  const sections = new Map(fixture.sections.map(section => [section.name,
    { section, summary: section, reader: fixture.file, decoded: true }]));
  const issues: string[] = [];
  const table = await readDwarfPackageIndex(sections.get(".debug_cu_index")!, sections, "little", issues);
  table!.rows = [table!.rows[0]!];
  table!.rows[0]![0]!.size = Number.MAX_SAFE_INTEGER;
  assert.deepEqual([...dwarfSplitScopes(sections, [table!], issues)], []);
  table!.rows[0]![0]!.size = fixture.sections.find(section => section.name === ".debug_info.dwo")!.size;
  sections.delete(".debug_abbrev.dwo");
  assert.deepEqual([...dwarfSplitScopes(sections, [table!], issues)], []);
});

const scopesForRanges = (ranges: Array<[number, number]>) => {
  const table: DwarfPackageIndex = { sectionName: ".debug_cu_index", version: 5, slots: [], columns: [1, 3],
    rows: ranges.map(([offset, size]) => [{ offset, size }, { offset: 0, size: 8 }]) };
  const sources = dwarfMacroSources([{ name: ".debug_cu_index", bytes: [] },
    { name: ".debug_info.dwo", bytes: new Array<number>(80).fill(0) },
    { name: ".debug_abbrev.dwo", bytes: new Array<number>(8).fill(0) }]);
  const issues: string[] = [];
  return { scopes: [...dwarfSplitScopes(sources, [table], issues)], issues };
};

void test("nested overlapping package rows are rejected regardless of matrix order", () => {
  const nested = scopesForRanges([[30, 5], [10, 40], [20, 5]]);
  assert.equal(nested.scopes.length, 0);
  assert.equal(nested.issues.length, 2);
});

void test("disjoint contributions and touching boundaries preserve every independently decodable unit", () => {
  const disjoint = scopesForRanges([[20, 4], [0, 4], [4, 4], [10, 4]]);
  assert.equal(disjoint.scopes.length, 4);
  assert.deepEqual(disjoint.issues, []);
});

void test("information overlap validation skips indexes without information columns", () => {
  const table: DwarfPackageIndex = { sectionName: ".debug_cu_index", version: 5,
    slots: [], columns: [3], rows: [[{ offset: 0, size: 8 }]] };
  const issues: string[] = [];
  const sources = dwarfMacroSources([{ name: ".debug_cu_index", bytes: [] },
    { name: ".debug_abbrev.dwo", bytes: new Array<number>(8).fill(0) }]);
  assert.deepEqual([...dwarfSplitScopes(sources, [table], issues)], []);
  assert.match(issues.join(" "), /no readable information/);
});
