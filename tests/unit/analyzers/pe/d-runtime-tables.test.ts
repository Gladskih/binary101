import assert from "node:assert/strict";
import { test } from "node:test";
import { findDModuleTableCandidates } from "../../../../analyzers/pe/d-runtime-tables.js";
import type { PeWindowsCore } from "../../../../analyzers/pe/types.js";
import type { PeBaseRelocationResult } from "../../../../analyzers/pe/directories/reloc.js";
import { D_TEST_ABI, D_TEST_IO } from "../../../fixtures/d-runtime.js";
import {
  createDirectoryBoundaryFixture, createDTableRelocations, createManyDTableCandidatesFixture,
  createRenamedPeDRuntimeFixture, D_TEST_PE
} from "../../../fixtures/pe-d-runtime.js";

const findDModuleTableSections = (core: PeWindowsCore,
  relocations: PeBaseRelocationResult | null, pointerSize: 4 | 8) =>
  findDModuleTableCandidates(core, relocations, pointerSize).map(candidate => candidate.section);

void test("selects pointer tables independently of section names", () => {
  const fixture = createRenamedPeDRuntimeFixture();

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), [fixture.tableSection]);
});

void test("accepts exactly two relocated slots at both ends of a table", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.writeTable([fixture.module.record.address, fixture.second.record.address]);
  fixture.relocations = createDTableRelocations(fixture.tableSection,
    [fixture.module.record.address, fixture.second.record.address], D_TEST_ABI.pointer64Bytes);

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), [fixture.tableSection]);
});

void test("accepts tables exactly one read window long", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.tableSection.virtualSize = fixture.tableSection.sizeOfRawData = D_TEST_IO.readWindowBytes;

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), [fixture.tableSection]);
});

void test("accepts tables larger than one read window", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.tableSection.virtualSize = fixture.tableSection.sizeOfRawData =
    D_TEST_IO.readWindowBytes + D_TEST_ABI.pointer64Bytes;

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), [fixture.tableSection]);
});

void test("rejects tables whose declared size contains a partial pointer", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.tableSection.virtualSize -= 1;

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), []);
});

void test("visits all candidate sections beyond the removed cap", () => {
  const fixture = createManyDTableCandidatesFixture();

  assert.equal(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes).length, fixture.core.sections.length);
});

for (const directory of [
  { size: 0, start: "inside" },
  { size: D_TEST_ABI.pointer64Bytes, start: "after" },
  { size: D_TEST_ABI.pointer64Bytes, start: "before" }
] as const) {
  void test(`allows a directory ${directory.start} the table with size ${directory.size}`, () => {
    const fixture = createDirectoryBoundaryFixture(directory.start, directory.size);

    assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
      D_TEST_ABI.pointer64Bytes), [fixture.tableSection]);
  });
}

void test("declines missing and anomalous relocations", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.relocations.warnings = ["Truncated"];

  assert.deepEqual(findDModuleTableSections(fixture.core, null, D_TEST_ABI.pointer64Bytes), []);
  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), []);
});

void test("ignores wrong relocation types, duplicate slots and unaligned sites", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.relocations.blocks[0]!.entries = [
    { type: D_TEST_PE.absoluteRelocation, offset: D_TEST_ABI.pointer64Bytes },
    { type: D_TEST_PE.dir64Relocation, offset: D_TEST_ABI.pointer64Bytes * 2 },
    { type: D_TEST_PE.dir64Relocation, offset: D_TEST_ABI.pointer64Bytes * 2 },
    { type: D_TEST_PE.dir64Relocation, offset: 1 },
    { type: D_TEST_PE.dir64Relocation, offset: D_TEST_PE.relocationPageBytes - 1 }
  ];

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), []);
});

void test("skips relocation pages before and after candidate sections", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.relocations.blocks[0]!.pageRva -= D_TEST_PE.relocationPageBytes;
  fixture.relocations.blocks.push({ ...fixture.relocations.blocks[0]!,
    pageRva: fixture.tableSection.virtualAddress + D_TEST_PE.relocationPageBytes });

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), []);
});

void test("excludes loader directories from candidate tables", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.core.dataDirs = [{ name: "IAT", rva: fixture.tableSection.virtualAddress,
    size: fixture.tableSection.virtualSize }];

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), []);
});

void test("does not interpret certificate file offsets as mapped RVAs", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.core.dataDirs = [{ name: "SECURITY", rva: fixture.tableSection.virtualAddress,
    size: fixture.tableSection.virtualSize }];

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), [fixture.tableSection]);
});

void test("supports HIGHLOW relocations for PE32 tables", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.relocations.blocks[0]!.entries = Array.from({
    length: fixture.tableSection.virtualSize / D_TEST_ABI.pointer32Bytes }, (_, index) =>
    ({ type: D_TEST_PE.highlowRelocation, offset: index * D_TEST_ABI.pointer32Bytes }));

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer32Bytes), [fixture.tableSection]);
});

void test("rejects executable sections", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.tableSection.characteristics |= D_TEST_PE.executableFlag;

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), []);
});

void test("rejects sections with zero-filled table tails", () => {
  const fixture = createRenamedPeDRuntimeFixture();
  fixture.tableSection.sizeOfRawData = fixture.tableSection.virtualSize - 1;

  assert.deepEqual(findDModuleTableSections(fixture.core, fixture.relocations,
    D_TEST_ABI.pointer64Bytes), []);
});
