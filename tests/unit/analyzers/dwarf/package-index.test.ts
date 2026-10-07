import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfPackageIndex } from "../../../../analyzers/dwarf/package-index.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { encodeDwarfPackageIndex } from "../../../fixtures/dwarf-package-fixture.js";

const readIndex = async (bytes: number[]) => {
  const sections = dwarfMacroSources([{ name: ".debug_cu_index", bytes },
    { name: ".debug_info.dwo", bytes: new Array<number>(8).fill(0) },
    { name: ".debug_abbrev.dwo", bytes: new Array<number>(8).fill(0) }]);
  const issues: string[] = [];
  return { index: await readDwarfPackageIndex(sections.get(".debug_cu_index")!, sections, "little", issues),
    issues };
};

void test("package indexes retain signature slots, section identifiers and bounded contributions", async () => {
  const result = await readIndex(encodeDwarfPackageIndex());

  assert.deepEqual(result.index, { sectionName: ".debug_cu_index", version: 5,
    slots: [{ signature: 2n, row: 1 }, { signature: 0n, row: 0 }], columns: [1, 3],
    rows: [[{ offset: 0, size: 8 }, { offset: 0, size: 8 }]] });
  assert.deepEqual(result.issues, []);
});

void test("GNU package v2 and zero signatures with populated rows remain valid", async () => {
  const result = await readIndex(encodeDwarfPackageIndex(0n, 2));

  assert.equal(result.index?.version, 2);
  assert.equal(result.index?.slots[0]?.signature, 0n);
  assert.deepEqual(result.issues, []);
});

void test("package indexes reject truncated headers and oversized array counts", async () => {
  const truncated = await readIndex([5, 0, 0]);
  const oversized = await readIndex([5, 0, 0, 0, ...new Array<number>(12).fill(255)]);

  assert.equal(truncated.index, null);
  assert.match(truncated.issues.join(" "), /Truncated/);
  assert.equal(oversized.index, null);
  assert.match(oversized.issues.join(" "), /arrays/);
});

const interruptedIndex = async (boundary: number) => {
  const sections = dwarfMacroSources([{ name: ".debug_cu_index", bytes: encodeDwarfPackageIndex() }]);
  const source = sections.get(".debug_cu_index")!;
  const issues: string[] = [];
  return { parsed: await readDwarfPackageIndex({ ...source, reader: {
    size: source.reader.size,
    read: (offset, size) => offset < boundary ? source.reader.read(offset, size)
      : Promise.resolve(new DataView(new ArrayBuffer(0))),
    readBytes: (offset, size) => source.reader.readBytes(offset, size)
  } }, sections, "little", issues), issues };
};

void test("short reads in every preflighted package array produce warnings instead of partial tables", async () => {
  // Header16, signatures16, row slots8, columns8, offsets8, sizes8 (DWARF5 7.3.5.3).
  const results = await Promise.all([16, 32, 40, 48, 56].map(interruptedIndex));
  assert.ok(results.every(result => result.parsed === null));
  assert.ok(results.every(result => result.issues.length > 0));
});

void test("package indexes report bytes beyond their complete matrix payload", async () => {
  const result = await readIndex([...encodeDwarfPackageIndex(), 7]);
  assert.ok(result.index);
  assert.match(result.issues.join(" "), /Trailing bytes/);
});
