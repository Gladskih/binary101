import assert from "node:assert/strict";
import { test } from "node:test";
import { readHllSource } from "../../../../../analyzers/pe/debug/hll-source.js";
import { legacyReader, legacyU16, legacyU32, legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";

const files = [...legacyU32(0), ...legacyU32(0), ...legacyU32(2), ...legacyPascal("first.c"), ...legacyPascal("second.c")];
const names = [0, 0, 3, 0, 0, 0, 0, 0, ...legacyU32(files.length), ...files];

void test("HLL4 source, listing, combined and path tables preserve file names and meaningful values", async () => {
  const warnings: string[] = [];
  const data = await readHllSource(legacyReader([
    ...names,
    0, 0, 0, 0, ...legacyU16(2), ...legacyU16(1), ...legacyU32(0x1000),
    ...legacyU16(7), ...legacyU16(1), ...legacyU32(16), ...legacyU16(7), ...legacyU16(1), ...legacyU32(24),
    0, 0, 1, 0, ...legacyU16(1), ...legacyU16(1), ...legacyU32(0), ...legacyU32(50), ...legacyU32(1), ...legacyU32(16),
    0, 0, 2, 0, ...legacyU16(1), ...legacyU16(2), ...legacyU32(0), ...legacyU16(8), ...legacyU16(2),
    ...legacyU32(60), ...legacyU32(1), ...legacyU32(16),
    0, 0, 4, 0, ...legacyU16(1), ...legacyU16(0), ...legacyU32(16), ...legacyU16(3), ...legacyU16(1)
  ], warnings), 0x400);
  assert.deepEqual(data.files, [{ index: 1, name: "first.c" }, { index: 2, name: "second.c" }]);
  assert.deepEqual(data.groups, [{ file: 1, segment: 1, category: "Source lines", values: [7, 7] },
    { file: 0, segment: 1, category: "Listing lines", values: [50] },
    { file: 2, segment: 2, category: "Source and listing lines", values: [8] },
    { file: 1, segment: 0, category: "Control-flow paths", values: [3] }]);
  assert.deepEqual(warnings, []);
});

for (const version of [0x100, 0x200, 0x300]) {
  void test(`HLL ${version} source headers retain their index widths and file names`, async () => {
    const warnings: string[] = [];
    const header = [0, 0, 0, 0, ...legacyU16(1), ...legacyU16(version === 0x100 ? 0 : 2),
      ...(version === 0x100 ? [] : legacyU32(files.length))];
    const data = await readHllSource(legacyReader([...header, ...legacyU16(7), ...legacyU16(1),
      ...legacyU32(16), ...files], warnings), version);
    assert.deepEqual(data.files, [{ index: 1, name: "first.c" }, { index: 2, name: "second.c" }]);
    assert.deepEqual(data.groups[0]!.values, [7]);
    assert.equal(data.groups[0]!.segment, version === 0x100 ? 1 : 2);
    assert.deepEqual(warnings, []);
  });
}

void test("HLL source retains valid prefix when a table is truncated or an entry type is unknown", async () => {
  const warnings: string[] = [];
  const data = await readHllSource(legacyReader([...names, 0, 0, 255, 0, 0, 0, 0, 0], warnings), 0x400);
  assert.equal(data.files.length, 2);
  assert.match(warnings[0]!, /Unknown HLL source table entry type 255/);
});

for (const bytes of [[0], [0, 0, 0, 0, 1, 0, 0, 0], [0, 0, 3, 0, 0, 0, 0, 0, 255, 255, 255, 255]]) {
  void test(`HLL source truncation ${bytes} remains bounded`, async () => {
    const warnings: string[] = [];
    await readHllSource(legacyReader(bytes, warnings), 0x400);
    assert.equal(warnings.length, 1);
  });
}

void test("HLL1 path codes and nonzero first file indices survive without becoming fake source lines", async () => {
  const warnings: string[] = [];
  const fileTable = [...legacyU32(9), ...legacyU32(1), ...legacyU32(1), ...legacyPascal("tenth.c")];
  const data = await readHllSource(legacyReader([
    0, 0, 0, 0, ...legacyU16(1), ...legacyU16(1), ...legacyU16(7), 10, 128, ...legacyU32(16),
    ...legacyU32(20), ...legacyU16(6), ...fileTable
  ], warnings), 0x100);
  assert.deepEqual(data.files, [{ index: 10, name: "tenth.c" }]);
  assert.deepEqual(data.groups, [{ file: 10, segment: 1, category: "Source lines", values: [7] },
    { file: 0, segment: 1, category: "Control-flow paths", values: [6] }]);
  assert.deepEqual(warnings, []);
});

void test("HLL2 file index is one byte and HLL3 file index is a word", async () => {
  const warnings: string[] = [];
  const fileTable = [...legacyU32(300), ...legacyU32(1),
    ...legacyU32(1), ...legacyPascal("large.c")];
  const data = await readHllSource(legacyReader([0, 0, 0, 0, ...legacyU16(1), ...legacyU16(2),
    ...legacyU32(fileTable.length), ...legacyU16(7), ...legacyU16(301), ...legacyU32(16), ...fileTable],
  warnings), 0x300);
  assert.deepEqual(data.files, [{ index: 301, name: "large.c" }]);
  assert.deepEqual(data.groups[0]!.values, [7]);
  assert.equal(data.groups[0]!.file, 301);
  assert.deepEqual(warnings, []);
});

void test("HLL source reserved headers, missing indices and unknown versions remain explicit", async () => {
  const warnings: string[] = [];
  const data = await readHllSource(legacyReader([1, 0, 0, 0, 1, 0, 1, 0, ...legacyU32(0),
    ...legacyU16(9), ...legacyU16(8), ...legacyU32(16)], warnings), 0x400);
  assert.deepEqual(data.groups, [{ file: 8, segment: 1, category: "Source lines", values: [9] }]);
  assert.match(warnings[0]!, /reserved/);
  assert.match(warnings[1]!, /missing source file index/);
  assert.deepEqual(await readHllSource(legacyReader([], warnings), 0xff00), { kind: "hllSource", files: [], groups: [] });
  assert.match(warnings[2]!, /Unsupported HLL source format version/);
});

void test("HLL file tables validate count before expanding names and preserve zero-length names", async () => {
  const warnings: string[] = [];
  const emptyName = [...legacyU32(0), ...legacyU32(0), ...legacyU32(1), 0];
  const data = await readHllSource(legacyReader([0, 0, 3, 0, 0, 0, 0, 0,
    ...legacyU32(emptyName.length), ...emptyName], warnings), 0x400);
  assert.deepEqual(data.files, [{ index: 1, name: "" }]);
  assert.deepEqual(warnings, []);
  const invalid = [...legacyU32(0), ...legacyU32(0), ...legacyU32(100)];
  await readHllSource(legacyReader([0, 0, 3, 0, 0, 0, 0, 0,
    ...legacyU32(invalid.length), ...invalid], warnings), 0x400);
  assert.match(warnings[0]!, /file names are truncated/);
});

void test("HLL file table trailing bytes and empty early tables are bounded", async () => {
  const warnings: string[] = [];
  const withTrailing = [...files, 0];
  await readHllSource(legacyReader([0, 0, 3, 0, 0, 0, 0, 0,
    ...legacyU32(withTrailing.length), ...withTrailing], warnings), 0x400);
  assert.match(warnings[0]!, /file table has trailing bytes/);
  const emptyWarnings: string[] = [];
  const early = await readHllSource(legacyReader([0, 0, 0, 0, 0, 0, 0, 0, ...legacyU32(0)], emptyWarnings), 0x200);
  assert.deepEqual(early, { kind: "hllSource", files: [], groups: [] });
  assert.deepEqual(emptyWarnings, []);
});

void test("HLL4 listing indices are independent of display columns and retain full-width line numbers", async () => {
  const warnings: string[] = [];
  const fileTable = [...legacyU32(80), ...legacyU32(132), ...legacyU32(1), ...legacyPascal("first.c")];
  const data = await readHllSource(legacyReader([0, 0, 3, 0, 0, 0, 0, 0,
    ...legacyU32(fileTable.length), ...fileTable,
    0, 0, 1, 0, ...legacyU16(1), ...legacyU16(1), ...legacyU32(0), ...legacyU32(0x10002),
    ...legacyU32(1), ...legacyU32(16)
  ], warnings), 0x400);
  assert.deepEqual(data.files, [{ index: 1, name: "first.c" }]);
  assert.deepEqual(data.groups, [{ file: 0, segment: 1, category: "Listing lines", values: [0x10002] }]);
  assert.deepEqual(warnings, []);
});

void test("HLL3 multiple chunks use each recorded file-table size and preserve their own segment", async () => {
  const warnings: string[] = [];
  const firstFiles = [...legacyU32(0), ...legacyU32(1), ...legacyU32(1), ...legacyPascal("first.c")];
  const secondFiles = [...legacyU32(1), ...legacyU32(1), ...legacyU32(1), ...legacyPascal("second.c")];
  const data = await readHllSource(legacyReader([
    0, 0, 0, 0, ...legacyU16(2), ...legacyU16(2), ...legacyU32(firstFiles.length),
    ...legacyU16(7), ...legacyU16(1), ...legacyU32(16),
    ...legacyU16(9), ...legacyU16(1), ...legacyU32(20), ...firstFiles,
    0, 0, 0, 0, ...legacyU16(1), ...legacyU16(3), ...legacyU32(secondFiles.length),
    ...legacyU16(10), ...legacyU16(2), ...legacyU32(24), ...secondFiles
  ], warnings), 0x300);
  assert.deepEqual(data.files, [{ index: 1, name: "first.c" }, { index: 2, name: "second.c" }]);
  assert.deepEqual(data.groups, [{ file: 1, segment: 2, category: "Source lines", values: [7, 9] },
    { file: 2, segment: 3, category: "Source lines", values: [10] }]);
  assert.deepEqual(warnings, []);
});

void test("HLL1 path count does not become a segment number and reserved source flags are diagnosed", async () => {
  const warnings: string[] = [];
  const data = await readHllSource(legacyReader([0, 0, 0, 0, 0, 0, 2, 0,
    ...legacyU32(16), ...legacyU16(3), ...legacyU32(20), ...legacyU16(5), ...files], warnings), 0x100);
  assert.deepEqual(data.groups, [{ file: 0, segment: 1, category: "Control-flow paths", values: [3, 5] }]);
  assert.deepEqual(warnings, []);
  await readHllSource(legacyReader([0, 0, 4, 1, 0, 0, 0, 0], warnings), 0x400);
  assert.match(warnings[0]!, /reserved fields are nonzero/);
});

void test("HLL early source tables reject unsupported kinds and truncated path arrays", async () => {
  const warnings: string[] = [];
  await readHllSource(legacyReader([0, 0, 1, 0, 0, 0, 0, 0], warnings), 0x100);
  assert.match(warnings[0]!, /Unsupported early HLL line table entry type/);
  await readHllSource(legacyReader([0, 0, 0, 0, 0, 0, 255, 255], warnings), 0x100);
  assert.equal(warnings.length, 2);
});

void test("HLL impossible file counts reject the table before returning partial names", async () => {
  const warnings: string[] = [];
  const table = [...legacyU32(0), ...legacyU32(0), ...legacyU32(2), 0];
  const data = await readHllSource(legacyReader([0, 0, 3, 0, 0, 0, 0, 0,
    ...legacyU32(table.length), ...table], warnings), 0x400);
  assert.deepEqual(data.files, []);
  assert.match(warnings[0]!, /file names are truncated/);
});
