import assert from "node:assert/strict";
import { test } from "node:test";
import { parseReadyToRunImports } from "../../../../../analyzers/pe/clr/ready-to-run-imports.js";
import { createReadyToRunImportFixture } from "../../../../helpers/ready-to-run-import-fixture.js";

void test("reads import descriptors, cell values and signature RVAs", async () => {
  const fixture = createReadyToRunImportFixture();
  const issues = new Set<string>();

  const result = await parseReadyToRunImports(fixture.header, fixture.reader, rva => rva, 8, issues);

  assert.equal(result.length, 1);
  assert.deepEqual(result[0], { rva: 64, size: 16, flags: 1, type: 2, entrySize: 8,
    signaturesRva: 96, auxiliaryDataRva: 112, entries: [
      { value: Uint8Array.from(Buffer.from("8877665544332211", "hex")), signatureRva: 112 },
      { value: Uint8Array.from(Buffer.from("1100ffeeddccbbaa", "hex")), signatureRva: 116 }
    ] });
  assert.equal(issues.size, 0);
});

void test("uses target pointer width for zero EntrySize and handles absent signatures", async () => {
  const fixture = createReadyToRunImportFixture();
  fixture.view.setUint8(11, 0);
  fixture.view.setUint32(12, 0, true);
  const issues = new Set<string>();

  const result = await parseReadyToRunImports(fixture.header, fixture.reader, rva => rva, 4, issues);

  assert.equal(result[0]?.entries.length, 4);
  assert.equal(result[0]?.entries[0]?.value.length, 4);
  assert.equal(result[0]?.entries[0]?.signatureRva, null);
  assert.equal(issues.size, 0);
});

void test("retains the descriptor when zero EntrySize has no known target", async () => {
  const fixture = createReadyToRunImportFixture();
  fixture.view.setUint8(11, 0);
  const issues = new Set<string>();

  const result = await parseReadyToRunImports(fixture.header, fixture.reader, rva => rva,
    undefined, issues);

  assert.deepEqual(result[0]?.entries, []);
  assert.match([...issues].join(" "), /pointer width/);
});

void test("keeps complete cells and warns about a partial cell and descriptor", async () => {
  const fixture = createReadyToRunImportFixture();
  fixture.view.setUint32(4, 9, true);
  const issues = new Set<string>();

  const result = await parseReadyToRunImports(new DataView(fixture.bytes.buffer, 0, 21),
    fixture.reader, rva => rva, 8, issues);

  assert.equal(result[0]?.entries.length, 1);
  assert.match([...issues].join(" "), /descriptor.*truncated/);
  assert.match([...issues].join(" "), /incomplete entry/);
});

void test("retains cells when their signature RVA table is truncated", async () => {
  const fixture = createReadyToRunImportFixture();
  fixture.view.setUint32(12, 124, true);
  const issues = new Set<string>();

  const result = await parseReadyToRunImports(fixture.header, fixture.reader, rva => rva, 8, issues);

  assert.equal(result[0]?.entries.length, 2);
  assert.equal(result[0]?.entries[0]?.signatureRva, 0);
  assert.equal(result[0]?.entries[1]?.signatureRva, null);
  assert.match([...issues].join(" "), /signature RVA table.*truncated/);
});

void test("does not invent cells in an unmapped or truncated cell range", async () => {
  const fixture = createReadyToRunImportFixture();
  fixture.view.setUint32(0, 127, true);
  const issues = new Set<string>();

  const result = await parseReadyToRunImports(fixture.header, fixture.reader, rva => rva, 8, issues);

  assert.deepEqual(result[0]?.entries, []);
  assert.match([...issues].join(" "), /cell range.*truncated/);
});

void test("turns file-read failures into visible warnings", async () => {
  const fixture = createReadyToRunImportFixture();
  fixture.reader.read = async () => { throw new Error("I/O failed"); };
  const issues = new Set<string>();

  const result = await parseReadyToRunImports(fixture.header, fixture.reader, rva => rva, 8, issues);

  assert.equal(result.length, 1);
  assert.match([...issues].join(" "), /could not be read/);
});
