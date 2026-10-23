import assert from "node:assert/strict";
import { test } from "node:test";
import { directHllDirectory, findCodeViewLocation } from "../../../../../analyzers/pe/debug/codeview-location.js";
import { createHll } from "../../../../fixtures/pe-hll.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("CodeView terminal trailer locates the matching header after a physical prefix", async () => {
  const file = new MockFile(Uint8Array.from([...new Uint8Array(32), ...createHll([])]));
  const warnings: string[] = [];
  assert.deepEqual(await findCodeViewLocation(file, 0, file.size, warning => warnings.push(warning)),
    { offset: 32, size: file.size - 32 });
  assert.deepEqual(warnings, []);
});

void test("CodeView anchors retain a leading header while diagnosing a broken trailer", async () => {
  const bytes = createHll([]);
  bytes.set(legacyU32(15), bytes.length - 4);
  const file = new MockFile(bytes);
  const warnings: string[] = [];
  assert.deepEqual(await findCodeViewLocation(file, 0, file.size, warning => warnings.push(warning)),
    { offset: 0, size: file.size });
  assert.match(warnings[0]!, /invalid backward distance/);
});

for (const [offset, size] of [[-1, 4], [0, -1], [100, 4], [0, 100], [NaN, 4], [0, Infinity], [0.5, 4]] as const) {
  void test(`CodeView candidate ${offset}/${size} must be an exact bounded file range`, async () => {
    const warnings: string[] = [];
    assert.equal(await findCodeViewLocation(new MockFile(new Uint8Array(8)), offset, size,
      warning => warnings.push(warning)), null);
    assert.match(warnings[0]!, /file bounds/);
  });
}

void test("CodeView short and nonmatching containers remain absent", async () => {
  const warnings: string[] = [];
  assert.equal(await findCodeViewLocation(new MockFile(new Uint8Array(7)), 0, 7,
    warning => warnings.push(warning)), null);
  assert.equal(await findCodeViewLocation(new MockFile(new Uint8Array(16)), 0, 16,
    warning => warnings.push(warning)), null);
  assert.deepEqual(warnings, []);
});

void test("Direct HLL DEBUG RVA must map to one contiguous file range", async () => {
  const file = new MockFile(createHll([]));
  const directory = { index: 6, name: "DEBUG", rva: 0x1000, size: file.size };
  const warnings: string[] = [];
  assert.deepEqual(await directHllDirectory(file, directory, rva => rva - 0x1000,
    warning => warnings.push(warning)), { offset: 0, size: file.size });
  assert.equal(await directHllDirectory(file, directory, () => null, warning => warnings.push(warning)), null);
  assert.equal(await directHllDirectory(file, { ...directory, size: 7 }, () => 0,
    warning => warnings.push(warning)), null);
  assert.deepEqual(warnings, []);
});

for (const signature of ["NB02", "NB04"]) {
  void test(`CodeView ${signature} has a minimal 16-byte trailer container and an 8-byte header anchor`, async () => {
    const header = [...new TextEncoder().encode(signature), ...legacyU32(0)];
    const file = new MockFile(Uint8Array.from([...header, ...new TextEncoder().encode(signature), ...legacyU32(16)]));
    const warnings: string[] = [];
    assert.deepEqual(await findCodeViewLocation(file, 0, file.size, warning => warnings.push(warning)),
      { offset: 0, size: 16 });
    assert.deepEqual(await findCodeViewLocation(new MockFile(Uint8Array.from(header)), 0, 8,
      warning => warnings.push(warning)), { offset: 0, size: 8 });
    assert.deepEqual(warnings, []);
  });
}

for (const distance of [0, 8, 15, 17, 0xffffffff]) {
  void test(`CodeView invalid backward distance ${distance} never initiates a read at the computed offset`, async context => {
    const file = new MockFile(Uint8Array.from([...new Uint8Array(8), 78, 66, 48, 52, ...legacyU32(distance)]));
    const read = file.read.bind(file);
    const requests: number[] = [];
    context.mock.method(file, "read", async (offset: number, size: number) => {
      requests.push(offset); return read(offset, size);
    });
    const warnings: string[] = [];
    assert.equal(await findCodeViewLocation(file, 0, file.size, warning => warnings.push(warning)), null);
    assert.deepEqual(requests, [8, 0]);
    assert.match(warnings[0]!, /invalid backward distance/);
  });
}

void test("CodeView trailer rejects mismatched header signatures instead of accepting arbitrary bytes", async () => {
  const file = new MockFile(Uint8Array.from([...new Uint8Array(16), 78, 66, 48, 52, ...legacyU32(16)]));
  const warnings: string[] = [];
  assert.equal(await findCodeViewLocation(file, 0, file.size, warning => warnings.push(warning)), null);
  assert.match(warnings[0]!, /mismatched header/);
});

for (const shortAt of [0, 1]) {
  void test(`CodeView short physical read ${shortAt} remains absent`, async context => {
    const file = new MockFile(Uint8Array.from([0, ...createHll([])]));
    const read = file.read.bind(file);
    let calls = 0;
    context.mock.method(file, "read", async (offset: number, size: number) =>
      calls++ === shortAt ? new DataView(new ArrayBuffer(0)) : read(offset, size));
    const warnings: string[] = [];
    assert.equal(await findCodeViewLocation(file, 0, file.size, warning => warnings.push(warning)), null);
    assert.match(warnings[0]!, /trailer/);
  });
}

void test("CodeView failed reads and direct DEBUG read failures become warnings", async context => {
  const file = new MockFile(createHll([]));
  context.mock.method(file, "read", async () => { throw new Error("read failed"); });
  const warnings: string[] = [];
  assert.equal(await findCodeViewLocation(file, 0, file.size, warning => warnings.push(warning)), null);
  assert.equal(await directHllDirectory(file, { index: 6, name: "DEBUG", rva: 0, size: file.size }, rva => rva,
    warning => warnings.push(warning)), null);
  assert.equal(warnings.length, 2);
  assert.match(warnings.join(" | "), /location read failed.*directory header read failed/);
});

void test("Direct DEBUG data and leading anchors reject short or unrelated headers", async context => {
  const file = new MockFile(new Uint8Array(8));
  const directory = { index: 6, name: "DEBUG", rva: 0, size: 8 };
  const warnings: string[] = [];
  assert.equal(await directHllDirectory(file, directory, rva => rva, warning => warnings.push(warning)), null);
  const read = file.read.bind(file);
  context.mock.method(file, "read", async (offset: number, size: number) =>
    size === 4 ? new DataView(new ArrayBuffer(0)) : read(offset, size));
  assert.equal(await findCodeViewLocation(file, 0, file.size, warning => warnings.push(warning)), null);
  assert.equal(await directHllDirectory(file, directory, rva => rva, warning => warnings.push(warning)), null);
  assert.deepEqual(warnings, []);
});

void test("CodeView zero ranges and sub-header candidates never read bytes", async context => {
  const file = new MockFile(Uint8Array.from([78, 66, 48, 52, 0, 0, 0, 0]));
  const read = context.mock.method(file, "read", async () => { throw new Error("unexpected read"); });
  const warnings: string[] = [];
  assert.equal(await findCodeViewLocation(file, 0, 0, warning => warnings.push(warning)), null);
  assert.equal(await findCodeViewLocation(file, 0, 7, warning => warnings.push(warning)), null);
  assert.equal(read.mock.callCount(), 0);
  assert.deepEqual(warnings, []);
});

void test("Direct DEBUG header anchors accept exactly eight bytes and reject seven", async () => {
  const file = new MockFile(Uint8Array.from([78, 66, 48, 52, 0, 0, 0, 0]));
  const warnings: string[] = [];
  assert.deepEqual(await directHllDirectory(file, { index: 6, name: "DEBUG", rva: 0, size: 8 }, rva => rva,
    warning => warnings.push(warning)), { offset: 0, size: 8 });
  assert.equal(await directHllDirectory(file, { index: 6, name: "DEBUG", rva: 0, size: 7 }, rva => rva,
    warning => warnings.push(warning)), null);
  assert.deepEqual(warnings, []);
});
