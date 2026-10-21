import assert from "node:assert/strict";
import { test } from "node:test";
import { readAmd64RuntimeFunctionTable } from "../../../../../../analyzers/pe/exception/amd64/runtime-function-table.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { writeRuntimeFunction } from "../../../../../helpers/pe-amd64-unwind-fixture.js";

const identityRvaToOffset = (rva: number): number => rva;

const rawRows = (count: number): MockFile => {
  const bytes = new Uint8Array(count * 12);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < count; index++) writeRuntimeFunction(view, index * 12, 4, 8, 16);
  return new MockFile(bytes);
};

void test("raw AMD64 table keeps valid rows after reporting unsorted starts once", async () => {
  const bytes = rawRows(3).data.slice();
  writeRuntimeFunction(new DataView(bytes.buffer), 0, 8, 12, 16);
  writeRuntimeFunction(new DataView(bytes.buffer), 24, 2, 6, 16);
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctionTable(new MockFile(new Uint8Array(32)),
    new MockFile(bytes), 3, identityRvaToOffset, issues);

  assert.deepEqual(table.beginRvas, [8, 4, 2]);
  assert.equal(table.invalidEntryCount, 0);
  assert.equal(issues.length, 1);
  assert.match(issues[0]!, /not sorted/);
});

for (const [count, expected] of [[5461, [[0, 65532]]], [5462, [[0, 65532], [65532, 12]]]] as const) {
void test(`raw AMD64 table ${count} rows remain bounded across the shared reader window`, async context => {
  // 5461 complete twelve-byte rows fit in 64 KiB; the next row requires a second read.
  const source = rawRows(count);
  const read = source.read.bind(source);
  const ranges: [number, number][] = [];
  context.mock.method(source, "read", async (offset: number, size: number) => {
    ranges.push([offset, size]);
    return read(offset, size);
  });
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctionTable(new MockFile(new Uint8Array(32)),
    source, count, identityRvaToOffset, issues);

  assert.equal(table.functionCount, count);
  assert.equal(table.invalidEntryCount, 0);
  assert.deepEqual(ranges, expected);
  assert.deepEqual(issues, []);
});
}

for (const count of [0, 1]) {
  void test(`raw AMD64 table does not scan complete rows beyond its declared count ${count}`, async () => {
    const issues: string[] = [];
    const table = await readAmd64RuntimeFunctionTable(new MockFile(new Uint8Array(32)),
      rawRows(3), count, identityRvaToOffset, issues);

    assert.equal(table.functionCount, count);
    assert.deepEqual(issues, []);
  });
}

void test("raw AMD64 table summarizes repeated invalid rows with their exact count", async () => {
  const bytes = rawRows(2).data.slice();
  const view = new DataView(bytes.buffer);
  view.setUint32(8, 0, true);
  view.setUint32(20, 0, true);
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctionTable(new MockFile(new Uint8Array(32)),
    new MockFile(bytes), 2, identityRvaToOffset, issues);

  assert.equal(table.invalidEntryCount, 2);
  assert.deepEqual(issues, ["2 RUNTIME_FUNCTION entries are invalid: UnwindData is zero."]);
});

void test("raw AMD64 table uses an explicit singular diagnostic for one invalid row", async () => {
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctionTable(new MockFile(new Uint8Array(32)),
    new MockFile(new Uint8Array(12)), 1, identityRvaToOffset, issues);

  assert.equal(table.invalidEntryCount, 1);
  assert.deepEqual(issues, ["1 RUNTIME_FUNCTION entry is invalid: BeginAddress is greater than or equal to EndAddress."]);
});

void test("raw AMD64 table never reads an incomplete row based on its known extent", async context => {
  const source = new MockFile(new Uint8Array(11));
  const read = context.mock.method(source, "read");
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctionTable(new MockFile(new Uint8Array(32)),
    source, 1, identityRvaToOffset, issues);

  assert.equal(table.functionCount, 0);
  assert.equal(read.mock.callCount(), 0);
  assert.equal(issues.length, 1);
  assert.match(issues[0]!, /truncated/);
});

void test("raw AMD64 table stops after a short physical read while retaining its complete prefix", async context => {
  const source = rawRows(5462);
  context.mock.method(source, "read", async () => new DataView(source.data.buffer, 0, 17));
  const issues: string[] = [];
  const table = await readAmd64RuntimeFunctionTable(new MockFile(new Uint8Array(32)),
    source, 5462, identityRvaToOffset, issues);

  assert.equal(table.functionCount, 1);
  assert.equal(table.invalidEntryCount, 0);
  assert.match(issues.join(" | "), /truncated/);
});

for (const count of [-1, NaN, Infinity, 0.5]) {
  void test(`raw AMD64 table safely rejects an invalid entry count ${count}`, async () => {
    const issues: string[] = [];
    const table = await readAmd64RuntimeFunctionTable(new MockFile(new Uint8Array(32)),
      rawRows(1), count, identityRvaToOffset, issues);

    assert.equal(table.functionCount, 0);
    assert.match(issues.join(" | "), /entry count is invalid/);
  });
}

