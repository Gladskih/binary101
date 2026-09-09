import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { createVersionStringReader, locateElfVersionTable,
  readVersionBytes } from "../../../../analyzers/elf/version-reader.js";
import { elfVersionFixture } from "../../../fixtures/elf-versions.js";

const table = { offset: 64, size: 28, count: 1, strings: { offset: 384, size: 26 } };

void test("reads bounded version bytes and caches decoded strings", async context => {
  const fixture = elfVersionFixture();
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const read = context.mock.fn(reader.read);
  const issues: string[] = [];
  const readString = createVersionStringReader({ ...reader, read }, table, issues);
  assert.equal(await readString(1), "LIB_1");
  const calls = read.mock.callCount();
  assert.equal(await readString(1), "LIB_1");
  assert.equal(read.mock.callCount(), calls);
  assert.equal((await readVersionBytes(reader, table, 0, 20, issues))?.byteLength, 20);
  assert.deepEqual(issues, []);
});

void test("rejects negative, oversized and short reads", async () => {
  const fixture = elfVersionFixture();
  const reader = createFileRangeReader(fixture.file(), 0, 65);
  const issues: string[] = [];
  assert.equal(await readVersionBytes(reader, table, -1, 20, issues), null);
  assert.equal(await readVersionBytes(reader, table, 20, 20, issues), null);
  assert.equal(await readVersionBytes(reader, table, 0, 20, issues), null);
  assert.equal(issues.length, 3);
});

void test("reports missing string tables and out-of-bounds string references", async () => {
  const fixture = elfVersionFixture();
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];
  assert.equal(await createVersionStringReader(reader, { ...table, strings: null }, issues)(0), "");
  assert.equal(await createVersionStringReader(reader, table, issues)(26), "");
  assert.equal(issues.length, 2);
});

void test("reports unterminated strings", async () => {
  const fixture = elfVersionFixture();
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];
  const read = createVersionStringReader(reader,
    { ...table, strings: { offset: 385, size: 3 } }, issues);
  assert.equal(await read(0), "");
  assert.match(issues.join(" "), /unterminated/);
});

void test("locates version records and strings through dynamic tags", () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections = [];
  fixture.elf.programHeaders = [{ type: 1, typeName: "LOAD", index: 0, offset: 0n,
    vaddr: 4096n, paddr: 0n, filesz: 1024n, memsz: 1024n, flags: 4, flagNames: [], align: 1n }];
  const issues: string[] = [];
  assert.deepEqual(locateElfVersionTable(fixture.elf, [
    { tag: 0x6ffffffc, value: 4160n }, { tag: 0x6ffffffd, value: 1n },
    { tag: 5, value: 4480n }, { tag: 10, value: 26n }
  ], "definitions", 2, issues), { offset: 64, size: 960, count: 1,
    strings: { offset: 384, size: 26 } });
  assert.deepEqual(issues, []);
});

void test("reports unmapped dynamic addresses and absent counts", () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections = [];
  const issues: string[] = [];
  assert.equal(locateElfVersionTable(fixture.elf,
    [{ tag: 0x6ffffffc, value: 99999n }], "definitions", 0, issues), null);
  assert.equal(issues.length, 2);
});

void test("reports a section outside the file", () => {
  const fixture = elfVersionFixture();
  fixture.elf.sections[3]!.offset = 1n << 60n;
  const issues: string[] = [];
  assert.equal(locateElfVersionTable(fixture.elf, [], "definitions", 0, issues), null);
  assert.match(issues.join(" "), /outside/);
});
