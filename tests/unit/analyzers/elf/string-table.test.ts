import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfStringTableReader } from "../../../../analyzers/elf/string-table.js";
import { MockFile } from "../../../helpers/mock-file.js";
import type { FileRangeReader } from "../../../../analyzers/file-range-reader.js";

const strings = (text: string, issues: string[]) => {
  const file = new MockFile(new TextEncoder().encode(text));
  return createElfStringTableReader(file, { offset: 0, size: file.size }, issues);
};

void test("reads names, suffixes, empty strings and cached results", async () => {
  const issues: string[] = [];
  const read = strings("\0example\0", issues);
  assert.equal(await read(1), "example");
  assert.equal(await read(3), "ample");
  assert.equal(await read(1), "example");
  assert.equal(await read(0), "");
  assert.equal(await read(8), "");
  assert.deepEqual(issues, []);
});

for (const offset of [-1, 0.5, NaN, Infinity, 2 ** 60, 3]) {
  void test(`rejects invalid string index ${offset}`, async () => {
    const issues: string[] = [];
    const read = strings("\0x\0", issues);
    assert.equal(await read(offset), null);
    assert.match(issues.join(" "), /offset/);
  });
}

void test("empty tables permit only index zero", async () => {
  const issues: string[] = [];
  const read = strings("", issues);
  assert.equal(await read(0), "");
  assert.deepEqual(issues, []);
  assert.equal(await read(1), null);
  assert.match(issues.join(" "), /offset/);
});

for (const range of [null, { offset: -1, size: 1 }, { offset: 0, size: -1 },
  { offset: 0.5, size: 1 }, { offset: 0, size: 0.5 }, { offset: 1, size: 1 }]) {
  void test(`rejects invalid table range ${JSON.stringify(range)}`, async () => {
    const issues: string[] = [];
    const read = createElfStringTableReader(new MockFile(new Uint8Array(1)), range, issues);
    assert.equal(await read(0), null);
    assert.match(issues.join(" "), /range/);
  });
}

void test("validates both sentinels and caches invalid names", async () => {
  const issues: string[] = [];
  const read = strings("bad", issues);
  assert.equal(await read(1), null);
  assert.equal(await read(1), null);
  assert.equal(await read(0), "");
  assert.equal(issues.length, 3);
  assert.match(issues.join(" "), /begin with NUL/);
  assert.match(issues.join(" "), /end with NUL/);
  assert.match(issues.join(" "), /unterminated/);
});

void test("decodes UTF-8 across read chunks", async () => {
  const issues: string[] = [];
  const name = "a".repeat(4095) + "é";
  assert.equal(await strings(`\0${name}\0`, issues)(1), name);
  assert.deepEqual(issues, []);
});

void test("caps names at the documented 64 KiB resource limit", async () => {
  const issues: string[] = [];
  assert.equal(await strings(`\0${"a".repeat(65536)}\0`, issues)(1), null);
  assert.match(issues.join(" "), /64 KiB/);
});

void test("accepts a name with its NUL at the resource boundary", async () => {
  const issues: string[] = [];
  const name = "a".repeat(65535);
  assert.equal(await strings(`\0${name}\0`, issues)(1), name);
  assert.deepEqual(issues, []);
});
void test("does not consume a terminator beyond the declared string table", async () => {
  const file = new MockFile(new TextEncoder().encode(`\0${"a".repeat(4100)}\0`));
  const issues: string[] = [];
  const read = createElfStringTableReader(file, { offset: 0, size: file.size - 1 }, issues);
  assert.equal(await read(1), null);
  assert.match(issues.join(" "), /unterminated/);
});
void test("stops when a string read ends before the declared table boundary", async () => {
  const file = new MockFile(new TextEncoder().encode("\0name\0"));
  const reader: FileRangeReader = {
    size: file.size,
    read: (offset, size) => file.read(offset, size),
    readBytes: (offset, size) => offset === 1
      ? Promise.resolve(new Uint8Array()) : file.readBytes(offset, size)
  };
  const issues: string[] = [];
  const read = createElfStringTableReader(reader, { offset: 0, size: file.size }, issues);

  assert.equal(await read(1), null);
  assert.match(issues.join(" "), /unterminated/);
});
