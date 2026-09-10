import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { readElfHashTable } from "../../../../analyzers/elf/hash-reader.js";
import { selectElfBinaryLayout } from "../../../../analyzers/elf/binary-layout.js";

const read = (words: number[], kind: "sysv" | "gnu", size = words.length * 4) => {
  const bytes = new Uint8Array(words.length * 4);
  const view = new DataView(bytes.buffer);
  words.forEach((word, index) => view.setUint32(index * 4, word, true));
  const file = new File([bytes], "hash");
  return readElfHashTable(createFileRangeReader(file, 0, file.size), { kind, offset: 0, size },
    selectElfBinaryLayout({ is64: false, littleEndian: true }));
};

void test("reads ELF32 GNU bloom and stops at the last bucket chain end", async () => {
  assert.deepEqual(await read([2, 3, 1, 7, 0x80000001, 3, 5, 2, 3, 5, 99], "gnu"), {
    kind: "gnu", offset: 0, symbolOffset: 3, bloomShift: 7,
    bloom: [0x80000001n], buckets: [3, 5], chains: [2, 3, 5], issues: []
  });
});

void test("does not invent chains when all GNU buckets are empty", async () => {
  assert.deepEqual(await read([1, 3, 1, 7, 1, 0, 99], "gnu"), {
    kind: "gnu", offset: 0, symbolOffset: 3, bloomShift: 7,
    bloom: [1n], buckets: [0], chains: [], issues: []
  });
});

void test("reports short backing reads even when source claims a complete header", async () => {
  assert.match((await read([1], "sysv", 8)).issues.join(" "), /truncated/);
  assert.match((await read([1, 1, 1, 5, 0, 1], "gnu", 28)).issues.join(" "), /truncated/);
});

void test("rejects bucket and chain allocations above the resource limit", async () => {
  assert.match((await read([1000001, 0], "sysv", 8000008)).issues.join(" "), /limit/);
  assert.match((await read([0, 1000001], "sysv", 8000008)).issues.join(" "), /limit/);
  assert.match((await read([1, 1], "sysv", 8)).issues.join(" "), /dimensions/);
});

void test("reports truncated arrays instead of accepting a shorter table", async () => {
  assert.match((await read([1, 1, 0], "sysv", 16)).issues.join(" "), /truncated/);
  assert.match((await read([1, 1, 1, 5], "gnu", 24)).issues.join(" "), /truncated/);
});
