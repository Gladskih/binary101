import assert from "node:assert/strict";
import { test } from "node:test";
import { readGvdbTable, readGvdbChildren } from "../../../../analyzers/embedded-resources/gvdb-table.js";
import { minimalGResource, overwriteResource, gResourceBeforeTable } from "../../../fixtures/embedded-resource-builders.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("preserves exact metadata fields, bounded keys and pointers", async () => {
  const file = new MockFile(minimalGResource());
  const result = await readGvdbTable(file, { offset: 0, size: file.size }, { offset: 24, size: 64 });
  assert.equal(result.bloomShift, 5);
  assert.deepEqual(result.bloomWords, [0xffffffff]);
  assert.deepEqual(result.buckets, [0]);
  assert.deepEqual(result.entries[1], { name: "a", parent: 0, hash: 5861557,
    keyOffset: 89, keySize: 1, type: "v", value: { offset: 96, size: 22 } });
  assert.deepEqual(await readGvdbChildren(file, result.entries[0]!), [1]);
});

void test("accepts data and keys before the root hash table, including exact header boundaries", async () => {
  const bytes = gResourceBeforeTable();
  const table = await readGvdbTable(new MockFile(bytes), { offset: 0, size: bytes.length }, { offset: 128, size: 64 });
  assert.deepEqual(table.entries[0], { name: "/", parent: null, hash: 177620,
    keyOffset: 24, keySize: 1, type: "L", value: { offset: 28, size: 4 } });
  const touching = overwriteResource(overwriteResource(bytes, 160, 124), 164, 128);
  assert.equal((await readGvdbTable(new MockFile(touching), { offset: 0, size: touching.length },
    { offset: 128, size: 64 })).entries[0]?.value.offset, 124);
  const keyTouching = overwriteResource(bytes, 152, 127);
  keyTouching[127] = 47;
  assert.equal((await readGvdbTable(new MockFile(keyTouching), { offset: 0, size: keyTouching.length },
    { offset: 128, size: 64 })).entries[0]?.keyOffset, 127);
  const valueAtHeaderEnd = overwriteResource(overwriteResource(bytes, 160, 24), 164, 28);
  assert.equal((await readGvdbTable(new MockFile(valueAtHeaderEnd), { offset: 0, size: valueAtHeaderEnd.length },
    { offset: 128, size: 64 })).entries[0]?.value.offset, 24);
});

for (const [label, offset, value, message] of [
  ["value before header", 160, 20, "Invalid GVDB value pointer"],
  ["value starts inside table", 160, 132, "Invalid GVDB value pointer"],
  ["value crosses table", 164, 132, "GVDB key or value overlaps the hash table"],
  ["key crosses table", 152, 128, "GVDB key or value overlaps the hash table"],
  ["key before header", 152, 23, "Invalid GVDB key pointer"],
  ["key beyond file", 152, 192, "Invalid GVDB key pointer"],
  ["reserved byte", 159, 1, "Nonzero GVDB reserved byte"]
] as const) {
  void test(`rejects GVDB ${label} in a table following its data`, async () => {
    const bytes = overwriteResource(gResourceBeforeTable(), offset, value,
      label === "reserved byte" ? "u8" : "le32");
    await assert.rejects(readGvdbTable(new MockFile(bytes), { offset: 0, size: bytes.length },
      { offset: 128, size: 64 }), { message });
  });
}

void test("validates UTF-8 without stripping a leading U+FEFF from a length-delimited key", async () => {
  const bytes = overwriteResource(minimalGResource(), 76, 3, "le16");
  bytes.set(new TextEncoder().encode("\ufeff"), 89);
  const table = await readGvdbTable(new MockFile(bytes), { offset: 0, size: bytes.length }, { offset: 24, size: 64 });
  assert.equal(table.entries[1]?.name, "\ufeff");
  bytes[89] = 0xff;
  await assert.rejects(readGvdbTable(new MockFile(bytes), { offset: 0, size: bytes.length },
    { offset: 24, size: 64 }), /encoded data/);
});

void test("rejects values aligned to four bytes but not to GVariant's eight-byte boundary", async () => {
  const bytes = overwriteResource(minimalGResource(), 80, 100);
  await assert.rejects(readGvdbTable(new MockFile(bytes), { offset: 0, size: bytes.length }, { offset: 24, size: 64 }),
    { message: "Invalid GVDB value pointer" });
});

void test("handles an empty low-level table and rejects invalid dimensions at exact boundaries", async () => {
  const bytes = minimalGResource();
  const view = new DataView(bytes.buffer);
  view.setUint32(24, 0, true);
  view.setUint32(32, 0, true);
  assert.deepEqual(await readGvdbTable(new MockFile(bytes),
    { offset: 0, size: bytes.length }, { offset: 24, size: 12 }),
    { bloomShift: 0, bloomWords: [], buckets: [0], entries: [] });
  await assert.rejects(readGvdbTable(new MockFile(bytes), { offset: 0, size: bytes.length }, { offset: 24, size: 8 }),
    { message: "Invalid GVDB hash table dimensions" });
  view.setUint32(28, 0, true);
  await assert.rejects(readGvdbTable(new MockFile(bytes), { offset: 0, size: bytes.length }, { offset: 24, size: 8 }),
    { message: "Invalid GVDB hash table dimensions" });
  const table = await readGvdbTable(new MockFile(minimalGResource()), { offset: 0, size: bytes.length },
    { offset: 24, size: 64 });
  await assert.rejects(readGvdbChildren(new MockFile(bytes),
    { ...table.entries[0]!, value: { offset: 0, size: -4 } }), { message: "GVDB word array exceeds table" });
});

void test("rejects metadata ranges and directory lists that are not bounded uint32 arrays", async () => {
  const file = new MockFile(minimalGResource());
  await assert.rejects(readGvdbTable(file, { offset: 0, size: file.size }, { offset: 24, size: 7 }), /root pointer/);
  await assert.rejects(readGvdbTable(file, { offset: 0, size: file.size }, { offset: 24, size: 65 }), /dimensions/);
  const bytes = overwriteResource(minimalGResource(), 60, 95);
  const broken = await readGvdbTable(new MockFile(bytes), { offset: 0, size: bytes.length }, { offset: 24, size: 64 });
  await assert.rejects(readGvdbChildren(new MockFile(bytes), broken.entries[0]!), /uint32/);
});
