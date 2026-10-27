import assert from "node:assert/strict";
import { test } from "node:test";
import { EhCursor } from "../../../../../analyzers/pe/msvc-eh/reader.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { MsvcRttiPeFixtureBuilder } from "../../../../fixtures/pe-msvc-rtti-fixture.js";

const cursorFor = (bytes: number[]) => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const rva = builder.allocateData(bytes.length, 1);
  builder.bytes.set(bytes, builder.offsetOf(rva));
  builder.truncateAtRva(rva + bytes.length);
  const fixture = builder.build();
  return new EhCursor(createEhImage(fixture.file, fixture.core), rva);
};

// MSVC 14.51 ehdata4_export.h, Compress::getNETencoded: low bits encode length.
for (const [encoded, expected] of [
  [[0xfe], 127], [[0x01, 0x02], 128], [[3, 0, 2], 16384],
  [[7, 0, 0, 2], 2097152], [[15, 0, 0, 0, 16], 268435456]
] as const) {
  void test(`FH4 compressed integer decodes ${expected} without reading outside its bytes`, async () => {
    const cursor = cursorFor([...encoded]);
    assert.equal(await cursor.compressed(), expected);
    assert.equal(cursor.valid, true);
  });
}

void test("FH4 reader rejects truncation, noncanonical encodings and impossible counts", async () => {
  const truncated = cursorFor([15, 0]);
  await truncated.compressed();
  assert.equal(truncated.valid, false);
  const overlong = cursorFor([1, 0]);
  await overlong.compressed();
  assert.equal(overlong.valid, false);
  const count = cursorFor([0xfe]);
  assert.equal(await count.count(2), 0);
  assert.equal(count.valid, false);
});

void test("FH4 full-width integers require the canonical 0x0f prefix", async () => {
  const cursor = cursorFor([0x1f, 0, 0, 0, 0x10]);
  assert.equal(await cursor.compressed(), 0x10000000);
  assert.equal(cursor.valid, false);
});

void test("FH4 cursor rejects a short physical read even when the image declares enough bytes", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const rva = builder.allocateData(8);
  const fixture = builder.build();
  fixture.file.read = async () => new DataView(new ArrayBuffer(0));
  const cursor = new EhCursor(createEhImage(fixture.file, fixture.core), rva);
  assert.equal(await cursor.uint32(), 0);
  assert.equal(cursor.valid, false);
});

void test("a cursor stays poisoned even after seeking back into readable bytes", async () => {
  const cursor = cursorFor([2, 0]);
  const start = cursor.position;
  assert.equal(await cursor.uint32(), 0);
  assert.equal(cursor.valid, false);
  assert.equal(cursor.position, start);
  cursor.position = start;
  assert.equal(await cursor.byte(), 0);
  assert.equal(cursor.valid, false);
});

void test("FH4 counts account for the minimum size of each entry", async () => {
  const cursor = cursorFor([4, 0, 0]); // Count=2, but only two bytes remain for two-byte entries.
  assert.equal(await cursor.count(2), 0);
  assert.equal(cursor.valid, false);
});

void test("the full-width compressed form rejects a value below its canonical threshold", async () => {
  const cursor = cursorFor([15, 0xff, 0xff, 0xff, 0x0f]); // 2^28-1 belongs in four bytes.
  assert.equal(await cursor.compressed(), 0x0fffffff);
  assert.equal(cursor.valid, false);
});
