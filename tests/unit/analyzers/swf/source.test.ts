import assert from "node:assert/strict";
import { test } from "node:test";
import { openCwsBody, openCwsPrefix } from "../../../../analyzers/swf/source.js";
import { createCws, createSwf, createSwfTag } from "../../../fixtures/swf-fixtures.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("openCwsBody supports prefix overlap, cached reads, forward media skips and exact stream completion", async () => {
  const swf = createSwf([createSwfTag(87, new Uint8Array(200000))]);
  const cws = new MockFile(createCws(swf));
  const source = openCwsBody(cws, 0, cws.size, swf.length);
  try {
    const first = await source.read(8, 1);
    const movie = await source.readBytes(8, 21);
    await source.readBytes(8, 1);
    const cached = await source.readBytes(10, 3);
    const end = await source.readBytes(swf.length - 2, 2);
    await source.finish();

    assert.equal(first.getUint8(0), swf[8]);
    assert.deepEqual(movie, swf.subarray(8, 29));
    assert.deepEqual(cached, swf.subarray(10, 13));
    assert.deepEqual(end, Uint8Array.of(0, 0));
    await assert.rejects(source.read(8, 1), /seek backwards/);
  } finally {
    await source.close();
  }
});

void test("openCwsBody clamps reads at EOF and preserves bytes across stream chunks", async () => {
  const payload = Uint8Array.from({ length: 200000 }, (_, index) => (index * 31 + 17) & 255);
  const swf = createSwf([createSwfTag(87, payload)]);
  const file = new MockFile(createCws(swf));
  const source = openCwsBody(file, 0, file.size, swf.length);
  try {
    await source.readBytes(8, 1);
    assert.deepEqual(await source.readBytes(9, swf.length), swf.subarray(9));
    assert.equal((await source.read(swf.length, 0)).byteLength, 0);
    await source.finish();
  } finally {
    await source.close();
  }
});

void test("openCwsBody validates requested address ranges", async () => {
  const file = new MockFile(createCws());
  const source = openCwsBody(file, 0, file.size, createSwf().length);
  try {
    await assert.rejects(source.read(7, 1), /out of bounds/);
    await assert.rejects(source.read(8, -1), /out of bounds/);
    await assert.rejects(source.read(8.5, 1), /out of bounds/);
    await assert.rejects(source.read(8, Number.NaN), /out of bounds/);
    await assert.rejects(source.read(createSwf().length + 1, 1), /out of bounds/);
  } finally {
    await source.close();
  }
});

void test("openCwsBody detects shorter and longer decompressed streams without trusting FileLength", async () => {
  const file = new MockFile(createCws());
  const short = openCwsBody(file, 0, file.size, createSwf().length - 1);
  const long = openCwsBody(file, 0, file.size, createSwf().length + 1);
  try {
    await assert.rejects(short.finish(), /exceeds FileLength/);
    await assert.rejects(long.finish(), /length differs/);
  } finally {
    await short.close();
    await long.close();
  }
});

void test("openCwsPrefix reads a movie header without requiring the rest of a large decoded body", async () => {
  const swf = createSwf([createSwfTag(87, new Uint8Array(2 * 1024 * 1024))]);
  const file = new MockFile(createCws(swf));
  const source = openCwsPrefix(file, 0, file.size, swf.length);
  try {
    assert.deepEqual(await source.readBytes(8, 21), swf.subarray(8, 29));
  } finally {
    await source.close();
  }
});
