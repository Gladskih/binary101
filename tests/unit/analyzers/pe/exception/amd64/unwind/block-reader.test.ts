import assert from "node:assert/strict";
import { test } from "node:test";
import { createAmd64UnwindBlockReader }
  from "../../../../../../../analyzers/pe/exception/amd64/unwind-block-reader.js";
import { createMemoryRangeReader } from "../../../../../../../analyzers/memory-range-reader.js";
import type { RvaToOffset } from "../../../../../../../analyzers/pe/types.js";

const windowFixture = (size = 0x11000) => {
  const bytes = Uint8Array.from({ length: size + 7 }, (_, index) => index & 255).subarray(7);
  const reader = createMemoryRangeReader(bytes);
  const requests: number[][] = [];
  const read = reader.read;
  reader.read = (offset, length) => { requests.push([offset, length]); return read(offset, length); };
  const mapper: RvaToOffset = rva => rva >= 0x1000 && rva - 0x1000 < size ? rva - 0x1000 : null;
  mapper.span = rva => {
    const offset = mapper(rva);
    return offset === null ? null : { offset, size: size - offset };
  };
  return { bytes, reader, requests, mapper, readBlock: createAmd64UnwindBlockReader(reader, mapper) };
};

void test("one local source window covers adjacent blocks and its exact end", async () => {
  const fixture = windowFixture();
  const first = await fixture.readBlock(0x1000 + 100);
  const last = fixture.readBlock(0x1000 + 100 + 65536 - 528);
  assert.ok(last instanceof DataView);
  assert.equal(first.byteLength, 528); // The complete format-bounded block, including a chain tail.
  assert.equal(last.byteLength, 528);
  assert.equal(first.getUint8(0), fixture.bytes[100]);
  assert.equal(last.getUint8(527), fixture.bytes[100 + 65536 - 1]);
  assert.deepEqual(fixture.requests, [[100, 65536]]);
  assert.ok(fixture.readBlock(0x1000 + 100) instanceof DataView);
  assert.deepEqual(fixture.requests, [[100, 65536]]);
  await fixture.readBlock(0x1000 + 100 + 65536 - 527);
  assert.equal(fixture.requests.length, 2);
  await fixture.readBlock(0x1000);
  assert.equal(fixture.requests.length, 3);
});

void test("a short mapped tail returns its actual prefix rather than padding a block", async () => {
  const fixture = windowFixture(527);
  const block = await fixture.readBlock(0x1000);
  assert.equal(block.byteLength, 527);
  assert.deepEqual(fixture.requests, [[0, 527]]);
  assert.equal((await fixture.readBlock(0xfff)).byteLength, 0);
});

void test("point-only mappers retain the existing prefix mapping rules", async () => {
  const fixture = windowFixture(32);
  const mapper: RvaToOffset = rva => rva >= 0x1000 && rva < 0x1008 ? rva - 0x1000 : null;
  assert.equal((await createAmd64UnwindBlockReader(fixture.reader, mapper)(0x1000)).byteLength, 8);
  assert.deepEqual(fixture.requests, [[0, 8]]);
});

void test("fragmented physical spans are assembled in logical RVA order", async () => {
  const fixture = windowFixture(1024);
  const mapper: RvaToOffset = rva => rva >= 0x1000 && rva < 0x1004 ? 20 + rva - 0x1000
    : rva >= 0x1004 && rva < 0x1210 ? 100 + rva - 0x1004 : null;
  mapper.span = rva => rva >= 0x1000 && rva < 0x1004 ? { offset: mapper(rva)!, size: 0x1004 - rva }
    : rva >= 0x1004 && rva < 0x1210 ? { offset: mapper(rva)!, size: 0x1210 - rva } : null;
  const block = await createAmd64UnwindBlockReader(fixture.reader, mapper)(0x1000);
  assert.equal(block.byteLength, 528);
  assert.equal(block.getUint8(3), fixture.bytes[23]);
  assert.equal(block.getUint8(4), fixture.bytes[100]);
  assert.equal(block.getUint8(527), fixture.bytes[623]);
  assert.deepEqual(fixture.requests, [[20, 4], [100, 524]]);
});

void test("physical short reads and empty reads expose only the returned bytes", async () => {
  const fixture = windowFixture();
  fixture.reader.read = async () => new DataView(new Uint8Array([9, 8, 7]).buffer);
  assert.equal((await fixture.readBlock(0x1000)).byteLength, 3);
  fixture.reader.read = async () => new DataView(new ArrayBuffer(0));
  assert.equal((await fixture.readBlock(0x1001)).byteLength, 0);
});
