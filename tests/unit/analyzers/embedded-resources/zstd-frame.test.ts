import assert from "node:assert/strict";
import { test } from "node:test";
import { resourceZstdSize } from "../../../../analyzers/embedded-resources/zstd-frame.js";

// Zstandard format Frame_Header_Descriptor / Frame_Content_Size, no payload decode needed here.
const frame = (descriptor: number, size: bigint, dictionaryFlag = 0): DataView => {
  const bytes = new Uint8Array(18);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0xfd2fb528, true);
  bytes[4] = descriptor | dictionaryFlag;
  const offset = 5 + Number((descriptor & 32) === 0) + (dictionaryFlag ? 2 ** (dictionaryFlag - 1) : 0);
  const sizeBytes = descriptor >>> 6;
  if (sizeBytes === 3) view.setBigUint64(offset, size, true);
  else if (sizeBytes === 2) view.setUint32(offset, Number(size), true);
  else if (sizeBytes === 1) view.setUint16(offset, Number(size) - 256, true);
  else bytes[offset] = Number(size);
  return view;
};

void test("reads every Zstandard size encoding and dictionary id width", () => {
  assert.equal(resourceZstdSize(frame(0x20, 0n)), 0);
  assert.equal(resourceZstdSize(frame(0x20, 255n)), 255);
  assert.equal(resourceZstdSize(frame(0x40, 256n)), 256);
  assert.equal(resourceZstdSize(frame(0x60, 1000n)), 1000);
  assert.equal(resourceZstdSize(frame(0x80, 90000n)), 90000);
  assert.equal(resourceZstdSize(frame(0xe0, 2n ** 40n)), 2 ** 40);
  assert.equal(resourceZstdSize(frame(0x60, 1000n, 1)), 1000);
  assert.equal(resourceZstdSize(frame(0x60, 1000n, 2)), 1000);
  assert.equal(resourceZstdSize(frame(0x60, 1000n, 3)), 1000);
  const exact = frame(0x60, 1000n, 1);
  assert.equal(resourceZstdSize(new DataView(exact.buffer, 0, 8)), 1000);
  const exactSingle = frame(0x20, 123n, 1);
  assert.equal(resourceZstdSize(new DataView(exactSingle.buffer, 0, 7)), 123);
});

void test("rejects bad magic, truncation, reserved flags, unknown size and unsafe sizes", () => {
  assert.throws(() => resourceZstdSize(new DataView(new ArrayBuffer(4))), /header/);
  assert.throws(() => resourceZstdSize(new DataView(new ArrayBuffer(3))),
    { message: "Invalid Zstandard frame header" });
  assert.throws(() => resourceZstdSize(new DataView(new ArrayBuffer(18))), /header/);
  const magicOnly = frame(0x20, 0n);
  assert.throws(() => resourceZstdSize(new DataView(magicOnly.buffer, 0, 5)),
    { message: "Truncated Zstandard content size" });
  assert.throws(() => resourceZstdSize(frame(0x28, 1n)), /flags/);
  assert.throws(() => resourceZstdSize(frame(0x30, 1n)), /flags/);
  assert.throws(() => resourceZstdSize(frame(0, 0n)), /unknown/);
  const valid = frame(0xe0, 1n);
  assert.throws(() => resourceZstdSize(new DataView(valid.buffer, 0, 12)), /Truncated/);
  assert.throws(() => resourceZstdSize(frame(0xe0, 2n ** 53n)), /safe/);
  assert.equal(resourceZstdSize(frame(0xe0, 2n ** 53n - 1n)), Number.MAX_SAFE_INTEGER);
});
