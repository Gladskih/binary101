import assert from "node:assert/strict";
import { test } from "node:test";
import { createRvaToOffsetMapper } from "../../../../../analyzers/pe/sections/rva-mapper.js";
import { readMappedRvaPrefix } from "../../../../../analyzers/pe/rva-byte-reader.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import type { PeSection } from "../../../../../analyzers/pe/types.js";

const section = (virtualAddress: number, virtualSize: number, pointerToRawData: number): PeSection => ({
  name: { kind: "inline", value: ".data" }, virtualAddress, virtualSize, pointerToRawData,
  sizeOfRawData: virtualSize, characteristics: 0
});

void test("span mapping preserves precedence when earlier sections interrupt later sections", () => {
  const map = createRvaToOffsetMapper([section(20, 4, 80), section(16, 16, 32)], 128, 8, 8);
  assert.deepEqual(map.span?.(16), { offset: 32, size: 4 });
  assert.deepEqual(map.span?.(20), { offset: 80, size: 4 });
  assert.deepEqual(map.span?.(24), { offset: 40, size: 8 });
  assert.deepEqual(map.span?.(0), { offset: 0, size: 8 });
  assert.equal(map(8), null);
  assert.equal(map(-1), null);
  assert.equal(map(NaN), null);
  assert.equal(map(0x100000000), null);
});

void test("span mapping stops at virtual tails, file ends and the RVA limit", () => {
  const map = createRvaToOffsetMapper([
    { ...section(16, 16, 32), sizeOfRawData: 4 },
    section(0xfffffff8, 16, 0)
  ], 64, 4, 8);
  assert.equal(map(0), null);
  assert.deepEqual(map.span?.(16), { offset: 32, size: 4 });
  assert.equal(map(20), null);
  assert.deepEqual(map.span?.(0xfffffff8), { offset: 0, size: 8 });
  const eof = createRvaToOffsetMapper([section(16, 16, 62)], 64, 0, 0);
  assert.deepEqual(eof.span?.(16), { offset: 62, size: 2 });
  assert.equal(eof(18), null);
});

void test("large mapped reads use section spans and preserve the existing data view", async () => {
  const bytes = new Uint8Array(65536);
  const mapping = createRvaToOffsetMapper([section(0x1000, bytes.length, 0)], bytes.length, 0, 0);
  let calls = 0;
  const span = mapping.span!;
  mapping.span = rva => { calls += 1; return span(rva); };
  const view = await readMappedRvaPrefix(new MockFile(bytes), 0x1000, bytes.length, mapping);
  assert.equal(view.byteLength, bytes.length);
  assert.equal(calls, 1);
});

void test("raw padding stops at VirtualSize and zero VirtualSize uses raw size", () => {
  const map = createRvaToOffsetMapper([
    { ...section(16, 2, 32), sizeOfRawData: 8 },
    { ...section(32, 0, 48), sizeOfRawData: 8 }
  ], 64, 8, 8);
  assert.deepEqual(map.span?.(17), { offset: 33, size: 1 });
  assert.equal(map(18), null);
  assert.deepEqual(map.span?.(33), { offset: 49, size: 7 });
  assert.deepEqual(map.span?.(3), { offset: 3, size: 5 });
});
