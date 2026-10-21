import assert from "node:assert/strict";
import { test } from "node:test";
import { readDebugPayload, readDebugPayloadBytes, createDebugPayloadReader }
  from "../../../../../analyzers/pe/debug/payload-reader.js";
import { createPeRvaFragments } from "../../../../helpers/pe-rva-fragments.js";

void test("debug payload RVA reads join fragments and honor relative offsets", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 1);
  assert.deepEqual([...await readDebugPayloadBytes(fixture.reader, fixture.mapping,
    0x1000, 0, 1, 3)], [2, 3, 4]);
  assert.equal((await readDebugPayload(fixture.reader, fixture.mapping,
    0x100000000, 0, 0, 4)).byteLength, 0);
});

void test("bounded debug payload readers clamp reads to the payload instead of following adjacent bytes", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 1);
  const reader = createDebugPayloadReader(fixture.reader, fixture.mapping, 0x1000, 0, 3);

  assert.equal(reader.size, 3);
  assert.deepEqual([...await reader.readBytes(1, 99)], [2, 3]);
  assert.equal((await reader.read(3, 1)).byteLength, 0);
});

for (const [offset, size] of [[-1, 1], [NaN, 1], [Infinity, 1], [0.5, 1], [4, 1], [5, 1],
  [0, -1], [0, 0], [0, NaN], [0, Infinity], [0, 0.5]] as const) {
  void test(`bounded debug payload reader rejects an invalid relative range ${offset}/${size}`, async context => {
    const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 1);
    const read = context.mock.method(fixture.reader, "read");
    const reader = createDebugPayloadReader(fixture.reader, fixture.mapping, 0x1000, 16, 4);

    assert.equal((await reader.read(offset, size)).byteLength, 0);
    assert.equal(read.mock.callCount(), 0);
  });
}

for (const size of [-1, NaN, Infinity, 0.5]) {
  void test(`bounded debug payload reader does not expose an invalid extent ${size}`, async () => {
    const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 1);
    const reader = createDebugPayloadReader(fixture.reader, fixture.mapping, 0x1000, 0, size);

    assert.equal(reader.size, 0);
    assert.equal((await reader.read(0, 1)).byteLength, 0);
  });
}

void test("debug file pointers take precedence over an unmapped RVA", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 4);
  assert.deepEqual([...await readDebugPayloadBytes(fixture.reader, () => null,
    0x1000, 16, 1, 3)], [2, 3, 4]);
});
