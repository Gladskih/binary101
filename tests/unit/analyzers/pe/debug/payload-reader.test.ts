import assert from "node:assert/strict";
import { test } from "node:test";
import { readDebugPayload, readDebugPayloadBytes }
  from "../../../../../analyzers/pe/debug/payload-reader.js";
import { createPeRvaFragments } from "../../../../helpers/pe-rva-fragments.js";

void test("debug payload RVA reads join fragments and honor relative offsets", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 1);
  assert.deepEqual([...await readDebugPayloadBytes(fixture.reader, fixture.mapping,
    0x1000, 0, 1, 3)], [2, 3, 4]);
  assert.equal((await readDebugPayload(fixture.reader, fixture.mapping,
    0x100000000, 0, 0, 4)).byteLength, 0);
});

void test("debug file pointers take precedence over an unmapped RVA", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(1, 2, 3, 4), 4);
  assert.deepEqual([...await readDebugPayloadBytes(fixture.reader, () => null,
    0x1000, 16, 1, 3)], [2, 3, 4]);
});
