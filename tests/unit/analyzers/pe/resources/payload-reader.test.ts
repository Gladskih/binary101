import assert from "node:assert/strict";
import { test } from "node:test";
import { createResourcePayloadReader } from "../../../../../analyzers/pe/resources/payload-reader.js";
import { readResourceLeafBytes } from "../../../../../analyzers/pe/resources/preview/leaf-data.js";
import { createPeRvaFragments } from "../../../../helpers/pe-rva-fragments.js";

void test("resource preview reads mapped payload bytes across file fragments", async () => {
  const fixture = createPeRvaFragments(0x2000, Uint8Array.of(1, 2, 3, 4), 1);
  const reader = createResourcePayloadReader(fixture.reader, fixture.mapping);
  const result = await readResourceLeafBytes(reader, {
    lang: 0, dataRVA: 0x2000, dataFileOffset: 16, size: 4, codePage: 0, reserved: 0
  });
  assert.deepEqual(result.data, Uint8Array.of(1, 2, 3, 4));
  assert.equal(result.issues, undefined);
  assert.equal(reader.size, fixture.reader.size);
  assert.deepEqual([...await reader.readBytes(16, 1)], [1]);
  assert.equal((await reader.read(16, 1)).getUint8(0), 1);
});
