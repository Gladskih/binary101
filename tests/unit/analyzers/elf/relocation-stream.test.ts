import assert from "node:assert/strict";
import { test } from "node:test";
import { ElfRelocationStream } from "../../../../analyzers/elf/relocation-stream.js";
import { packedRelocationFixture, encodeSigned, encodeUnsigned } from "../../../fixtures/elf-packed-relocations.js";

for (const value of [0n, 63n, 64n, -1n, -65n, -(1n << 63n), (1n << 63n) - 1n]) {
  void test(`SLEB128 reads ${value} including signed boundaries`, async () => {
    const { stream } = packedRelocationFixture(encodeSigned(value));
    assert.equal(await stream.signed(), value);
    assert.equal(stream.position, stream.end);
  });
}
for (const value of [0n, 127n, 128n, (1n << 64n) - 1n]) {
  void test(`ULEB128 reads ${value}`, async () => {
    const { stream } = packedRelocationFixture(encodeUnsigned(value));
    assert.equal(await stream.unsigned(), value);
  });
}
for (const bytes of [[], [0x80], Array<number>(10).fill(0xff), encodeUnsigned(1n << 64n)]) {
  void test(`ULEB128 rejects truncation or overflow: ${bytes.length} bytes`, async () => {
    const { stream } = packedRelocationFixture(bytes);
    await assert.rejects(stream.unsigned(), /truncated|overflows/);
  });
}
for (const bytes of [[0x80], Array<number>(10).fill(0xff), encodeSigned(1n << 63n), encodeSigned(-(1n << 63n) - 1n)]) {
  void test(`SLEB128 rejects truncation or overflow: ${bytes.join(",")}`, async () => {
    const { stream } = packedRelocationFixture(bytes);
    await assert.rejects(stream.signed(), /truncated|overflows/);
  });
}
void test("cursor detects a short read inside declared bounds", async () => {
  const stream = new ElfRelocationStream({ size: 1, read: async () => new DataView(new ArrayBuffer(0)),
    readBytes: async () => new Uint8Array() }, 0, 1);
  await assert.rejects(stream.byte(), /truncated packed relocation read/);
});
