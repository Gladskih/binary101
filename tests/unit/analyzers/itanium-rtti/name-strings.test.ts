import assert from "node:assert/strict";
import { test } from "node:test";
import { createNameStrings } from "../../../../analyzers/itanium-rtti/name-strings.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";

const stringImage = (length: number, end: number) => {
  const fixture = createItaniumFixture();
  const reads: number[] = [];
  fixture.image.read = async (address, size) => {
    reads.push(address);
    const bytes = new Uint8Array(Math.max(0, Math.min(size, length - address))).fill(65);
    if (end >= address && end < address + bytes.length) bytes[end - address] = 0;
    return new DataView(bytes.buffer);
  };
  return { names: createNameStrings(fixture.image), reads };
};

for (const length of [1, 511, 512, 4095, 4096, 8193]) {
  void test(`retains a complete ${length}-byte name`, async () => {
    const { names, reads } = stringImage(length + 1, length);

    const result = await names.read(0);

    assert.deepEqual(result, { value: "A".repeat(length) });
    assert.deepEqual(reads, Array.from({ length: Math.ceil((length + 1) / 4096) },
      (_, index) => index * 4096));
    assert.equal(await names.read(0), result);
    assert.equal(reads.length, Math.ceil((length + 1) / 4096));
  });
}
for (const [length, end] of [[0, -1], [1, 0], [1, -1], [4096, -1], [8193, -1]]) {
  void test(`rejects empty or unterminated data (${length}, ${end})`, async () => {
    const { names } = stringImage(length!, end!);

    assert.equal(await names.read(0), null);
  });
}
void test("honors DataView bounds and byte offsets", async () => {
  const fixture = createItaniumFixture();
  fixture.image.read = async () => new DataView(new Uint8Array([0, 65, 66, 0, 90]).buffer, 1, 3);

  assert.deepEqual(await createNameStrings(fixture.image).read(0), { value: "AB" });
});
