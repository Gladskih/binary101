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
  void test(`validates a ${length}-byte name independently of retained text`, async () => {
    const { names, reads } = stringImage(length + 1, length);

    const result = await names.read(0);

    assert.deepEqual(result, { value: length <= 511 ? "A".repeat(length) : null });
    assert.equal(names.exhausted, false);
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
    assert.equal(names.exhausted, false);
  });
}
void test("honors DataView bounds and byte offsets", async () => {
  const fixture = createItaniumFixture();
  fixture.image.read = async () => new DataView(new Uint8Array([0, 65, 66, 0, 90]).buffer, 1, 3);

  assert.deepEqual(await createNameStrings(fixture.image).read(0), { value: "AB" });
});

void test("shares the scan budget across distinct strings and counts only inspected bytes", async () => {
  // Resource policy: 64 MiB per image, including terminating NULs.
  const { names } = stringImage(64 * 1024 * 1024, 64 * 1024 * 1024 - 1);

  assert.deepEqual(await names.read(0), { value: null });
  assert.equal(names.exhausted, false);
  assert.equal(await names.read(1), null);
  assert.equal(names.exhausted, true);
});

void test("stops before reading beyond the scan budget", async () => {
  const { names, reads } = stringImage(64 * 1024 * 1024 + 1, -1);

  assert.equal(await names.read(0), null);
  assert.equal(names.exhausted, true);
  assert.equal(reads.length, 16384);
});

void test("limits the last request to the remaining budget", async () => {
  const fixture = createItaniumFixture();
  const requests: number[] = [];
  fixture.image.read = async (address, size) => {
    requests.push(size);
    return new DataView(address === 0 ? new Uint8Array([65, 0]).buffer :
      new Uint8Array(size).fill(65).buffer);
  };
  const names = createNameStrings(fixture.image);

  assert.deepEqual(await names.read(0), { value: "A" });
  assert.equal(await names.read(1), null);
  assert.equal(names.exhausted, true);
  assert.equal(requests.at(-1), 4094);
});

void test("counts a NUL at the beginning of a chunk against the shared budget", async () => {
  const fixture = createItaniumFixture();
  const requests: number[] = [];
  fixture.image.read = async (address, size) => {
    requests.push(size);
    return new DataView(address === 0 ? new Uint8Array([0]).buffer :
      new Uint8Array(size).fill(65).buffer);
  };
  const names = createNameStrings(fixture.image);

  assert.equal(await names.read(0), null);
  assert.equal(await names.read(1), null);
  assert.equal(names.exhausted, true);
  assert.equal(requests.at(-1), 4095);
});
