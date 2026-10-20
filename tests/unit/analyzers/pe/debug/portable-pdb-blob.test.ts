import assert from "node:assert/strict";
import { test } from "node:test";
import { PortablePdbBlobReader } from "../../../../../analyzers/pe/debug/portable-pdb-blob.js";

void test("Portable PDB blob reader checks fixed-width values and preserves byte offsets", () => {
  const reader = new PortablePdbBlobReader(Uint8Array.of(99, 1, 2, 3, 4, 255, 255, 255, 255, 0));

  assert.equal(reader.byte(), 99);
  assert.equal(reader.uint32(), 0x04030201); // Little-endian fixed-width integer.
  assert.equal(reader.int32(), -1);
  assert.deepEqual(reader.take(0), new Uint8Array());
  assert.equal(reader.remaining, 1);
  assert.throws(() => reader.finish(), /trailing/);
  assert.equal(reader.byte(), 0);
  assert.equal(reader.remaining, 0);
  assert.doesNotThrow(() => reader.finish());
  assert.throws(() => reader.byte(), /truncated/);
});

void test("Portable PDB blob reader decodes terminated UTF-8 text without stripping BOM", () => {
  const reader = new PortablePdbBlobReader(new TextEncoder().encode("\ufefftext\0\0"));

  assert.equal(reader.utf8z(), "\ufefftext");
  assert.equal(reader.utf8z(), "");
  assert.throws(() => reader.utf8z(), /terminat/);
  assert.throws(() => new PortablePdbBlobReader(Uint8Array.of(255, 0)).utf8z(), /encoded data|UTF-8/);
  assert.throws(() => new PortablePdbBlobReader(Uint8Array.of(1)).utf8z(), /terminat/);
});

[
  { bytes: [0], unsigned: 0, signed: 0 },
  { bytes: [127], unsigned: 127, signed: -1 },
  { bytes: [128, 128], unsigned: 128, signed: 64 },
  { bytes: [191, 255], unsigned: 16383, signed: -1 },
  { bytes: [192, 0, 64, 0], unsigned: 16384, signed: 8192 },
  { bytes: [223, 255, 255, 255], unsigned: 0x1fffffff, signed: -1 }
].forEach(({ bytes, unsigned, signed }) => {
  void test(`Portable PDB blob reader handles ${bytes.length}-byte compressed value ${unsigned}`, () => {
    assert.equal(new PortablePdbBlobReader(Uint8Array.from(bytes)).compressed(), unsigned);
    assert.equal(new PortablePdbBlobReader(Uint8Array.from(bytes)).signed(), signed);
  });
});

[[], [128], [192, 0, 0], [224]].forEach(bytes => {
  void test(`Portable PDB blob reader rejects malformed compressed bytes ${bytes}`, () => {
    assert.throws(() => new PortablePdbBlobReader(Uint8Array.from(bytes)).compressed(), /compressed/);
    assert.throws(() => new PortablePdbBlobReader(Uint8Array.from(bytes)).signed(), /compressed/);
  });
});

[-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER].forEach(size => {
  void test(`Portable PDB blob reader rejects invalid byte span ${size}`, () => {
    assert.throws(() => new PortablePdbBlobReader(Uint8Array.of(0)).take(size), /truncated|size/);
  });
});

void test("Portable PDB blob reader bounds counts by bytes before iteration", () => {
  const reader = new PortablePdbBlobReader(Uint8Array.of(2, 0, 0));

  assert.equal(reader.count(), 2);
  assert.throws(() => new PortablePdbBlobReader(Uint8Array.of(3, 0, 0)).count(), /count/);
  assert.equal(new PortablePdbBlobReader(Uint8Array.of(0)).count(), 0);
});
