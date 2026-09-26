import assert from "node:assert/strict";
import { test } from "node:test";
import { SltgReader } from "../../../../../analyzers/pe/type-library/sltg-reader.js";
import { readSltgType } from "../../../../../analyzers/pe/type-library/sltg-descriptors.js";

const typeReader = (...words: number[]): SltgReader => {
  const data = new Uint8Array(words.length * 2);
  const view = new DataView(data.buffer);
  words.forEach((word, index) => view.setUint16(index * 2, word, true));
  return new SltgReader(data, []);
};

for (const [flags, expected] of [[0, 1], [0xc000, 0], [0x8000, 3], [0x4000, 2],
  [0x2000, 5], [0x80, 9]] as const) {
  void test(`SLTG parameter modifiers ${flags}`, () => {
    assert.deepEqual(readSltgType(typeReader(flags | 3), 0), { type: "long", flags: expected, next: 2 });
  });
}

void test("SLTG pointer modifiers, pointer records and safearrays compose", () => {
  assert.equal(readSltgType(typeReader(0xe03), 0).type, "long*");
  assert.equal(readSltgType(typeReader(26, 3), 0).type, "long*");
  assert.equal(readSltgType(typeReader(27, 0, 26, 3), 0).type, "SAFEARRAY(long*)");
});

void test("SLTG user-defined types resolve their reference table indexes", () => {
  const reader = typeReader(29, 4);
  reader.references.set(1, 100);
  assert.equal(readSltgType(reader, 0).type, "href(100)");
  assert.equal(readSltgType(typeReader(29, 4), 0).type, "href(-1)");
});

void test("SLTG array descriptors preserve lower bounds", () => {
  const data = new Uint8Array(32);
  const view = new DataView(data.buffer);
  view.setUint16(0, 28, true);
  view.setUint16(2, 8, true);
  view.setUint16(4, 3, true);
  view.setUint16(8, 1, true);
  view.setUint32(24, 3, true);
  view.setInt32(28, -1, true);
  assert.equal(readSltgType(new SltgReader(data, []), 0).type, "long[-1..1]");
});

for (const dimensions of [0, 0xffff, 1]) {
  void test(`SLTG arrays reject invalid dimensions or truncated bounds ${dimensions}`, () => {
    const reader = typeReader(28, 8, 3, 0, dimensions);
    assert.equal(readSltgType(reader, 0).type, "long[invalid bounds]");
    assert.ok(reader.issues.length);
  });
}

void test("SLTG type expressions reject missing words", () => {
  const reader = typeReader(26);
  assert.equal(readSltgType(reader, 0).type, "invalid type");
  assert.equal(readSltgType(typeReader(), 0).type, "invalid type");
  assert.match(reader.issues.join(), /truncated/);
});
