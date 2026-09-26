import assert from "node:assert/strict";
import { test } from "node:test";
import { SltgReader } from "../../../../../analyzers/pe/type-library/sltg-reader.js";
import { SltgHelpStrings } from "../../../../../analyzers/pe/type-library/sltg-help.js";

const helpReader = (table: number[], maximum = 32): SltgReader => {
  const data = new Uint8Array(6 + table.length);
  const view = new DataView(data.buffer);
  view.setUint16(0, maximum, true);
  view.setUint32(2, table.length, true);
  data.set(table, 6);
  return new SltgReader(data, []);
};

void test("SLTG Huffman help strings follow MSB-first branches and cache words", () => {
  const reader = helpReader([0x80, 0, 7, 0, 72, 105, 0, 0, 0]);
  const decoder = new SltgHelpStrings(reader, 0);
  assert.equal(decoder.decode(Uint8Array.from([0x80])), "Hi");
  assert.equal(decoder.decode(Uint8Array.from([0xc0])), "Hi Hi");
  assert.equal(decoder.decode(new Uint8Array()), null);
  assert.deepEqual(reader.issues, []);
});

void test("SLTG help strings can exactly fill the declared size", () => {
  const reader = helpReader([0x80, 0, 7, 0, 72, 105, 0, 0, 0], 2);
  assert.equal(new SltgHelpStrings(reader, 0).decode(Uint8Array.from([0x80])), "Hi");
  assert.deepEqual(reader.issues, []);
});

void test("SLTG help branches use big-endian offsets larger than one byte", () => {
  const table = new Array<number>(265).fill(0);
  table.splice(0, 3, 0x80, 1, 4);
  table.splice(260, 5, 0x80, 0, 3, 0, 0);
  const reader = helpReader(table);
  assert.equal(new SltgHelpStrings(reader, 0).decode(Uint8Array.from([0])), "");
  assert.deepEqual(reader.issues, []);
});

void test("SLTG help decoding stops when input bits end", () => {
  const reader = helpReader([0x80, 0, 7, 0, 72, 105, 0, 0, 0]);
  assert.equal(new SltgHelpStrings(reader, 0).decode(Uint8Array.from([255])),
    "Hi Hi Hi Hi Hi Hi Hi Hi");
});

for (const table of [[0x80, 255, 255, 0, 0], [0, 65], [0x80], []]) {
  void test(`SLTG malformed Huffman table ${table.length} bytes cannot throw`, () => {
    const reader = helpReader(table);
    assert.equal(new SltgHelpStrings(reader, 0).decode(Uint8Array.from([0])), "");
    assert.ok(reader.issues.length);
  });
}

void test("SLTG decoding limits output from a tree with a root leaf", () => {
  const reader = helpReader([0, 65, 0], 2);
  assert.equal(new SltgHelpStrings(reader, 0).decode(Uint8Array.from([0])), "A");
  assert.match(reader.issues.join(), /declared size/);
});

void test("SLTG help decoding reports a cyclic prefix tree", () => {
  const reader = helpReader([0x80, 0, 0, 0, 0]);
  const decoder = new SltgHelpStrings(reader, 0);
  assert.equal(decoder.decode(Uint8Array.from([0])), "");
  assert.equal(decoder.decode(Uint8Array.from([0])), "");
  assert.match(reader.issues.join(), /cycle/);
});

void test("SLTG help decoding fills the maximum representable declared output length", () => {
  // SLTG compressed-help buffer length is a WORD (maximum 65535).
  // https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c (decode_string)
  // Four 1-branches encode A; 0-branches end the string. Each output word takes four bits.
  const reader = helpReader([0x80, 0, 15, 0x80, 0, 15, 0x80, 0, 15, 0x80, 0, 15,
    0, 65, 0, 0, 0], 65535);
  assert.equal(new SltgHelpStrings(reader, 0).decode(new Uint8Array(16384).fill(255)),
    new Array<string>(32768).fill("A").join(" "));
  assert.deepEqual(reader.issues, []);
});

void test("SLTG help headers are bounded to the library block", () => {
  const reader = new SltgReader(new Uint8Array(), []);
  assert.equal(new SltgHelpStrings(reader, 0).decode(Uint8Array.from([0])), "");
  assert.ok(reader.issues.length);
});
