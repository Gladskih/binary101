import assert from "node:assert/strict";
import test from "node:test";
import { ReadyToRunSignatureCursor } from "../../../../../analyzers/pe/clr/ready-to-run-signature-cursor.js";
import { skipReadyToRunType } from "../../../../../analyzers/pe/clr/ready-to-run-type-grammar.js";

const finishType = (bytes: Uint8Array): number => {
  const cursor = new ReadyToRunSignatureCursor(bytes, 0);
  skipReadyToRunType(cursor);
  return cursor.offset;
};

void test("R2R types consume primitive, canonical and high-bit element encodings", () => {
  assert.equal(finishType(Uint8Array.of(8)), 1);
  assert.equal(finishType(Uint8Array.of(0x3e)), 1);
  assert.equal(finishType(Uint8Array.of(0x88)), 1);
});

void test("R2R types consume nested pointers, byrefs, arrays, pinned types and modifiers", () => {
  const bytes = Uint8Array.of(0x0f, 0x10, 0x1d, 0x45, 0x1f, 4, 0x20, 5, 0x3f, 2, 0x12, 4);

  assert.equal(finishType(bytes), bytes.length);
});

void test("R2R types consume generic variables and generic instantiations", () => {
  assert.equal(finishType(Uint8Array.of(0x13, 0x80, 0xff)), 3);
  assert.equal(finishType(Uint8Array.of(0x1e, 1)), 2);
  const bytes = Uint8Array.of(0x15, 0x11, 4, 2, 8, 0x15, 0x12, 5, 0);
  assert.equal(finishType(bytes), bytes.length);
});

void test("R2R types consume multidimensional array sizes and signed bounds", () => {
  const bytes = Uint8Array.of(0x14, 8, 2, 2, 3, 4, 2, 1, 0);

  assert.equal(finishType(bytes), bytes.length);
  assert.equal(finishType(Uint8Array.of(0x14, 8, 0)), 3);
});

void test("R2R types consume function pointers with generics, varargs and sentinel parameters", () => {
  const generic = Uint8Array.of(0x1b, 0x10, 1, 1, 1, 8);
  const varargs = Uint8Array.of(0x1b, 5, 2, 1, 8, 0x41, 0x41, 14);

  assert.equal(finishType(generic), generic.length);
  assert.equal(finishType(varargs), varargs.length);
  assert.equal(finishType(Uint8Array.of(0x1b, 0, 0, 1)), 4);
  assert.equal(finishType(Uint8Array.of(0x1b, 5, 1, 1, 0xc1, 8)), 6);
});

void test("R2R type traversal has no arbitrary nesting cap", () => {
  const bytes = new Uint8Array(10001).fill(0x0f);
  bytes[bytes.length - 1] = 8;

  assert.equal(finishType(bytes), bytes.length);
});

void test("R2R type traversal rejects unknown and incomplete encodings", () => {
  assert.throws(() => finishType(Uint8Array.of(0x40)), /Unsupported/);
  assert.throws(() => finishType(Uint8Array.of(0x0f)), /truncated/);
  assert.throws(() => finishType(Uint8Array.of(0x15, 0x12, 4, 2, 8)), /count exceeds/);
  assert.throws(() => finishType(Uint8Array.of(0x1b, 0, 1, 1)), /count exceeds|truncated/);
});

void test("R2R arrays reject more sizes or lower bounds than their rank", () => {
  assert.throws(() => finishType(Uint8Array.of(0x14, 8, 1, 2, 3, 4)), /size count/);
  assert.throws(() => finishType(Uint8Array.of(0x14, 8, 1, 0, 2, 0, 0)), /lower-bound count/);
});
