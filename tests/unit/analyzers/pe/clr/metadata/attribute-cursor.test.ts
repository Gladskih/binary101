"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomAttributeValue } from "../../../../../../analyzers/pe/clr/metadata-attributes.js";
import { AttributeCursor } from "../../../../../../analyzers/pe/clr/metadata-attribute-cursor.js";

const boxedArrayBlob = (depth: number): Uint8Array => Uint8Array.of(
  1, 0, // ECMA-335 II.23.3 attribute prolog.
  ...Array.from({ length: depth }, () => [0x1d, 0x51, 1, 0, 0, 0]).flat(),
  // Each boxed object[] has one element; the innermost element is a boxed I4.
  0x08, 0, 0, 0, 0,
  0, 0 // NumNamed.
);

void test("decodes deeply nested boxed attribute arrays without a stack overflow", () => {
  const decoded = decodeCustomAttributeValue(boxedArrayBlob(10000), ["object"], "Deep boxes");
  assert.equal(decoded.issues, undefined);
  assert.deepEqual(decoded.namedArguments, []);
  assert.equal(decoded.fixedArguments[0]?.value, "0");
});

void test("allows ordinary boxed arrays and independent arguments", () => {
  const decoded = decodeCustomAttributeValue(boxedArrayBlob(2), ["object"], "Boxes");
  assert.equal(decoded.fixedArguments[0]?.value, "0");
  assert.equal(decoded.issues, undefined);
});

void test("accepts boxed values on both sides of the former depth limit", () => {
  assert.equal(decodeCustomAttributeValue(boxedArrayBlob(62), ["object"], "Boundary").issues, undefined);
  assert.equal(decodeCustomAttributeValue(boxedArrayBlob(63), ["object"], "Beyond")
    .issues, undefined);
});

void test("releases depth between independent boxed arguments", () => {
  const blob = Uint8Array.of(1, 0,
    ...Array.from({ length: 70 }, () => [8, 0, 0, 0, 0]).flat(), 0, 0);
  const decoded = decodeCustomAttributeValue(blob, new Array<string>(70).fill("object"), "Independent");
  assert.equal(decoded.fixedArguments.length, 70);
  assert.equal(decoded.issues, undefined);
});

const sequentialValues = (): Uint8Array => {
  const bytes = new Uint8Array(17);
  const view = new DataView(bytes.buffer);
  bytes[0] = 0x7f;
  view.setFloat32(1, 1.25, true);
  view.setFloat64(5, -2.5, true);
  bytes.set([0xff, 1, 0x41, 0], 13); // ECMA-335 II.23.3: null, "A" and empty SerStrings.
  return bytes;
};

void test("advances across floats and strings within a bounded byte view", () => {
  const issues: string[] = [];
  const cursor = new AttributeCursor(Uint8Array.of(0, ...sequentialValues()).subarray(1), issues, "Values");
  assert.equal(cursor.readU8(), 0x7f);
  assert.equal(cursor.readF32(), 1.25);
  assert.equal(cursor.readF64(), -2.5);
  assert.equal(cursor.readSerString(), null);
  assert.equal(cursor.readSerString(), "A");
  assert.equal(cursor.readSerString(), "");
  assert.equal(cursor.remaining, 0);
  assert.deepEqual(issues, []);
});

void test("reports truncated scalar and string reads", () => {
  const issues: string[] = [];
  const cursor = new AttributeCursor(new Uint8Array(), issues, "Truncated");
  assert.equal(cursor.readF32(), null);
  assert.equal(cursor.readF64(), null);
  assert.equal(cursor.readSerString(), null);
  assert.match(issues[0] ?? "", /blob is truncated/);
  assert.match(issues[1] ?? "", /blob is truncated/);
  assert.match(issues[2] ?? "", /string is truncated/);
});
