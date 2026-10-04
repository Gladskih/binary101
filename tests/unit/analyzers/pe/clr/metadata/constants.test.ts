"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseConstant } from "../../../../../../analyzers/pe/clr/metadata-constants.js";

void test("decodes signed constants, UTF-16 and the CLASS null encoding", () => {
  // ECMA-335 II.22.9: I1=4, I8=10, STRING=14, CLASS=18.
  assert.deepEqual(parseConstant(Uint8Array.of(0xff), 4, "Constant"), { kind: "constant", value: -1 });
  assert.deepEqual(parseConstant(new Uint8Array(8).fill(0xff), 10, "Constant"), { kind: "constant", value: "-1" });
  assert.deepEqual(parseConstant(Uint8Array.of(0xff, 0xfe, 65, 0), 14, "Constant"), { kind: "constant", value: "\ufeffA" });
  assert.deepEqual(parseConstant(new Uint8Array(4), 18, "Constant"), { kind: "constant", value: null });
});

void test("warns on unsupported encodings without losing their bytes", () => {
  assert.deepEqual(parseConstant(Uint8Array.of(7), 0x55, "Constant"), {
    kind: "constant", value: [7], issues: ["Constant constant type 0x55 is unsupported."]
  });
  assert.match(parseConstant(Uint8Array.of(1), 18, "Constant").issues![0]!, /four zero bytes/);
  assert.match(parseConstant(Uint8Array.of(0), 18, "Constant").issues![0]!, /four zero bytes/);
  assert.match(parseConstant(Uint8Array.of(0, 0, 0, 1), 18, "Constant").issues![0]!, /four zero bytes/);
  assert.match(parseConstant(Uint8Array.of(1), 0x104, "Constant").issues![0]!, /padding/);
});

void test("reports truncated primitives, surplus bytes and odd strings", () => {
  assert.equal(parseConstant(new Uint8Array(), 8, "Constant").value, null);
  assert.ok(parseConstant(new Uint8Array(), 8, "Constant").issues?.length);
  assert.match(parseConstant(Uint8Array.of(1, 2), 4, "Constant").issues![0]!, /trailing/);
  assert.ok(parseConstant(Uint8Array.of(1), 14, "Constant").issues?.length);
});

// ECMA-335 II.22.9 Constant.Type encoding, checked independently of parser tables.
for (const [type, bytes, value] of [
  [2, [1], true], [3, [65, 0], "A"], [5, [255], 255], [6, [255, 255], -1],
  [7, [255, 255], 65535], [8, [255, 255, 255, 255], -1], [9, [255, 255, 255, 255], 4294967295],
  [11, new Array<number>(8).fill(255), "0xffffffffffffffff"],
  [12, [0, 0, 128, 63], 1], [13, [0, 0, 0, 0, 0, 0, 240, 63], 1]
] as const) {
  void test(`decodes Constant.Type ${type}`, () => {
    assert.deepEqual(parseConstant(Uint8Array.from(bytes), type, "Constant"), { kind: "constant", value });
  });
}

void test("accepts null's exact four-byte encoding without spurious warnings", () => {
  assert.deepEqual(parseConstant(Uint8Array.of(0, 0, 0, 0), 18, "Constant"), { kind: "constant", value: null });
});
