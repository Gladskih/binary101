import assert from "node:assert/strict";
import { test } from "node:test";
import { readThumbMovePair } from "../../../../../analyzers/pe/code-thunks/thumb-move.js";

const pair = (): DataView => {
  // LLVM LLD applyMOV/readMOV: MOVW ip,#0xabcd; MOVT ip,#0x1234.
  // https://github.com/llvm/llvm-project/blob/main/lld/COFF/Chunks.cpp#L156
  const view = new DataView(new ArrayBuffer(8));
  view.setUint16(0, 0xf64a, true);
  view.setUint16(2, 0x3ccd, true);
  view.setUint16(4, 0xf2c1, true);
  view.setUint16(6, 0x2c34, true);
  return view;
};

void test("PE Thumb address materialization combines both scattered immediates", () => {
  assert.equal(readThumbMovePair(pair(), 0, 12), 0x1234abcd);
});

for (const [offset, register] of [[-1, 12], [0.5, 12], [1, 12], [0, -1], [0, 16], [0, 1.5], [0, 1]]) {
  void test(`Thumb address pair rejects offset ${offset} and register ${register}`, () => {
    assert.equal(readThumbMovePair(pair(), offset!, register!), null);
  });
}

void test("Thumb address pair rejects a mismatched MOVT and short reads", () => {
  const view = pair();
  view.setUint16(4, 0, true);
  assert.equal(readThumbMovePair(view, 0, 12), null);
  assert.equal(readThumbMovePair(new DataView(new ArrayBuffer(7)), 0, 12), null);
});

for (const register of [0, 15]) {
  void test(`Thumb address pairs allow boundary register ${register}`, () => {
    const view = pair();
    view.setUint16(2, 0x30cd | (register << 8), true);
    view.setUint16(6, 0x2034 | (register << 8), true);
    assert.equal(readThumbMovePair(view, 0, register), 0x1234abcd);
  });
}

void test("a truncated otherwise valid Thumb pair returns null before reading its last halfword", () => {
  const view = new DataView(pair().buffer, 0, 7);
  assert.equal(readThumbMovePair(view, 0, 12), null);
});
