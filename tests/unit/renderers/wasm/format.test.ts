import assert from "node:assert/strict";
import { test } from "node:test";
import { formatDescriptor, formatExpression, formatLimits, formatSignature } from "../../../../renderers/wasm/format.js";

void test("formats signatures and expression operands", () => {
  assert.equal(formatSignature({ params: ["i32"], results: ["i64"] }), "(i32) → (i64)");
  assert.equal(formatSignature(undefined), "Unresolved type");
  assert.equal(formatSignature({ params: ["i32", "i64"], results: ["f32", "f64"] }),
    "(i32, i64) → (f32, f64)");
  assert.equal(formatExpression([{ offset: 0, mnemonic: "i32.const", operands: "42" },
    { offset: 2, mnemonic: "end", operands: "" }]), "i32.const 42; end");
});

void test("formats descriptors and 64-bit limits without losing precision", () => {
  const limits = { min: 9007199254740993n, max: null, shared: true, address64: true };
  assert.equal(formatLimits(limits), "9007199254740993..unbounded, 64-bit, shared");
  assert.equal(formatDescriptor({ kind: "memory", limits }), "9007199254740993..unbounded, 64-bit, shared");
  assert.equal(formatDescriptor({ kind: "table", table: { type: "funcref", limits } }),
    "funcref, 9007199254740993..unbounded, 64-bit, shared");
  assert.equal(formatDescriptor({ kind: "function", typeIndex: 1 }), "type 1");
  assert.equal(formatDescriptor({ kind: "tag", typeIndex: 2 }), "type 2");
  assert.equal(formatDescriptor({ kind: "global", global: { type: "i32", mutable: true } }), "i32, mutable");
  assert.equal(formatDescriptor({ kind: "global", global: { type: "i32", mutable: false } }), "i32, constant");
  assert.equal(formatLimits({ min: 1n, max: 2n, shared: false, address64: false }), "1..2, 32-bit");
  assert.equal(formatLimits({ min: 0n, max: 0n, shared: false, address64: false }), "0..0, 32-bit");
});
