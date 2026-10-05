import assert from "node:assert/strict";
import { test } from "node:test";
import { nativeAotFieldSignature, nativeAotMethodSignature } from
  "../../../../renderers/native-aot/member-signatures.js";

void test("formats signatures and preserves names when a signature was unavailable", () => {
  assert.equal(nativeAotMethodSignature({ name: "Unknown" }), "Unknown");
  assert.equal(nativeAotFieldSignature({ name: "Count" }), "Count");
  assert.equal(nativeAotFieldSignature({ name: "Count", type: "System.Int32" }), "System.Int32 Count");
  assert.equal(nativeAotMethodSignature({ name: "Run", signature: {
    callingConvention: 0, genericParameterCount: 2, returnType: "System.Void",
    parameters: [], varArgParameters: []
  } }), "System.Void Run<arity=2>()");
  assert.equal(nativeAotMethodSignature({ name: "Run", signature: {
    callingConvention: 5, genericParameterCount: 0, returnType: "System.Void",
    parameters: [], varArgParameters: ["System.Int32"]
  } }), "System.Void Run(..., System.Int32)");
  assert.equal(nativeAotMethodSignature({ name: "Run", signature: {
    callingConvention: 5, genericParameterCount: 0, returnType: "System.Void",
    parameters: ["System.String"], varArgParameters: ["System.Int32"]
  } }), "System.Void Run(System.String, ..., System.Int32)");
});

void test("separates multiple named generics, parameters and varargs", () => {
  assert.equal(nativeAotMethodSignature({ name: "Call", signature: {
    callingConvention: 0, genericParameterCount: 2, returnType: "R",
    parameters: ["P", "Q"], varArgParameters: ["A", "B"]
  }, genericParameters: [
    { name: "T", number: 0, flags: 0, kind: 1, constraints: [] },
    { name: "U", number: 1, flags: 0, kind: 1, constraints: [] }
  ] }), "R Call<T, U>(P, Q, ..., A, B)");
});
