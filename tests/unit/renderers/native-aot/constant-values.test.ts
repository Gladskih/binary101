import assert from "node:assert/strict";
import test from "node:test";
import { nativeAotConstantText as text } from "../../../../renderers/native-aot/constant-values.js";

void test("constant text retains exact scalar semantics without displaying address-like encodings", () => {
  assert.equal(text({ type: "object", value: null }), "null");
  assert.equal(text({ type: "string", value: "<quoted>\n" }), '"<quoted>\\n"');
  assert.equal(text({ type: "char", value: "é" }), '"é"');
  assert.equal(text({ type: "long", value: "9007199254740993" }), "9007199254740993 (long)");
  assert.equal(text({ type: "bool", value: false }), "false (bool)");
  assert.equal(text({ type: "float", value: -0 }), "-0 (float)");
  assert.equal(text({ type: "double", value: Infinity }), "Infinity (double)");
  assert.equal(text({ type: "Type", value: "System.String" }), "typeof(System.String)");
  assert.equal(text({ type: "Example.Mode", value: 42 }), "42 (Example.Mode)");
});

void test("array overviews show stored type and count, including empty and nested arrays", () => {
  assert.equal(text({ type: "int[]", value: [] }), "int[] (0 elements)");
  assert.equal(text({ type: "object[]", value: [{ type: "int[]", value: [{ type: "int", value: 42 }] }] }),
    "object[] (1 elements)");
});
