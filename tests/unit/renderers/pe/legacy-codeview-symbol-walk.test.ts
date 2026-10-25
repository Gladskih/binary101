import assert from "node:assert/strict";
import { test } from "node:test";
import { iterateLegacyCodeViewSymbols } from "../../../../renderers/pe/legacy-codeview-symbol-walk.js";
import { codeViewSymbolTree } from "../../../fixtures/pe-codeview-embedded-symbols.js";

void test("CodeView symbol traversal retains physical ordering and immediate container identity", () => {
  const named = { type: 0x110e, name: "nested" };

  assert.deepEqual([...iterateLegacyCodeViewSymbols({ kind: "symbols", records: [
    { type: 0xe, children: [named] }, { type: 0x113b, children: [named, { type: 6 }] }, named
  ] })], [
    { record: { type: 0xe, children: [named] } }, { record: named, container: "This pointer" },
    { record: { type: 0x113b, children: [named, { type: 6 }] } },
    { record: named, container: "Discarded symbols", addressContext: "discarded" },
    { record: { type: 6 }, container: "Discarded symbols", addressContext: "discarded" },
    { record: named }
  ]);
});

void test("CodeView symbol traversal handles deep trees without recursion or growing ancestry strings", () => {
  const depth = 2048;
  const nodes = [...iterateLegacyCodeViewSymbols({ kind: "symbols", records: [codeViewSymbolTree(depth)] })];

  assert.equal(nodes.length, depth + 1);
  assert.deepEqual(nodes.at(-1), { record: { type: 0x110e, name: "deep" }, container: "This pointer" });
  assert.ok(nodes.slice(1).every(node => node.container === "This pointer"));
});

void test("CodeView symbol traversal includes symbols embedded in type leaves", () => {
  assert.deepEqual([...iterateLegacyCodeViewSymbols({ kind: "types", records: [
    { type: 0x20c, symbols: [{ type: 0xe, children: [{ type: 0x110e, name: "value" }] }] },
    { type: 2, symbols: [{ type: 0x110d, name: "base" }] }, { type: 3, name: "array" }
  ] })], [
    { record: { type: 0xe, children: [{ type: 0x110e, name: "value" }] }, container: "Referenced symbol", addressContext: "type" },
    { record: { type: 0x110e, name: "value" }, container: "This pointer", addressContext: "type" },
    { record: { type: 0x110d, name: "base" }, container: "Pointer", addressContext: "type" }
  ]);
  assert.deepEqual([...iterateLegacyCodeViewSymbols({ kind: "libraries", names: ["library"] })], []);
  assert.deepEqual([...iterateLegacyCodeViewSymbols({ kind: "symbols", records: [] })], []);
});
