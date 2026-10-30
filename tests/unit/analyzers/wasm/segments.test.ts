import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWasm } from "../../../../analyzers/wasm/index.js";
import { parseSegments } from "../../../../analyzers/wasm/segments.js";
import { wasmReader } from "../../../fixtures/wasm-reader.js";
import { wasmModule, wasmSection, wasmString } from "../../../fixtures/wasm-fixtures.js";

void test("reads passive and explicit-memory data segments", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(5, [1, 0, 1]),
    wasmSection(11, [2, 1, ...wasmString("passive"), 2, 0, 0x41, 0, 0x0b,
      ...wasmString("a".repeat(40))]))))!;
  assert.deepEqual(result.issues, []);
  assert.equal(result.data[0]?.memory, null);
  assert.equal(result.data[0]?.mode, "passive");
  assert.equal(result.data[1]?.preview.length, 32);
  assert.equal(result.data[1]?.size, 40);
  assert.equal(result.data[1]?.memory, 0);
  assert.equal(result.data[1]?.mode, "active");
});

void test("handles all element segment modes and expression encodings", async () => {
  const emptyOffset = [0x41, 0, 0x0b];
  const result = (await parseWasm(wasmModule(wasmSection(4, [1, 0x70, 0, 0]),
    wasmSection(9, [8, 0, ...emptyOffset, 0, 1, 0, 0, 2, 0, ...emptyOffset, 0, 0,
      3, 0, 0, 4, ...emptyOffset, 1, 0xd0, 0x70, 0x0b,
      5, 0x70, 0, 6, 0, ...emptyOffset, 0x70, 0, 7, 0x70, 0]))))!;
  assert.deepEqual(result.issues, []);
  assert.equal(result.elements.length, 8);
  assert.deepEqual(result.elements.map(row => row.mode),
    ["active", "passive", "active", "declarative", "active", "passive", "active", "declarative"]);
  assert.ok(Array.isArray(result.elements[4]?.entries[0]));
  assert.deepEqual(result.elements.map(row => row.type), new Array<string>(8).fill("funcref"));
});

void test("keeps implicit memory-zero segments separate from explicit nonzero indices", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(5, [2, 0, 1, 0, 1]),
    wasmSection(11, [2, 0, 0x41, 0, 0x0b, ...wasmString("implicit"),
      2, 1, 0x41, 0, 0x0b, ...wasmString("explicit")]))))!;
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.data.map(row => row.memory), [0, 1]);
  assert.deepEqual(result.data.map(row => row.mode), ["active", "active"]);
});

void test("flags bytes after the expression inside a body, even with matching section length", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(1, [1, 0x60, 0, 0]),
    wasmSection(3, [1, 0]), wasmSection(10, [1, 3, 0, 0x0b, 1]))))!;
  assert.equal(result.code.length, 1);
  assert.match(result.issues.join(" "), /Function body.*trailing byte/);
});

void test("rejects declared data lengths before consuming their partial payload", async () => {
  const result = (await parseWasm(wasmModule()))!;
  const reader = wasmReader([1, 1, 40, ...new Array<number>(39).fill(0)]);
  await assert.rejects(parseSegments(11, reader, result), /Truncated/);
  assert.equal(reader.offset, 3);
  assert.deepEqual(result.data, []);
});

void test("reports invalid segment flags and element kinds", async () => {
  assert.match((await parseWasm(wasmModule(wasmSection(9, [1, 8]))))!.issues.join(" "), /element segment flags/);
  assert.match((await parseWasm(wasmModule(wasmSection(9, [1, 1, 1, 0]))))!.issues.join(" "), /element kind/);
  assert.match((await parseWasm(wasmModule(wasmSection(11, [1, 3]))))!.issues.join(" "), /data segment flags/);
  assert.match((await parseWasm(wasmModule(wasmSection(11, [1, 1, 10, 1]))))!.issues.join(" "), /Truncated/);
});

void test("retains instructions before unknown opcodes and continues with the next function", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(1, [1, 0x60, 0, 0]),
    wasmSection(3, [3, 0, 0, 0]),
    wasmSection(10, [3, 4, 0, 1, 0xff, 0x0b, 3, 1, 2, 0x7f, 3, 0, 0x0b, 1]))))!;
  assert.equal(result.code.length, 3);
  assert.equal(result.code[0]?.instructions[0]?.mnemonic, "nop");
  assert.equal(result.code[1]?.locals[0]?.count, 2);
  assert.equal(result.code[2]?.instructions[0]?.mnemonic, "end");
  assert.match(result.issues.join(" "), /Unsupported opcode/);
  assert.match(result.issues.join(" "), /Truncated/);
  assert.match(result.issues.join(" "), /trailing byte/);
});
