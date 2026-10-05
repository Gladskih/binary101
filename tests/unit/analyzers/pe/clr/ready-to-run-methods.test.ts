import assert from "node:assert/strict";
import { test } from "node:test";
import { parseReadyToRunMethods } from "../../../../../analyzers/pe/clr/ready-to-run-methods.js";
import { NativeFormatReader } from "../../../../../analyzers/native-aot/native-format-reader.js";

void test("decodes sparse method RIDs and runtime-function indices", () => {
  const issues = new Set<string>();

  const methods = parseReadyToRunMethods(Uint8Array.of(16, 1, 8, 12), issues);

  assert.deepEqual(methods, [{ methodRid: 2, runtimeFunctionIndex: 3, fixupOffset: null }]);
  assert.equal(issues.size, 0);
});

void test("decodes inline fixups and backward shared fixup references", () => {
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 18, 4), new Set()),
    [{ methodRid: 1, runtimeFunctionIndex: 2, fixupOffset: 4 }]);
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 22, 2), new Set()),
    [{ methodRid: 1, runtimeFunctionIndex: 2, fixupOffset: 3 }]);
});

void test("checks the exclusive end of the fixup range and accepts its zero boundary", () => {
  const issues = new Set<string>();

  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 18), issues), []);
  assert.match([...issues].join(), /fixup offset is outside/);
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 22, 8), new Set()),
    [{ methodRid: 1, runtimeFunctionIndex: 2, fixupOffset: 0 }]);
});

void test("reports invalid method fixups without discarding other data", () => {
  const issues = new Set<string>();

  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 22, 100), issues), []);
  assert.match([...issues].join(" "), /fixup offset/);
});

void test("decodes aliased payloads once while preserving each method RID", context => {
  const reads = context.mock.method(NativeFormatReader.prototype, "unsigned");
  const issues = new Set<string>();
  // Two NativeArray blocks point to the same leaf for local index zero.
  const methods = parseReadyToRunMethods(Uint8Array.of(136, 2, 2, 0, 12), issues);

  assert.deepEqual(methods, [
    { methodRid: 1, runtimeFunctionIndex: 3, fixupOffset: null },
    { methodRid: 17, runtimeFunctionIndex: 3, fixupOffset: null }
  ]);
  assert.equal(reads.mock.calls.filter(call => call.arguments[0] === 4).length, 1);
  assert.equal(issues.size, 0);
});

void test("caches aliased malformed payloads and reports a single failure", context => {
  const reads = context.mock.method(NativeFormatReader.prototype, "unsigned");
  const issues = new Set<string>();

  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(136, 2, 2, 0, 0x1f), issues), []);
  assert.equal(reads.mock.calls.filter(call => call.arguments[0] === 4).length, 1);
  assert.equal(issues.size, 1);
});
