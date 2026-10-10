import assert from "node:assert/strict";
import { test } from "node:test";
import { parseReadyToRunMethods } from "../../../../../analyzers/pe/clr/ready-to-run-methods.js";
import { NativeFormatReader } from "../../../../../analyzers/native-aot/native-format-reader.js";

void test("decodes sparse method RIDs and runtime-function indices", () => {
  const issues = new Set<string>();

  // Array header 16 declares two entries. The tree maps local index 1 to entry byte 12,
  // whose NativeFormat value 6 is runtime-function index 3 with no fixup.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/NativeArray.cs
  const methods = parseReadyToRunMethods(Uint8Array.of(16, 1, 8, 12), issues);

  assert.deepEqual(methods, [{ methodRid: 2, runtimeFunctionIndex: 3, fixupOffset: null }]);
  assert.equal(issues.size, 0);
});

void test("decodes inline fixups and backward shared fixup references", () => {
  // Header 8, one-byte block index 1, leaf 0 select entry offset 3 (RID 1).
  // Entry value 9 encodes index 2 plus inline fixup; value 11 plus distance 1 shares offset 3.
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 18, 4), new Set()),
    [{ methodRid: 1, runtimeFunctionIndex: 2, fixupOffset: 4 }]);
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 22, 2), new Set()),
    [{ methodRid: 1, runtimeFunctionIndex: 2, fixupOffset: 3 }]);
});

void test("checks the exclusive end of the fixup range and accepts its zero boundary", () => {
  const issues = new Set<string>();

  // Inline-fixup entry at the section end points one byte beyond the available bytes.
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 18), issues), []);
  assert.match([...issues].join(), /fixup offset is outside/);
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 22, 8), new Set()),
    [{ methodRid: 1, runtimeFunctionIndex: 2, fixupOffset: 0 }]);
});

void test("reports invalid method fixups without discarding other data", () => {
  const issues = new Set<string>();

  // Shared-fixup entry's distance 50 from encoded value 100 points before the section.
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(8, 1, 0, 22, 100), issues), []);
  assert.match([...issues].join(" "), /fixup offset/);
});

void test("decodes aliased payloads once while preserving each method RID", context => {
  const reads = context.mock.method(NativeFormatReader.prototype, "unsigned");
  const issues = new Set<string>();
  // Header 136 declares 17 entries; both one-byte block indexes point to node offset 3,
  // whose leaf points to the shared entry at offset 4.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/NativeArray.cs
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

  // Same aliased two-block tree, with an invalid NativeFormat lead byte at shared offset 4.
  assert.deepEqual(parseReadyToRunMethods(Uint8Array.of(136, 2, 2, 0, 0x1f), issues), []);
  assert.equal(reads.mock.calls.filter(call => call.arguments[0] === 4).length, 1);
  assert.equal(issues.size, 1);
});
