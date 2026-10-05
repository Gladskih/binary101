import assert from "node:assert/strict";
import test from "node:test";
import { parseReadyToRunInstanceMethods } from "../../../../../analyzers/pe/clr/ready-to-run-instance-methods.js";
import { createNativeHashtableFixture } from "../../../../helpers/native-hashtable-fixture.js";
import { NativeFormatReader } from "../../../../../analyzers/native-aot/native-format-reader.js";
import { ReadyToRunSignatureCursor } from "../../../../../analyzers/pe/clr/ready-to-run-signature-cursor.js";

void test("decodes a generic instance signature followed by its runtime-function index", () => {
  // A generic method with two arguments; NativeFormat unsigned 12 encodes entry 6,
  // whose low fixup bit is zero and runtime-function index is 3.
  const bytes = createNativeHashtableFixture([Uint8Array.of(4, 1, 2, 8, 14, 12)]);
  const issues = new Set<string>();

  assert.deepEqual(parseReadyToRunInstanceMethods(bytes, issues), [
    { signatureOffset: 9, runtimeFunctionIndex: 3, fixupOffset: null }
  ]);
  assert.equal(issues.size, 0);
});

void test("keeps other instances when one signature or entrypoint is malformed", () => {
  const bytes = createNativeHashtableFixture([
    Uint8Array.of(0x40, 0x40), Uint8Array.of(0, 1, 4), Uint8Array.of(0, 1)
  ]);
  const issues = new Set<string>();

  const methods = parseReadyToRunInstanceMethods(bytes, issues);

  assert.equal(methods.length, 1);
  assert.equal(methods[0]!.runtimeFunctionIndex, 1);
  assert.match([...issues].join(" "), /Unsupported R2R type/);
  assert.match([...issues].join(" "), /outside|bounds|truncated/);
});

void test("reads inline and backward-reference fixups after instance signatures", () => {
  const bytes = createNativeHashtableFixture([Uint8Array.of(0, 1, 18, 42), Uint8Array.of(0, 1, 22, 2)]);
  const issues = new Set<string>();

  const methods = parseReadyToRunInstanceMethods(bytes, issues);

  assert.deepEqual(methods.map(method => [method.runtimeFunctionIndex, method.fixupOffset]),
    [[2, 18], [2, 21]]);
  assert.equal(issues.size, 0);
});

void test("reports corrupt hashtable headers without throwing", () => {
  const issues = new Set<string>();

  assert.deepEqual(parseReadyToRunInstanceMethods(Uint8Array.of(3), issues), []);
  assert.match([...issues].join(" "), /InstanceMethodEntryPoints.*header/);
});

void test("decodes aliased instance tuples and their failures only once", context => {
  const bytes = createNativeHashtableFixture([Uint8Array.of(0, 1, 4), Uint8Array.of(0, 1, 4)]);
  new DataView(bytes.buffer).setInt32(11, 5, true);
  const reader = context.mock.method(NativeFormatReader.prototype, "unsigned");
  const issues = new Set<string>();

  assert.equal(parseReadyToRunInstanceMethods(bytes, issues).length, 1);
  assert.equal(reader.mock.calls.filter(call => call.arguments[0] === 17).length, 1);
});

void test("caches failed aliased instance tuples", context => {
  const bytes = createNativeHashtableFixture([Uint8Array.of(0x40, 0x40), Uint8Array.of(0x40, 0x40)]);
  new DataView(bytes.buffer).setInt32(11, 5, true);
  const issues = new Set<string>();
  const bytesRead = context.mock.method(ReadyToRunSignatureCursor.prototype, "byte");

  assert.deepEqual(parseReadyToRunInstanceMethods(bytes, issues), []);
  assert.equal(issues.size, 1);
  assert.equal(bytesRead.mock.callCount(), 1);
});

void test("normalizes non-Error instance and table decoding failures into warnings", context => {
  const bytes = createNativeHashtableFixture([Uint8Array.of(0, 1, 4)]);
  const entryIssues = new Set<string>();
  const tableIssues = new Set<string>();
  const unsigned = NativeFormatReader.prototype.unsigned;
  context.mock.method(NativeFormatReader.prototype, "unsigned", function(
    this: NativeFormatReader, offset: number
  ) {
    if (offset < 9) return unsigned.call(this, offset); // Hashtable references precede the payload.
    throw "unexpected failure";
  });

  assert.deepEqual(parseReadyToRunInstanceMethods(bytes, entryIssues), []);
  assert.deepEqual([...entryIssues], ["InstanceMethodEntryPoints: instance decoding failed"]);
  context.mock.method(NativeFormatReader.prototype, "uint8", () => { throw null; });
  assert.deepEqual(parseReadyToRunInstanceMethods(bytes, tableIssues), []);
  assert.deepEqual([...tableIssues], ["InstanceMethodEntryPoints: instance table decoding failed"]);
});
