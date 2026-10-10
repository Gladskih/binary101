import assert from "node:assert/strict";
import test from "node:test";
import { readDictionaryMethods } from "../../../../analyzers/native-aot/dictionary-methods.js";
import { NativeLayoutTypeReader } from "../../../../analyzers/native-aot/layout-type.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";
import { createLegacyDictionaryFixture, createLegacyLayoutCursor } from "../../../helpers/native-layout-legacy-fixture.js";

// Cell kinds and inline method fields follow the runtime's dictionary and NativeLayout writers.
// https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/GenericDictionaryCell.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/NativeLayoutVertexNode.cs

void test(".NET 9 dictionary ldtoken and constrained signatures follow relative targets", () => {
  const fixture = createLegacyDictionaryFixture();

  const methods = readDictionaryMethods(fixture.cursor, new NativeLayoutTypeReader(), fixture.issues);

  assert.deepEqual(methods, [
    { signatureOffset: 37, flags: 12, methodName: "M", methodSignatureOffset: 47, entrypointIndex: 1 },
    { signatureOffset: 37, flags: 12, methodName: "M", methodSignatureOffset: 47, entrypointIndex: 1 },
    { signatureOffset: 21, flags: 13, methodName: "M", methodSignatureOffset: 47, entrypointIndex: 0 }
  ]);
  assert.equal(fixture.cursor.offset, 33);
  assert.equal(fixture.issues.size, 0);
});

void test("legacy dictionaries reject modern-only cells and malformed relative signatures", () => {
  const issues = new Set<string>();

  // Count 1, then legacy cell kind 32 (0x40/2), which .NET 9 explicitly rejects.
  assert.deepEqual(readDictionaryMethods(createLegacyLayoutCursor(Uint8Array.of(2, 64)),
    new NativeLayoutTypeReader(), issues), []);
  // Count 1, MethodLdToken kind 8, then a signed relative signature target beyond the payload.
  assert.deepEqual(readDictionaryMethods(createLegacyLayoutCursor(Uint8Array.of(2, 16, 126)),
    new NativeLayoutTypeReader(), issues), []);
  assert.match([...issues].join(" "), /\.NET 9.*unknown/);
  assert.match([...issues].join(" "), /outside/);
});

void test("dictionary cells yield only explicit method function indices", () => {
  // Three inline cells: kind 1 type reference; kind 13 method with flags 4 and entrypoint index 1;
  // kind 5 static data ends with explicit index 0. NativeFormat values use the one-byte doubled form.
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(6, 2, 12, 26, 8, 2, 12, 20, 10, 12, 0));

  assert.deepEqual(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues),
    [{ signatureOffset: 4, flags: 4, methodToken: 10, entrypointIndex: 1 }]);
  assert.equal(issues.size, 0);
});

void test("unknown dictionary cells preserve the preceding method", () => {
  // Count 2; a kind-13 method record precedes unsupported kind 0.
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(4, 26, 8, 0, 12, 20, 0));

  assert.equal(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues).length, 1);
  assert.match([...issues][0]!, /unknown/);
});

void test("constrained method cells decode both type and method payloads", () => {
  // Count 3 includes GenericStaticConstrainedMethod kind 32; its type constraint precedes
  // a method signature with entrypoint flag 4 and method token 10.
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(
    6, 64, 12, 8, 2, 66, 12, 8, 2, 68, 8, 8, 0, 12, 20));

  assert.deepEqual(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues),
    [{ signatureOffset: 11, flags: 4, methodToken: 10, entrypointIndex: 0 }]);
  assert.equal(issues.size, 0);
});

void test("NotYetSupported marker cells warn and do not hide following method cells", () => {
  // Bytes 185,3 encode cell kind 238 in the two-byte NativeFormat form; the next cell is a method.
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(4, 185, 3, 0, 26, 0, 12, 20));

  assert.equal(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues).length, 1);
  assert.match([...issues][0]!, /NotYetSupported/);
});

void test("dictionary decoding exposes untyped reader failures", context => {
  const { cursor, issues } = createFunctionEntryFixture(Uint8Array.of(2));
  context.mock.method(cursor, "count", () => { throw "untyped failure"; });

  assert.deepEqual(readDictionaryMethods(cursor, new NativeLayoutTypeReader(), issues), []);
  assert.deepEqual([...issues], ["NativeLayout dictionary read failed."]);
});
