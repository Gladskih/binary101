import assert from "node:assert/strict";
import test from "node:test";
import { readNativeAotInvokeTuple } from "../../../../analyzers/native-aot/invoke-tuple.js";
import { createLegacyLayoutCursor } from "../../../helpers/native-layout-legacy-fixture.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("modern InvokeMap tuples retain metadata, code indices and generic arguments", () => {
  const { cursor } = createFunctionEntryFixture(Uint8Array.of(68, 20, 8, 0, 2, 4, 6, 8));

  assert.deepEqual(readNativeAotInvokeTuple(cursor), { flags: 34, metadataOffset: 10, declaringTypeIndex: 4,
    entrypointIndex: 0, invokeStubIndex: 1, genericArgumentIndices: [3, 4] });
  assert.equal(cursor.offset, cursor.reader.size);
});

void test("legacy tuples distinguish metadata handles from NativeLayout name/signature offsets", () => {
  const metadata = createLegacyLayoutCursor(Uint8Array.of(72, 20, 8, 0, 2));
  const named = createLegacyLayoutCursor(Uint8Array.of(100, 14, 8, 0, 2, 28, 4, 6, 8));

  assert.deepEqual(readNativeAotInvokeTuple(metadata), { flags: 36, metadataOffset: 10, declaringTypeIndex: 4,
    entrypointIndex: 0, invokeStubIndex: 1, genericArgumentIndices: [] });
  assert.deepEqual(readNativeAotInvokeTuple(named), { flags: 50, nameAndSignatureOffset: 7, declaringTypeIndex: 4,
    entrypointIndex: 0, invokeStubIndex: 1, genericMethodSignatureOffset: 14, genericArgumentIndices: [3, 4] });
  assert.equal(named.offset, named.reader.size);
});

void test("universal canonical legacy methods omit the generic argument sequence", () => {
  // .NET 9 IsUniversalCanonicalEntry=0x40; RequiresInstArg=0x10 adds a signature before the omitted sequence.
  const withContext = createLegacyLayoutCursor(Uint8Array.of(217, 3, 20, 8, 0, 28));
  const noContext = createLegacyLayoutCursor(Uint8Array.of(9, 3, 20, 8));
  const instantiated = createLegacyLayoutCursor(Uint8Array.of(12, 20, 8, 2, 4, 6, 8));

  assert.deepEqual(readNativeAotInvokeTuple(withContext), { flags: 246, metadataOffset: 10, declaringTypeIndex: 4,
    entrypointIndex: 0, invokeStubIndex: null, genericMethodSignatureOffset: 14, genericArgumentIndices: [] });
  assert.deepEqual(readNativeAotInvokeTuple(noContext), { flags: 194, nameAndSignatureOffset: 10, declaringTypeIndex: 4,
    entrypointIndex: null, invokeStubIndex: null, genericArgumentIndices: [] });
  assert.deepEqual(readNativeAotInvokeTuple(instantiated), { flags: 6, metadataOffset: 10, declaringTypeIndex: 4,
    entrypointIndex: null, invokeStubIndex: 1, genericArgumentIndices: [3, 4] });
  assert.equal(withContext.offset, withContext.reader.size);
  assert.equal(noContext.offset, noContext.reader.size);
});

void test("InvokeMap tuples reject unknown flags, missing fields and impossible generic counts", () => {
  assert.throws(() => readNativeAotInvokeTuple(createLegacyLayoutCursor(Uint8Array.of(1, 4))), /flags/);
  assert.throws(() => readNativeAotInvokeTuple(createFunctionEntryFixture(Uint8Array.of(8)).cursor), /flags/);
  assert.throws(() => readNativeAotInvokeTuple(createLegacyLayoutCursor(Uint8Array.of(0))), /outside/);
  assert.throws(() => readNativeAotInvokeTuple(createLegacyLayoutCursor(Uint8Array.of(4, 20, 8, 0, 20))), /count/);
});
