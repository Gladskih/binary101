import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../../../analyzers/native-aot/native-format-store.js";
import { NativeFormatSignatures } from "../../../../analyzers/native-aot/native-format-signatures.js";
import { createNativeFormatSignatureFixture, createNativeFormatSharedSignatureFixture } from
  "../../../helpers/native-format-signature-fixture.js";

// The signature-kind handle tags mirror NativeFormatReaderCommonGen.cs independently of production.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
const signatureType = {
  array: 0x01, field: 0x23, modified: 0x2d, method: 0x2b, pointer: 0x32,
  methodSpecification: 0x3e, instantiation: 0x3c
} as const;

void test("decodes method signatures, varargs, arrays, pointers and generic variables", () => {
  const fixture = createNativeFormatSignatureFixture();
  const warnings = new Set<string>();
  const signatures = new NativeFormatSignatures(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));

  assert.deepEqual(signatures.method(fixture.handle("method", signatureType.method)), {
    callingConvention: 0x20, genericParameterCount: 1, returnType: "Demo.Item",
    parameters: ["Demo.Item[]", "!0&"], varArgParameters: ["Demo.Item<!0, !!1>"]
  });
  assert.equal(signatures.type(fixture.handle("multi-array", signatureType.array)),
    "Demo.Item[rank=2; sizes=3; lowerBounds=-1]");
  assert.equal(signatures.type(fixture.handle("modified", signatureType.modified)),
    "Demo.Item* modopt(Demo.Item)");
  assert.equal(signatures.type(fixture.handle("specification", signatureType.methodSpecification)),
    "fnptr[0x20; arity=1] Demo.Item(Demo.Item[], !0&, ..., Demo.Item<!0, !!1>)");
  assert.equal(signatures.method({ type: signatureType.method, offset: 0 }), undefined);
  assert.equal(warnings.size, 0);
});

void test("contains cyclic signatures and reports the cycle without recursion", () => {
  const fixture = createNativeFormatSignatureFixture();
  const offset = fixture.handle("pointer", signatureType.pointer).offset;
  // Typed handle payload is (target offset << 7) | tag; 0x32 is the PointerSignature tag.
  new DataView(fixture.bytes.buffer).setUint32(offset + 1, offset * 128 + 0x32, true);
  const warnings = new Set<string>();
  const signatures = new NativeFormatSignatures(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));

  assert.match(signatures.type({ type: signatureType.pointer, offset }), /invalid type/);
  assert.match([...warnings].join(" "), /cycle/);
  assert.equal(warnings.size, 1);
});

void test("caches decoded signatures and rejects non-type handles", () => {
  const fixture = createNativeFormatSignatureFixture();
  const warnings = new Set<string>();
  const signatures = new NativeFormatSignatures(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));
  const handle = fixture.handle("method", signatureType.method);

  assert.equal(signatures.method(handle), signatures.method(handle));
  // A Field handle is a metadata member record, not a NativeFormat type-signature node.
  assert.match(signatures.type(fixture.handle("type", signatureType.field)), /invalid type/);
  assert.match([...warnings].join(" "), /Unexpected type-signature/);
});

void test("reuses shared signature nodes without treating a diamond as a cycle", context => {
  const fixture = createNativeFormatSharedSignatureFixture();
  const warnings = new Set<string>();
  const store = new NativeFormatStore(new NativeFormatReader(fixture.bytes), warnings);
  const reads = context.mock.method(store, "record");
  const signatures = new NativeFormatSignatures(store);

  assert.equal(signatures.type(fixture.handle("instantiation", signatureType.instantiation)),
    "Demo.Item<Demo.Item, Demo.Item*>");
  assert.equal(warnings.size, 0);
  assert.equal(reads.mock.callCount(), 4); // Instantiation, shared type, shared pointer, pointer target.
});
