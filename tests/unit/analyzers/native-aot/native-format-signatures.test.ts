import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../../../analyzers/native-aot/native-format-store.js";
import { NativeFormatSignatures } from "../../../../analyzers/native-aot/native-format-signatures.js";
import { createNativeFormatSignatureFixture, createNativeFormatSharedSignatureFixture } from
  "../../../helpers/native-format-signature-fixture.js";

void test("decodes method signatures, varargs, arrays, pointers and generic variables", () => {
  const fixture = createNativeFormatSignatureFixture();
  const warnings = new Set<string>();
  const signatures = new NativeFormatSignatures(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));

  assert.deepEqual(signatures.method(fixture.handle("method", 0x2b)), {
    callingConvention: 0x20, genericParameterCount: 1, returnType: "Demo.Item",
    parameters: ["Demo.Item[]", "!0&"], varArgParameters: ["Demo.Item<!0, !!1>"]
  });
  assert.equal(signatures.type(fixture.handle("multi-array", 0x01)),
    "Demo.Item[rank=2; sizes=3; lowerBounds=-1]");
  assert.equal(signatures.type(fixture.handle("modified", 0x2d)),
    "Demo.Item* modopt(Demo.Item)");
  assert.equal(signatures.type(fixture.handle("specification", 0x3e)),
    "fnptr[0x20; arity=1] Demo.Item(Demo.Item[], !0&, ..., Demo.Item<!0, !!1>)");
  assert.equal(signatures.method({ type: 0x2b, offset: 0 }), undefined);
  assert.equal(warnings.size, 0);
});

void test("contains cyclic signatures and reports the cycle without recursion", () => {
  const fixture = createNativeFormatSignatureFixture();
  const offset = fixture.handle("pointer", 0x32).offset;
  new DataView(fixture.bytes.buffer).setUint32(offset + 1, offset * 128 + 0x32, true);
  const warnings = new Set<string>();
  const signatures = new NativeFormatSignatures(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));

  assert.match(signatures.type({ type: 0x32, offset }), /invalid type/);
  assert.match([...warnings].join(" "), /cycle/);
  assert.equal(warnings.size, 1);
});

void test("caches decoded signatures and rejects non-type handles", () => {
  const fixture = createNativeFormatSignatureFixture();
  const warnings = new Set<string>();
  const signatures = new NativeFormatSignatures(new NativeFormatStore(
    new NativeFormatReader(fixture.bytes), warnings));
  const handle = fixture.handle("method", 0x2b);

  assert.equal(signatures.method(handle), signatures.method(handle));
  assert.match(signatures.type(fixture.handle("type", 0x23)), /invalid type/);
  assert.match([...warnings].join(" "), /Unexpected type-signature/);
});

void test("reuses shared signature nodes without treating a diamond as a cycle", context => {
  const fixture = createNativeFormatSharedSignatureFixture();
  const warnings = new Set<string>();
  const store = new NativeFormatStore(new NativeFormatReader(fixture.bytes), warnings);
  const reads = context.mock.method(store, "record");
  const signatures = new NativeFormatSignatures(store);

  assert.equal(signatures.type(fixture.handle("instantiation", 0x3c)),
    "Demo.Item<Demo.Item, Demo.Item*>");
  assert.equal(warnings.size, 0);
  assert.equal(reads.mock.callCount(), 4);
});
