import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatStore } from "../../../../analyzers/native-aot/native-format-store.js";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";

// Record tags are the generated metadata handle types, mirrored locally for an independent oracle.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
const recordType = {
  arraySignature: 0x01, methodSignature: 0x2b, fieldDefinition: 0x23,
  typeInstantiation: 0x3c, assemblyReference: 0x39
} as const;

void test("reads byte-backed enums using their compressed encoding", () => {
  // SignatureCallingConvention.HasThis=0x20 is a compressed enum value, stored as 0x40.
  // The following compressed integer 4 encodes generic-parameter count 2.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
  const store = new NativeFormatStore(new NativeFormatReader(
    Uint8Array.of(0, 0x40, 4, 0, 0, 0)), new Set());

  assert.equal(store.record({ type: recordType.methodSignature, offset: 1 }).number("callingConvention"), 0x20);
  assert.equal(store.record({ type: recordType.methodSignature, offset: 1 }).number("genericParameterCount"), 2);
});

void test("retains valid fields before a truncated tail and caches record reads", () => {
  const warnings = new Set<string>();
  // 44 compresses field flags 22; the zero is a nil name handle and the signature tail is truncated.
  const store = new NativeFormatStore(new NativeFormatReader(Uint8Array.of(0, 44, 0)), warnings);
  const handle = { type: recordType.fieldDefinition, offset: 1 };

  const field = store.record(handle);

  assert.equal(field.number("flags"), 22);
  assert.equal(field.handle("name").offset, 0);
  assert.equal(store.record(handle), field);
  assert.equal(warnings.size, 1);
  assert.throws(() => field.handle("signature"), /signature/);
});

void test("retains collection prefixes, skips nil handles and rejects unknown record layouts", () => {
  const warnings = new Set<string>();
  // TypeInstantiation at offset 1: nil generic type, count 2, first namespace handle at offset 4,
  // then an incomplete five-byte integer for the second argument.
  const store = new NativeFormatStore(new NativeFormatReader(
    Uint8Array.of(0, 0, 4, 0xbd, 8, 0x0f, 0)), warnings);
  const partial = store.record({ type: recordType.typeInstantiation, offset: 1 });

  assert.deepEqual(partial.handles("arguments"), [{ type: 0x2f, offset: 4 }]);
  // 0x40 lies beyond generated HandleType IDs 1..0x3f, so this record layout is unknown.
  assert.equal(store.record({ type: 0x40, offset: 1 }).failure instanceof Error, true);
  assert.match([...warnings].join(" "), /Unsupported record type/);
  assert.deepEqual(new NativeFormatStore(new NativeFormatReader(Uint8Array.of(0, 0, 2, 0)),
    new Set()).record({ type: recordType.typeInstantiation, offset: 1 }).handles("arguments"), []);
});

void test("keeps byte blobs and unsigned dimensions distinct from signed bounds", () => {
  const warnings = new Set<string>();
  // AssemblyReference: publicKeyOrToken length 2 and bytes aa bb. ArraySignature then has
  // rank 1, one size 127 (encoded 0xfe), and one lower bound -1 (encoded 0xfe).
  const store = new NativeFormatStore(new NativeFormatReader(
    Uint8Array.of(0, 0, 0, 2, 0, 0, 0, 4, 0xaa, 0xbb, 0, 0, 2, 2, 0xfe, 2, 0xfe)), warnings);

  assert.deepEqual(store.record({ type: recordType.assemblyReference, offset: 1 }).values["publicKeyOrToken"],
    Uint8Array.of(0xaa, 0xbb));
  assert.deepEqual(store.record({ type: recordType.arraySignature, offset: 11 }).numbers("sizes"), [127]);
  assert.deepEqual(store.record({ type: recordType.arraySignature, offset: 11 }).numbers("lowerBounds"), [-1]);
  assert.equal(warnings.size, 0);
});
void test("absent fields cannot resolve to inherited JavaScript object properties", () => {
  const store = new NativeFormatStore(new NativeFormatReader(Uint8Array.of(0)), new Set());
  // HandleType 0x14 is the generated empty record.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
  const record = store.record({ type: 0x14, offset: 0 });

  assert.throws(() => record.handle("constructor"), /could not be read/);
  assert.throws(() => record.handle("toString"), /could not be read/);
});
