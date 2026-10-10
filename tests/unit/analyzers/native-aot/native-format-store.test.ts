import assert from "node:assert/strict";
import { test } from "node:test";
import { NativeFormatStore } from "../../../../analyzers/native-aot/native-format-store.js";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";

void test("reads byte-backed enums using their compressed encoding", () => {
  // MdBinaryReaderGen.Read(SignatureCallingConvention) uses DecodeUnsigned, even
  // though the enum's underlying type is byte. HasThis = 0x20 encodes as 0x40.
  const store = new NativeFormatStore(new NativeFormatReader(
    Uint8Array.of(0, 0x40, 4, 0, 0, 0)), new Set());

  assert.equal(store.record({ type: 0x2b, offset: 1 }).number("callingConvention"), 0x20);
  assert.equal(store.record({ type: 0x2b, offset: 1 }).number("genericParameterCount"), 2);
});

void test("retains valid fields before a truncated tail and caches record reads", () => {
  const warnings = new Set<string>();
  const store = new NativeFormatStore(new NativeFormatReader(Uint8Array.of(0, 44, 0)), warnings);
  const handle = { type: 0x23, offset: 1 };

  const field = store.record(handle);

  assert.equal(field.number("flags"), 22);
  assert.equal(field.handle("name").offset, 0);
  assert.equal(store.record(handle), field);
  assert.equal(warnings.size, 1);
  assert.throws(() => field.handle("signature"), /signature/);
});

void test("retains collection prefixes, skips nil handles and rejects unknown record layouts", () => {
  const warnings = new Set<string>();
  // TypeInstantiation: nil generic type, two polymorphic arguments; second is truncated.
  const store = new NativeFormatStore(new NativeFormatReader(
    Uint8Array.of(0, 0, 4, 0xbd, 8, 0x0f, 0)), warnings);
  const partial = store.record({ type: 0x3c, offset: 1 });

  assert.deepEqual(partial.handles("arguments"), [{ type: 0x2f, offset: 4 }]);
  assert.equal(store.record({ type: 0x40, offset: 1 }).failure instanceof Error, true);
  assert.match([...warnings].join(" "), /Unsupported record type/);
  assert.deepEqual(new NativeFormatStore(new NativeFormatReader(Uint8Array.of(0, 0, 2, 0)),
    new Set()).record({ type: 0x3c, offset: 1 }).handles("arguments"), []);
});

void test("keeps byte blobs and unsigned dimensions distinct from signed bounds", () => {
  const warnings = new Set<string>();
  const store = new NativeFormatStore(new NativeFormatReader(
    Uint8Array.of(0, 0, 0, 2, 0, 0, 0, 4, 0xaa, 0xbb, 0, 0, 2, 2, 0xfe, 2, 0xfe)), warnings);

  assert.deepEqual(store.record({ type: 0x39, offset: 1 }).values["publicKeyOrToken"],
    Uint8Array.of(0xaa, 0xbb));
  assert.deepEqual(store.record({ type: 1, offset: 11 }).numbers("sizes"), [127]);
  assert.deepEqual(store.record({ type: 1, offset: 11 }).numbers("lowerBounds"), [-1]);
  assert.equal(warnings.size, 0);
});
void test("absent fields cannot resolve to inherited JavaScript object properties", () => {
  const store = new NativeFormatStore(new NativeFormatReader(Uint8Array.of(0)), new Set());
  const record = store.record({ type: 0x14, offset: 0 });

  assert.throws(() => record.handle("constructor"), /could not be read/);
  assert.throws(() => record.handle("toString"), /could not be read/);
});
