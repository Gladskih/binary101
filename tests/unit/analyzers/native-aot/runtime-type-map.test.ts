import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotRuntimeTypes } from "../../../../analyzers/native-aot/runtime-type-map.js";
import { createNativeAotRuntimeTypeFixture } from "../../../helpers/native-aot-runtime-type-fixture.js";
import { NativeFormatCursor } from "../../../../analyzers/native-aot/native-format-cursor.js";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { createNativeAotObjectGcFixture } from "../../../helpers/native-aot-gc-fixture.js";

void test("runtime types retain GC layouts and preserve other fields when a descriptor is damaged", async () => {
  const fixture = createNativeAotObjectGcFixture();
  fixture.view.setUint32(fixture.type.rva, fixture.type.flags, true);
  fixture.view.setUint32(fixture.type.rva + 4, fixture.type.baseSize, true);

  const type = (await new NativeAotRuntimeTypes(fixture.references).read(fixture.cursor)).runtimeType;

  assert.deepEqual(type?.gcDescriptor, { kind: "object", series: [{ offset: 8, bytes: 8 }, { offset: 24, bytes: 16 }] });
  assert.equal(type?.slots[0]?.kind, "method");
  fixture.word(fixture.type.rva - 8, 0n);
  const damaged = await new NativeAotRuntimeTypes(fixture.references).read(new NativeFormatCursor(
    new NativeFormatReader(Uint8Array.of(0, 20)), 0));
  assert.equal(damaged.runtimeType?.gcDescriptor, undefined);
  assert.deepEqual(damaged.runtimeType?.slots, type?.slots);
  assert.match([...fixture.issues].join(" "), /series count/);
});

for (const width of [4, 8] as const) {
  void test(`decodes ${width}-byte vtables and distinguishes methods, dictionaries and null slots`, async () => {
    const fixture = createNativeAotRuntimeTypeFixture(width);

    const entry = await new NativeAotRuntimeTypes(fixture.references).read(fixture.cursor);

    assert.deepEqual(entry, { typeIndex: 0, metadataHandle: 10, runtimeType: {
      rva: 0x180, flags: 0x04000000, baseSize: 24, numVtableSlots: 3, numInterfaces: 1,
      hashCode: 0x12345678, slots: [{ kind: "method", rva: fixture.codeRvas[0] },
        { kind: "data", rva: 0x220 }, { kind: "null" }]
    } });
    assert.deepEqual([...fixture.issues], []);
  });
}

void test("aliases reuse decoded headers and slot reads", async context => {
  const fixture = createNativeAotRuntimeTypeFixture();
  const reader = new NativeAotRuntimeTypes(fixture.references);
  const reads = context.mock.method(fixture.image, "readData");
  const first = await reader.read(fixture.cursor);
  const count = reads.mock.callCount();

  const second = await reader.read(new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(0, 22)), 0));

  assert.equal(second.runtimeType, first.runtimeType);
  assert.equal(second.metadataHandle, 11);
  assert.equal(reads.mock.callCount(), count);
});

void test("malformed fixed headers, I/O failures and unaligned type references warn", async context => {
  const fixture = createNativeAotRuntimeTypeFixture();
  fixture.view.setInt32(fixture.fixupsRva, 0x181 - fixture.fixupsRva, true);

  assert.equal((await new NativeAotRuntimeTypes(fixture.references).read(fixture.cursor)).runtimeType, null);
  assert.match([...fixture.issues].join(), /alignment/);
  fixture.view.setInt32(fixture.fixupsRva, 0x180 - fixture.fixupsRva, true);
  context.mock.method(fixture.image, "readData", async () => { throw "failure"; });
  const other = createNativeAotRuntimeTypeFixture();
  context.mock.method(other.references.data, "unsigned", async () => { throw "failure"; });
  assert.equal((await new NativeAotRuntimeTypes(other.references).read(other.cursor)).runtimeType, null);
  assert.match([...other.issues].join(), /decoding failed/);
});

void test("unmapped header fields and missing reference indices preserve raw map entries", async context => {
  const fixture = createNativeAotRuntimeTypeFixture();
  context.mock.method(fixture.image, "readData", async (address: number, size: number) =>
    address === fixture.fixupsRva ? new DataView(fixture.bytes.buffer, address, size) : null);

  assert.equal((await new NativeAotRuntimeTypes(fixture.references).read(fixture.cursor)).runtimeType, null);
  assert.match([...fixture.issues].join(), /fixed header/);
  const missing = createNativeAotRuntimeTypeFixture();
  const cursor = new NativeFormatCursor(new NativeFormatReader(Uint8Array.of(4, 20)), 0);
  assert.equal((await new NativeAotRuntimeTypes(missing.references).read(cursor)).runtimeType, null);
  assert.match([...missing.issues].join(), /data index/);
});

void test("retains complete vtable slots before an unmapped tail", async context => {
  const fixture = createNativeAotRuntimeTypeFixture();
  context.mock.method(fixture.image, "isMappedRange", (address: number, size: number) =>
    address >= 0 && address + size <= 0x1a8);

  const type = (await new NativeAotRuntimeTypes(fixture.references).read(fixture.cursor)).runtimeType;

  assert.equal(type?.numVtableSlots, 3);
  assert.deepEqual(type?.slots, [{ kind: "method", rva: fixture.codeRvas[0] }, { kind: "data", rva: 0x220 }]);
  assert.match([...fixture.issues].join(), /vtable is truncated/);
});

void test("visits all slots declared by the ushort count without a parser cap", async context => {
  const fixture = createNativeAotRuntimeTypeFixture();
  // MethodTable._usNumVtableSlots is ushort; this is the format's maximum count.
  fixture.view.setUint16(0x190, 65535, true);
  context.mock.method(fixture.image, "isMappedRange", () => true);
  context.mock.method(fixture.image, "isDataRange", () => true);
  context.mock.method(fixture.image, "readPointerValue", async () => 0n);

  const type = (await new NativeAotRuntimeTypes(fixture.references).read(fixture.cursor)).runtimeType;

  assert.equal(type?.slots.length, 65535);
  assert.deepEqual(type?.slots.at(-1), { kind: "null" });
  assert.deepEqual([...fixture.issues], []);
});

void test("executable or unmapped type headers cannot masquerade as runtime type data", () => {
  const fixture = createNativeAotRuntimeTypeFixture();
  fixture.view.setInt32(fixture.fixupsRva, fixture.codeRvas[0]! - fixture.fixupsRva, true);

  return new NativeAotRuntimeTypes(fixture.references).read(fixture.cursor).then(entry => {
    assert.equal(entry.runtimeType, null);
    assert.match([...fixture.issues].join(), /invalid mapped range/);
  });
});

void test("requires the complete fixed header to be mapped before interpreting its fields", async context => {
  const fixture = createNativeAotRuntimeTypeFixture();
  context.mock.method(fixture.image, "isMappedRange", (address: number, size: number) =>
    address !== 0x180 || size <= 8);

  const entry = await new NativeAotRuntimeTypes(fixture.references).read(fixture.cursor);

  assert.equal(entry.runtimeType, null);
  assert.match([...fixture.issues].join(), /header has an invalid mapped range/);
});
