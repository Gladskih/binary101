import assert from "node:assert/strict";
import test from "node:test";
import { NativeFormatReader } from "../../../../analyzers/native-aot/native-format-reader.js";
import { parseNativeAotInvokeMap } from "../../../../analyzers/native-aot/invoke-map.js";
import { createNativeAotInvokeFixture } from "../../../helpers/native-aot-invoke-fixture.js";
import { createNativeHashtableFixture } from "../../../helpers/native-hashtable-fixture.js";

const replaceMap = (fixture: ReturnType<typeof createNativeAotInvokeFixture>, payloads: Uint8Array[]) => {
  const bytes = createNativeHashtableFixture(payloads);
  fixture.bytes.set(bytes, fixture.mapRva);
  fixture.sections[0]!.size = bytes.length;
};

void test("NativeAOT InvokeMap resolves method bodies and invoke stubs through common fixups", async () => {
  const fixture = createNativeAotInvokeFixture();

  assert.deepEqual(await parseNativeAotInvokeMap(fixture.image, fixture.sections), {
    entries: [{ flags: 34, metadataOffset: 10, declaringTypeIndex: 4,
      entrypointRva: fixture.codeRvas[0], invokeStubRva: fixture.codeRvas[1],
      genericArgumentIndices: [3, 4] }], warnings: []
  });
});

void test("InvokeMap is absent when its section is not present", async () => {
  const fixture = createNativeAotInvokeFixture();

  assert.equal(await parseNativeAotInvokeMap(fixture.image, []), undefined);
});

void test("InvokeMap rejects ambiguous duplicate sections", async () => {
  const fixture = createNativeAotInvokeFixture();

  const map = await parseNativeAotInvokeMap(fixture.image, [...fixture.sections, fixture.sections[0]!]);

  assert.deepEqual(map?.entries, []);
  assert.match(map!.warnings.join(" "), /ambiguous/);
});

void test("InvokeMap supports abstract methods and entries requiring parameter interpretation", async () => {
  const fixture = createNativeAotInvokeFixture();
  // NativeFormat unsigned 0x80 (NeedsParameterInterpretation) uses low-bit continuation tags.
  replaceMap(fixture, [Uint8Array.of(1, 2, 20, 8), Uint8Array.of(0, 20, 8, 2)]);

  const map = await parseNativeAotInvokeMap(fixture.image, fixture.sections);

  assert.deepEqual(map?.entries.map(entry => [entry.entrypointRva, entry.invokeStubRva]),
    [[null, null], [null, fixture.codeRvas[1]]]);
  assert.deepEqual(map?.warnings, []);
});

void test("InvokeMap preserves metadata when an external code reference is invalid", async () => {
  const fixture = createNativeAotInvokeFixture();
  fixture.sections.pop();

  const map = await parseNativeAotInvokeMap(fixture.image, fixture.sections);

  assert.equal(map?.entries.length, 1);
  assert.equal(map!.entries[0]!.entrypointRva, null);
  assert.equal(map!.entries[0]!.invokeStubRva, null);
  assert.match(map!.warnings.join(" "), /Common fixups table/);
});

void test("InvokeMap preserves other entries after a truncated tuple or unknown flags", async () => {
  const fixture = createNativeAotInvokeFixture();
  replaceMap(fixture, [Uint8Array.of(8, 0, 0), Uint8Array.of(0, 20, 8, 0), Uint8Array.of(2)]);

  const map = await parseNativeAotInvokeMap(fixture.image, fixture.sections);

  assert.equal(map?.entries.length, 1);
  assert.equal(map!.entries[0]!.invokeStubRva, fixture.codeRvas[0]);
  assert.match(map!.warnings.join(" "), /unknown flags/);
  assert.match(map!.warnings.join(" "), /outside|truncated/);
});

void test("InvokeMap rejects impossible generic argument counts", async () => {
  const fixture = createNativeAotInvokeFixture();
  replaceMap(fixture, [Uint8Array.of(68, 20, 8, 0, 2, 20)]);

  const map = await parseNativeAotInvokeMap(fixture.image, fixture.sections);

  assert.deepEqual(map?.entries, []);
  assert.match(map!.warnings.join(" "), /count exceeds/);
});

void test("InvokeMap decodes aliased payloads only once", async context => {
  const fixture = createNativeAotInvokeFixture();
  replaceMap(fixture, [Uint8Array.of(0, 20, 8, 0), Uint8Array.of(0, 20, 8, 0)]);
  // Rewrite the second five-byte reference to point at the first tuple.
  fixture.view.setInt32(fixture.mapRva + 11, 15 - 10, true);
  const reads = context.mock.method(fixture.image, "readData");

  const map = await parseNativeAotInvokeMap(fixture.image, fixture.sections);

  assert.equal(map?.entries.length, 1);
  assert.equal(reads.mock.callCount(), 2); // One blob read, one unique common fixup.
});

void test("InvokeMap reports malformed hash tables and unreadable map sections", async () => {
  const fixture = createNativeAotInvokeFixture();
  fixture.sections[0]!.size = 1;
  fixture.bytes[fixture.mapRva] = 3;

  const invalid = await parseNativeAotInvokeMap(fixture.image, fixture.sections);
  fixture.sections[0]!.size = null;
  const unreadable = await parseNativeAotInvokeMap(fixture.image, fixture.sections);

  assert.match(invalid!.warnings.join(" "), /header/);
  assert.match(unreadable!.warnings.join(" "), /unknown or invalid size/);
  assert.deepEqual(invalid?.entries, []);
  assert.deepEqual(unreadable?.entries, []);
});

void test("InvokeMap normalizes non-Error tuple and table failures", async context => {
  const fixture = createNativeAotInvokeFixture();
  const unsigned = NativeFormatReader.prototype.unsigned;
  context.mock.method(NativeFormatReader.prototype, "unsigned", function(
    this: NativeFormatReader, offset: number
  ) {
    if (offset < 9) return unsigned.call(this, offset); // Hashtable references precede the payload.
    throw null;
  });

  const entry = await parseNativeAotInvokeMap(fixture.image, fixture.sections);
  context.mock.method(NativeFormatReader.prototype, "uint8", () => { throw null; });
  const table = await parseNativeAotInvokeMap(fixture.image, fixture.sections);

  assert.deepEqual(entry?.entries, []);
  assert.deepEqual(entry?.warnings, ["Invoke entry decoding failed."]);
  assert.deepEqual(table?.entries, []);
  assert.deepEqual(table?.warnings, ["Invoke table decoding failed."]);
});
