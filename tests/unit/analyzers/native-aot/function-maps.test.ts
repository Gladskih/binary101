import assert from "node:assert/strict";
import test from "node:test";
import { parseNativeAotFunctionMaps } from "../../../../analyzers/native-aot/function-maps.js";
import { createNativeAotFunctionMapFixture, createNativeAotTemplateFixture } from
  "../../../helpers/native-aot-function-map-fixture.js";

for (const type of [310, 316, 317, 321, 322, 336]) {
  void test(`function map ${type} forwards malformed entry warnings`, async () => {
    const fixture = createNativeAotFunctionMapFixture(type, [new Uint8Array()]);

    const parsed = await parseNativeAotFunctionMaps(fixture.image, fixture.sections);

    assert.equal(parsed?.maps[0]?.entries.length, 0);
    assert.match(parsed!.maps[0]!.warnings.join(" "), /out of bounds/);
  });
}

void test("NativeAOT function maps decode struct, delegate and exact method records", async () => {
  const struct = createNativeAotFunctionMapFixture(316, [Uint8Array.of(0, 10, 64, 2, 2, 2, 2, 65, 8)]);
  const delegate = createNativeAotFunctionMapFixture(317, [Uint8Array.of(0, 2, 2, 2)]);
  const exact = createNativeAotFunctionMapFixture(336, [Uint8Array.of(0, 20, 4, 0, 2, 2)]);
  exact.sections.push({ ...exact.sections[1]!, type: 331 });

  assert.equal((await parseNativeAotFunctionMaps(struct.image, struct.sections))?.maps[0]?.entries.length, 1);
  assert.equal((await parseNativeAotFunctionMaps(delegate.image, delegate.sections))?.maps[0]?.entries.length, 1);
  assert.equal((await parseNativeAotFunctionMaps(exact.image, exact.sections))?.maps[0]?.entries.length, 1);
});

void test("exact methods use NativeReferences rather than CommonFixups", async () => {
  const fixture = createNativeAotTemplateFixture();
  const exact = createNativeAotFunctionMapFixture(336, [Uint8Array.of(0, 20, 0, 0)]);
  exact.bytes.set(fixture.bytes.subarray(0x220, 0x228), 0x220);
  exact.sections.push({ type: 331, rva: 0x220, size: 8 });

  const map = (await parseNativeAotFunctionMaps(exact.image, exact.sections))?.maps[0];

  assert.equal(map?.type, 336);
  assert.ok(map?.type === 336);
  assert.equal(map.entries[0]?.entrypointRva, exact.codeRvas[1]);
});

void test("NativeAOT template maps use their own native reference table", async () => {
  const fixture = createNativeAotTemplateFixture();

  const maps = await parseNativeAotFunctionMaps(fixture.image, fixture.sections);

  assert.equal(maps?.maps[0]?.type, 322);
  assert.deepEqual(maps?.warnings, []);
  assert.deepEqual(maps?.maps[0]?.warnings, []);
});

void test("function maps distinguish missing and ambiguous layouts and map sections", async () => {
  const missing = createNativeAotFunctionMapFixture(322, [Uint8Array.of(0, 0)]);
  const duplicate = createNativeAotTemplateFixture();
  duplicate.sections.push({ ...duplicate.sections[0]! });
  const ambiguous = createNativeAotTemplateFixture();
  ambiguous.sections.push({ ...ambiguous.sections[2]! });

  assert.match((await parseNativeAotFunctionMaps(missing.image, missing.sections))!.warnings.join(" "), /layout|Layout/);
  assert.match((await parseNativeAotFunctionMaps(duplicate.image, duplicate.sections))!.maps[0]!.warnings[0]!,
    /ambiguous/);
  assert.match((await parseNativeAotFunctionMaps(ambiguous.image, ambiguous.sections))!.warnings[0]!, /ambiguous/);
  assert.equal(await parseNativeAotFunctionMaps(missing.image, []), undefined);
});

void test("cctor maps preserve invalid data references with visible warnings", async () => {
  const fixture = createNativeAotFunctionMapFixture(310, [Uint8Array.of(0, 4)]);

  const maps = await parseNativeAotFunctionMaps(fixture.image, fixture.sections);

  assert.equal(maps?.maps[0]?.entries.length, 1);
  assert.match(maps!.warnings.join(" "), /data index/);
});

void test("type templates decode their layouts and native statics function fields", async () => {
  const fixture = createNativeAotFunctionMapFixture(321, [Uint8Array.of(0, 0)]);
  fixture.bytes.set([156, 2, 0], 0x340);
  fixture.sections.push({ type: 330, rva: 0x340, size: 3 }, { ...fixture.sections[1]!, type: 333 });

  const parsed = await parseNativeAotFunctionMaps(fixture.image, fixture.sections);

  assert.deepEqual(parsed?.maps[0]?.entries[0], { typeIndex: 0, layoutOffset: 0,
    layout: { classConstructorRva: fixture.codeRvas[1], dictionaryMethods: [] } });
  assert.deepEqual(parsed?.warnings, []);
});

void test("type template owner indices are validated without reading the referenced type", async () => {
  const fixture = createNativeAotFunctionMapFixture(321, [Uint8Array.of(4, 0)]);
  fixture.bytes[0x340] = 0;
  fixture.sections.push({ type: 330, rva: 0x340, size: 1 });

  const parsed = await parseNativeAotFunctionMaps(fixture.image, fixture.sections);

  assert.equal(parsed?.maps[0]?.entries.length, 1);
  assert.deepEqual(parsed?.warnings, ["Common fixups data index is outside the table."]);
});

void test("marshalling maps never request unused NativeLayout or NativeReferences sections", async () => {
  const fixture = createNativeAotFunctionMapFixture(317, [Uint8Array.of(0, 2, 2, 2)]);

  assert.deepEqual((await parseNativeAotFunctionMaps(fixture.image, fixture.sections))?.warnings, []);
});
