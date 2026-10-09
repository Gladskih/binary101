import assert from "node:assert/strict";
import test from "node:test";
import { collectNativeAotFunctionMapSeeds } from "../../../../analyzers/native-aot/function-map-seeds.js";
import { createFunctionMapModels } from "../../../helpers/native-aot-function-map-models.js";
import { createNativeAotTypeMapFixture } from "../../../helpers/native-aot-runtime-type-fixture.js";
import { parseNativeAotFunctionMaps } from "../../../../analyzers/native-aot/function-maps.js";
import { createNativeAotRuntimeTailMapFixture } from "../../../helpers/native-aot-runtime-tail-fixture.js";

void test("function maps seed only named code fields and deduplicate addresses within each source", () => {
  const groups = collectNativeAotFunctionMapSeeds(createFunctionMapModels());

  assert.deepEqual(groups.map(group => group.rvas), [[0x40], [0x40, 0x300],
    [0x40, 0x300], [0x40, 0x300], [0x40], [0x300]]);
  assert.match(groups[1]!.source, /Struct marshalling/);
});

void test("finalizers and sealed methods seed code; dispatch tables remain data", async () => {
  const fixture = createNativeAotRuntimeTailMapFixture();
  const parsed = await parseNativeAotFunctionMaps(fixture.image, fixture.sections,
    { majorVersion: 16, minorVersion: 0 });
  const map = parsed!.maps[0]!;
  assert.equal(map.type, 301);
  map.entries[0]!.runtimeType!.tail!.sealedSlots.push({ slot: 1, targetRva: null, requiresInstantiatingThunk: false });

  assert.deepEqual(collectNativeAotFunctionMapSeeds(parsed).map(group => group.rvas), [[0x40, 0x300]]);
  assert.deepEqual(parsed?.warnings, []);
});

void test("runtime vtables supply methods while dictionary and null slots never become seeds", async () => {
  const fixture = createNativeAotTypeMapFixture();
  const parsed = await parseNativeAotFunctionMaps(fixture.image, fixture.sections);

  assert.deepEqual(collectNativeAotFunctionMapSeeds(parsed).map(group => group.rvas), [[fixture.codeRvas[0]]]);
  assert.deepEqual(collectNativeAotFunctionMapSeeds({ warnings: [], maps: [
    { type: 301, warnings: [], entries: [{ typeIndex: 0, metadataHandle: 10, runtimeType: null }] }
  ] }), []);
});

void test("absent, empty and non-code maps add no roots", () => {
  assert.deepEqual(collectNativeAotFunctionMapSeeds(undefined), []);
  assert.deepEqual(collectNativeAotFunctionMapSeeds({ warnings: [], maps: [
    { type: 322, warnings: [], entries: [{ signatureOffset: 0, layoutOffset: 0, flags: 0,
      methodToken: 10, declaringTypeIndex: 0, genericArgumentIndices: [], entrypointRva: null }] },
    { type: 310, warnings: [], entries: [] }
  ] }), []);
});
