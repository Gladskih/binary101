import assert from "node:assert/strict";
import test from "node:test";
import { collectNativeAotFunctionMapSeeds } from "../../../../analyzers/native-aot/function-map-seeds.js";
import { createFunctionMapModels } from "../../../helpers/native-aot-function-map-models.js";

void test("function maps seed only named code fields and deduplicate addresses within each source", () => {
  const groups = collectNativeAotFunctionMapSeeds(createFunctionMapModels());

  assert.deepEqual(groups.map(group => group.rvas), [[0x40], [0x40, 0x300],
    [0x40, 0x300], [0x40, 0x300], [0x40], [0x300]]);
  assert.match(groups[1]!.source, /Struct marshalling/);
});

void test("absent, empty and non-code maps add no roots", () => {
  assert.deepEqual(collectNativeAotFunctionMapSeeds(undefined), []);
  assert.deepEqual(collectNativeAotFunctionMapSeeds({ warnings: [], maps: [
    { type: 322, warnings: [], entries: [{ signatureOffset: 0, layoutOffset: 0, flags: 0,
      methodToken: 10, declaringTypeIndex: 0, genericArgumentIndices: [], entrypointRva: null }] },
    { type: 310, warnings: [], entries: [] }
  ] }), []);
});
