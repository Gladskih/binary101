import assert from "node:assert/strict";
import test from "node:test";
import { nativeAotFunctionMapStatistics } from "../../../../renderers/native-aot/function-map-statistics.js";
import { createFunctionMapModels } from "../../../helpers/native-aot-function-map-models.js";
import { createNativeAotRuntimeTailMapFixture } from "../../../helpers/native-aot-runtime-tail-fixture.js";
import { parseNativeAotFunctionMaps } from "../../../../analyzers/native-aot/function-maps.js";

void test("type statistics distinguish dictionaries, finalizers, sealed methods and resolution failures", async () => {
  const fixture = createNativeAotRuntimeTailMapFixture();
  const data = await parseNativeAotFunctionMaps(fixture.image, fixture.sections, { majorVersion: 16, minorVersion: 0 });
  const map = data!.maps[0]!;
  assert.equal(map.type, 301);
  map.entries.push({ ...map.entries[0]! });
  map.entries.push({ typeIndex: 2, metadataHandle: 12, runtimeType: null });

  const statistics = nativeAotFunctionMapStatistics(map);

  assert.deepEqual(statistics.map(statistic => statistic.value),
    [3, 2, 1, 1, 1, 1, 1, 1, 5, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(statistics.map(statistic => statistic.label), ["Map records", "Distinct code entry points",
    "Decoded runtime types", "Virtual method slots", "Dictionary/data slots", "Empty virtual slots",
    "Finalizable types", "Distinct finalizer methods", "Interface dispatch records", "Static interface dispatch records",
    "Special interface resolutions", "Referenced sealed slots", "Distinct sealed methods", "Instantiating-thunk references",
    "Decoded GC layouts", "Object reference regions", "Arrays containing only references", "Arrays with mixed value layouts",
    "Metadata-only types with reference fields"]);
  assert.ok(statistics.every(statistic => statistic.description.length > 20));
});

void test("unavailable tails and absent types produce honest zero counts", () => {
  const statistics = nativeAotFunctionMapStatistics({ type: 301, warnings: [], entries: [
    { typeIndex: 0, metadataHandle: 10, runtimeType: { rva: 0x180, flags: 0, baseSize: 24,
      numVtableSlots: 0, numInterfaces: 0, hashCode: 0, slots: [] } },
    { typeIndex: 1, metadataHandle: 11, runtimeType: null }
  ] });

  assert.deepEqual(statistics.map(statistic => statistic.value),
    [2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
});

void test("interop and generic summaries count named roles rather than exposing numeric pointer fields", () => {
  const data = createFunctionMapModels();

  assert.deepEqual(data.maps.map(map => nativeAotFunctionMapStatistics(map).map(statistic => statistic.value)), [
    [1, 1], [1, 2, 1, 1, 1, 1, 0], [1, 2, 1, 0, 1], [1, 2, 1, 1, 1], [1, 1, 0, 0, 0], [1, 1, 0]
  ]);
  assert.ok(data.maps.flatMap(nativeAotFunctionMapStatistics).every(statistic =>
    statistic.label.length > 0 && statistic.description.length > 20));
});

void test("missing generic layouts and nullable routine targets are excluded from distinct counts", () => {
  const data = createFunctionMapModels();
  const struct = data.maps[1]!;
  const template = data.maps[4]!;
  assert.equal(struct.type, 316);
  assert.equal(template.type, 322);
  delete struct.entries[0]!.nativeSize;
  template.entries[0]!.genericArgumentIndices = [1];
  delete template.entries[0]!.layout;

  assert.equal(nativeAotFunctionMapStatistics(struct)[2]?.value, 0);
  assert.deepEqual(nativeAotFunctionMapStatistics(template).map(statistic => statistic.value), [1, 1, 0, 0, 0]);
});

void test("nonempty cleanup, closed delegates, instantiations and thunk roles remain visible", async () => {
  const data = createFunctionMapModels();
  const struct = data.maps[1]!;
  const delegate = data.maps[2]!;
  const exact = data.maps[5]!;
  assert.equal(struct.type, 316);
  assert.equal(delegate.type, 317);
  assert.equal(exact.type, 336);
  struct.entries[0]!.cleanupRva = 0x40;
  delegate.entries[0]!.closedRva = 0x40;
  exact.entries[0]!.genericArgumentIndices = [1];

  assert.deepEqual(nativeAotFunctionMapStatistics(struct).map(statistic => statistic.value), [1, 2, 1, 1, 1, 1, 1]);
  assert.deepEqual(nativeAotFunctionMapStatistics(delegate).map(statistic => statistic.value), [1, 2, 1, 1, 1]);
  assert.deepEqual(nativeAotFunctionMapStatistics(exact).map(statistic => statistic.value), [1, 1, 1]);
  const fixture = createNativeAotRuntimeTailMapFixture();
  const parsed = await parseNativeAotFunctionMaps(fixture.image, fixture.sections,
    { majorVersion: 16, minorVersion: 0 });
  const map = parsed!.maps[0]!;
  assert.equal(map.type, 301);
  map.entries[0]!.runtimeType!.tail!.sealedSlots[0]!.requiresInstantiatingThunk = true;
  assert.equal(nativeAotFunctionMapStatistics(map).find(item => item.label === "Instantiating-thunk references")?.value, 1);
});
