import assert from "node:assert/strict";
import test from "node:test";
import { nativeAotGcStatistics } from "../../../../renderers/native-aot/gc-statistics.js";
import type { NativeAotRuntimeType } from "../../../../analyzers/native-aot/runtime-type-map.js";

void test("GC summaries explain regions, repeating arrays and types without descriptors", () => {
  const type: NativeAotRuntimeType = { rva: 0, flags: 0, baseSize: 24,
    numVtableSlots: 1, numInterfaces: 0, hashCode: 0, slots: [] };

  const statistics = nativeAotGcStatistics([
    { ...type, gcDescriptor: { kind: "object", series: [{ offset: 8, bytes: 8 }, { offset: 24, bytes: 8 }] } },
    { ...type, gcDescriptor: { kind: "array-all-references", dataOffset: 16 } },
    { ...type, gcDescriptor: { kind: "array-repeating", firstReferenceOffset: 24,
      series: [{ pointerCount: 1, skipBytes: 8 }] } },
    { ...type, flags: 0x01000000, numVtableSlots: 0 }, { ...type, flags: 0x01000000, numVtableSlots: 0 },
    { ...type, flags: 0x01000000 }, { ...type, numVtableSlots: 0 }
  ]);

  assert.deepEqual(statistics.map(item => item.value), [3, 2, 1, 1, 2]);
  assert.deepEqual(statistics.map(item => item.label), ["Decoded GC layouts", "Object reference regions",
    "Arrays containing only references", "Arrays with mixed value layouts", "Metadata-only types with reference fields"]);
  assert.ok(statistics.every(item => item.description.length > 40));
  assert.deepEqual(nativeAotGcStatistics([]).map(item => item.value), [0, 0, 0, 0, 0]);
});
