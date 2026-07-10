"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { analyzePeMsvcRtti } from "../../../../../analyzers/pe/msvc-rtti/index.js";
import type { MsvcRttiAnalysis } from "../../../../../analyzers/pe/msvc-rtti/types.js";
import {
  createSimpleMsvcRttiFixture,
  MsvcRttiPeFixtureBuilder
} from "../../../../fixtures/pe-msvc-rtti-fixture.js";

const analyzeFixture = async (builder: MsvcRttiPeFixtureBuilder): Promise<MsvcRttiAnalysis | null> => {
  const fixture = builder.build();
  return analyzePeMsvcRtti(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core,
    fixture.relocations
  );
};

void test("analyzePeMsvcRtti rejects a random DIR64 target", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const randomDataRva = builder.allocateData(24, 4);
  builder.addDir64Pointer(randomDataRva);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects signature 1 without matching pSelf", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  // rttidata.h places the image-relative pSelf field at COL +20.
  builder.patchUint32(vftable.colRva, 20, vftable.colRva + 4);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects a valid COL self-link with a damaged TypeDescriptor", async () => {
  const { builder, type } = createSimpleMsvcRttiFixture();
  builder.patchByte(type.nameRva, 0x3c);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects a ClassHierarchyDescriptor outside mapped data", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  // rttidata.h places pClassDescriptor at COL +16; SizeOfImage is 0x5000.
  builder.patchUint32(vftable.colRva, 16, 0x5000);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects unknown hierarchy flags", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  // CHD attributes only define bits 0x1, 0x2, and 0x4.
  builder.patchUint32(hierarchy.rva, 4, 0x8);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects excessive BaseClassArray counts", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  // The analyzer's explicit resource limit is 4096 descriptors.
  builder.patchUint32(hierarchy.rva, 8, 4097);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects an overflow-scale BaseClassArray count", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  builder.patchUint32(hierarchy.rva, 8, 0xffff_ffff);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects unknown BaseClassDescriptor attributes", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  // BCD attributes use only the low seven bits in current rttidata.h.
  builder.patchUint32(hierarchy.baseDescriptorRvas[0]!, 20, 0x80);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects the older BCD revision without pClassDescriptor", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  builder.patchUint32(hierarchy.baseDescriptorRvas[0]!, 20, 0);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects a root TypeDescriptor that differs from the COL", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  const otherType = builder.addType(".?AVOther@@");
  builder.patchUint32(hierarchy.baseDescriptorRvas[0]!, 0, otherType.rva);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects structurally incompatible numContainedBases", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const base = builder.addHierarchy(builder.addType(".?AVBase@@"));
  const derived = builder.addHierarchy(builder.addType(".?AVDerived@@"), [{ hierarchy: base }]);
  builder.addVftable(derived, [builder.allocateFunctionTarget()]);
  builder.patchUint32(derived.baseDescriptorRvas[0]!, 4, 0);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects a cycle through additional hierarchy references", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const leaf = builder.addHierarchy(builder.addType(".?AVLeaf@@"));
  const middle = builder.addHierarchy(builder.addType(".?AVMiddle@@"), [{ hierarchy: leaf }]);
  const top = builder.addHierarchy(builder.addType(".?AVTop@@"), [{ hierarchy: middle }]);
  builder.addVftable(top, [builder.allocateFunctionTarget()]);
  // Middle's non-root Leaf BCD now points back to the active Top hierarchy.
  builder.patchUint32(middle.baseDescriptorRvas[1]!, 24, top.rva);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti ignores a COL pointer without a DIR64 relocation", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  builder.removeDir64Site(vftable.locatorSlotRva);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects a truncated locator pointer slot", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  builder.truncateAtRva(vftable.locatorSlotRva + 4);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects a COL without a complete following slot", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  builder.truncateAtRva(vftable.rva + 4);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects the first vftable slot without DIR64", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  builder.removeDir64Site(vftable.rva);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects a vftable target in non-executable data", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AVDataTarget@@");
  const hierarchy = builder.addHierarchy(type);
  builder.addVftable(hierarchy, [type.rva]);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti rejects an external vftable target", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  builder.patchBigUint64(vftable.rva, 0x1_4000_6000n);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti stops before the first unconfirmed slot", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture(3);
  builder.removeDir64Site(vftable.rva + 2 * 8);

  const result = await analyzeFixture(builder);

  assert.ok(result);
  assert.deepEqual(result.vftables[0]?.functionTargetRvas, vftable.functionTargetRvas.slice(0, 2));
});

void test("analyzePeMsvcRtti ignores fake COL records and decorated strings without a chain", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  builder.removeDir64Site(vftable.locatorSlotRva);
  for (let index = 0; index < 32; index += 1) builder.addDir64Pointer(0x1000);

  const result = await analyzeFixture(builder);

  assert.equal(result, null);
});

