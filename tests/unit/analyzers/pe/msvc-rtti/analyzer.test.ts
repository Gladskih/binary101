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

void test("analyzePeMsvcRtti confirms a simple class and contiguous virtual slots", async () => {
  const { builder, type, vftable } = createSimpleMsvcRttiFixture(3);

  const result = await analyzeFixture(builder);

  assert.ok(result);
  assert.equal(result.layout, "microsoft-cxx-amd64-image-relative-rtti-rev1");
  assert.deepEqual(result.types, [{ rva: type.rva, decoratedName: ".?AVSimple@@" }]);
  assert.deepEqual(result.vftables[0]?.functionTargetRvas, vftable.functionTargetRvas);
  assert.equal(result.completeObjectLocators.length, 1);
  assert.equal(result.classHierarchies[0]?.root.children.length, 0);
});

void test("analyzePeMsvcRtti does not let a mismatched COL poison a valid hierarchy", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const validType = builder.addType(".?AVValid@@");
  const hierarchy = builder.addHierarchy(validType);
  const mismatchedType = builder.addType(".?AVMismatched@@");
  const falseCandidate = builder.addVftable(hierarchy, [builder.allocateFunctionTarget()]);
  // MSVC rttidata.h places the image-relative TypeDescriptor reference at COL +12.
  builder.patchUint32(falseCandidate.colRva, 12, mismatchedType.rva);
  const valid = builder.addVftable(hierarchy, [builder.allocateFunctionTarget()]);

  const result = await analyzeFixture(builder);

  assert.ok(result);
  assert.ok(falseCandidate.locatorSlotRva < valid.locatorSlotRva);
  assert.deepEqual(result.completeObjectLocators.map(locator => locator.rva), [valid.colRva]);
  assert.deepEqual(result.vftables.map(vftable => vftable.rva), [valid.rva]);
  assert.deepEqual(result.types.map(type => type.decoratedName), [".?AVValid@@"]);
});

void test("analyzePeMsvcRtti reconstructs single inheritance as a tree", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const baseType = builder.addType(".?AVBase@@");
  const baseHierarchy = builder.addHierarchy(baseType);
  const derivedType = builder.addType(".?AVDerived@@");
  const derivedHierarchy = builder.addHierarchy(derivedType, [{ hierarchy: baseHierarchy }]);
  builder.addVftable(derivedHierarchy, [builder.allocateFunctionTarget()]);

  const result = await analyzeFixture(builder);

  assert.ok(result);
  const hierarchy = result.classHierarchies.find(entry => entry.rva === derivedHierarchy.rva);
  assert.ok(hierarchy);
  assert.equal(hierarchy.root.numContainedBases, 1);
  assert.equal(hierarchy.root.children[0]?.typeDescriptorRva, baseType.rva);
  assert.equal(hierarchy.root.children[0]?.children.length, 0);
});

void test("analyzePeMsvcRtti preserves multiple COL and vftables for one complete type", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const left = builder.addHierarchy(builder.addType(".?AVLeft@@"));
  const right = builder.addHierarchy(builder.addType(".?AVRight@@"));
  const completeType = builder.addType(".?AVMultiple@@");
  const hierarchy = builder.addHierarchy(
    completeType,
    [{ hierarchy: left }, { hierarchy: right, pmd: { mdisp: 16, pdisp: -1, vdisp: 0 } }],
    0x1
  );
  const sharedTarget = builder.allocateFunctionTarget();
  builder.addVftable(hierarchy, [sharedTarget], 0, 0);
  builder.addVftable(hierarchy, [sharedTarget, builder.allocateFunctionTarget()], 16, 4);

  const result = await analyzeFixture(builder);

  assert.ok(result);
  assert.equal(result.types.filter(type => type.rva === completeType.rva).length, 1);
  assert.equal(result.completeObjectLocators.length, 2);
  assert.deepEqual(result.completeObjectLocators.map(locator => locator.offset), [0, 16]);
  assert.deepEqual(result.completeObjectLocators.map(locator => locator.cdOffset), [0, 4]);
  assert.equal(result.vftables.length, 2);
  assert.equal(result.vftables.filter(table => table.functionTargetRvas.includes(sharedTarget)).length, 2);
  assert.equal(result.classHierarchies.find(entry => entry.rva === hierarchy.rva)?.root.children.length, 2);
});

void test("analyzePeMsvcRtti keeps virtual inheritance PMD and attributes signed", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const virtualBase = builder.addHierarchy(builder.addType(".?AVVirtualBase@@"));
  const completeType = builder.addType(".?AVVirtualDerived@@");
  const hierarchy = builder.addHierarchy(completeType, [{
    hierarchy: virtualBase,
    pmd: { mdisp: -8, pdisp: 16, vdisp: -4 },
    attributes: 0x10
  }], 0x2);
  builder.addVftable(hierarchy, [builder.allocateFunctionTarget()]);

  const result = await analyzeFixture(builder);

  assert.ok(result);
  const parsed = result.classHierarchies.find(entry => entry.rva === hierarchy.rva);
  assert.equal(parsed?.attributes, 0x2);
  assert.deepEqual(parsed?.root.children[0]?.pmd, { mdisp: -8, pdisp: 16, vdisp: -4 });
  assert.equal(parsed?.root.children[0]?.attributes, 0x50);
});

void test("analyzePeMsvcRtti retains independent types and repeated base subobjects", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const repeated = builder.addHierarchy(builder.addType(".?AVRepeated@@"));
  const firstType = builder.addType(".?AVFirst@@");
  const first = builder.addHierarchy(
    firstType,
    [{ hierarchy: repeated }, { hierarchy: repeated }],
    0x5
  );
  const secondType = builder.addType(".?AUStructType@@");
  const second = builder.addHierarchy(secondType);
  builder.addVftable(first, [builder.allocateFunctionTarget()]);
  builder.addVftable(second, [builder.allocateFunctionTarget()]);

  const result = await analyzeFixture(builder);

  assert.ok(result);
  assert.equal(result.completeObjectLocators.length, 2);
  assert.equal(result.types.length, 3);
  const firstTree = result.classHierarchies.find(entry => entry.rva === first.rva)?.root;
  assert.equal(firstTree?.children.length, 2);
  assert.equal(firstTree?.children[0]?.typeDescriptorRva, repeated.type.rva);
  assert.equal(firstTree?.children[1]?.typeDescriptorRva, repeated.type.rva);
  assert.notEqual(firstTree?.children[0], firstTree?.children[1]);
});
