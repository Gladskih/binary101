"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { createMsvcRttiImage } from "../../../../../analyzers/pe/msvc-rtti/image.js";
import {
  parseBaseClassDescriptor,
  parseClassHierarchyDescriptor,
  parseCompleteObjectLocator
} from "../../../../../analyzers/pe/msvc-rtti/structure-parsers.js";
import {
  createSimpleMsvcRttiFixture,
  MsvcRttiPeFixtureBuilder
} from "../../../../fixtures/pe-msvc-rtti-fixture.js";
import { MSVC_RTTI_FIXTURE_IMAGE_BASE } from "../../../../fixtures/pe-msvc-rtti-pe.js";

const imageFor = (builder: MsvcRttiPeFixtureBuilder) => {
  const fixture = builder.build();
  return createMsvcRttiImage(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core.sections,
    MSVC_RTTI_FIXTURE_IMAGE_BASE,
    fixture.core.opt.SizeOfImage
  );
};

void test("parseCompleteObjectLocator preserves unsigned offset fields", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  builder.patchUint32(vftable.colRva, 4, 0xffff_ffff);
  builder.patchUint32(vftable.colRva, 8, 0x8000_0000);

  const parsed = await parseCompleteObjectLocator(imageFor(builder), vftable.colRva);

  assert.ok(parsed);
  assert.equal(parsed.offset, 0xffff_ffff);
  assert.equal(parsed.cdOffset, 0x8000_0000);
});

void test("parseCompleteObjectLocator rejects unsupported signature and missing references", async () => {
  const unsupported = createSimpleMsvcRttiFixture();
  unsupported.builder.patchUint32(unsupported.vftable.colRva, 0, 0);
  const missingType = createSimpleMsvcRttiFixture();
  missingType.builder.patchUint32(missingType.vftable.colRva, 12, 0);
  const missingHierarchy = createSimpleMsvcRttiFixture();
  missingHierarchy.builder.patchUint32(missingHierarchy.vftable.colRva, 16, 0);

  const parsed = await Promise.all([
    parseCompleteObjectLocator(imageFor(unsupported.builder), unsupported.vftable.colRva),
    parseCompleteObjectLocator(imageFor(missingType.builder), missingType.vftable.colRva),
    parseCompleteObjectLocator(imageFor(missingHierarchy.builder), missingHierarchy.vftable.colRva)
  ]);

  assert.deepEqual(parsed, [null, null, null]);
});

void test("parseCompleteObjectLocator rejects a truncated record", async () => {
  const { builder, vftable } = createSimpleMsvcRttiFixture();
  builder.truncateAtRva(vftable.colRva + 20);

  const parsed = await parseCompleteObjectLocator(imageFor(builder), vftable.colRva);

  assert.equal(parsed, null);
});

void test("parseClassHierarchyDescriptor accepts every named attribute bit", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  builder.patchUint32(hierarchy.rva, 4, 0x7);

  const parsed = await parseClassHierarchyDescriptor(imageFor(builder), hierarchy.rva);

  assert.deepEqual(parsed, {
    attributes: 0x7,
    numBaseClasses: 1,
    baseClassArrayRva: hierarchy.baseClassArrayRva
  });
});

void test("parseClassHierarchyDescriptor rejects invalid fixed fields", async () => {
  const badSignature = createSimpleMsvcRttiFixture();
  badSignature.builder.patchUint32(badSignature.hierarchy.rva, 0, 1);
  const zeroCount = createSimpleMsvcRttiFixture();
  zeroCount.builder.patchUint32(zeroCount.hierarchy.rva, 8, 0);
  const zeroArray = createSimpleMsvcRttiFixture();
  zeroArray.builder.patchUint32(zeroArray.hierarchy.rva, 12, 0);

  const parsed = await Promise.all([
    parseClassHierarchyDescriptor(imageFor(badSignature.builder), badSignature.hierarchy.rva),
    parseClassHierarchyDescriptor(imageFor(zeroCount.builder), zeroCount.hierarchy.rva),
    parseClassHierarchyDescriptor(imageFor(zeroArray.builder), zeroArray.hierarchy.rva)
  ]);

  assert.deepEqual(parsed, [null, null, null]);
});

void test("parseBaseClassDescriptor reads signed PMD and all named attribute bits", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  const descriptorRva = hierarchy.baseDescriptorRvas[0]!;
  builder.patchInt32(descriptorRva, 8, -1);
  builder.patchInt32(descriptorRva, 12, -2);
  builder.patchInt32(descriptorRva, 16, -3);
  builder.patchUint32(descriptorRva, 20, 0x7f);

  const parsed = await parseBaseClassDescriptor(imageFor(builder), descriptorRva);

  assert.ok(parsed);
  assert.deepEqual(parsed.pmd, { mdisp: -1, pdisp: -2, vdisp: -3 });
  assert.equal(parsed.attributes, 0x7f);
});

void test("parseBaseClassDescriptor rejects missing relative references", async () => {
  const missingType = createSimpleMsvcRttiFixture();
  missingType.builder.patchUint32(missingType.hierarchy.baseDescriptorRvas[0]!, 0, 0);
  const missingHierarchy = createSimpleMsvcRttiFixture();
  missingHierarchy.builder.patchUint32(missingHierarchy.hierarchy.baseDescriptorRvas[0]!, 24, 0);

  const parsed = await Promise.all([
    parseBaseClassDescriptor(
      imageFor(missingType.builder),
      missingType.hierarchy.baseDescriptorRvas[0]!
    ),
    parseBaseClassDescriptor(
      imageFor(missingHierarchy.builder),
      missingHierarchy.hierarchy.baseDescriptorRvas[0]!
    )
  ]);

  assert.deepEqual(parsed, [null, null]);
});

void test("parseBaseClassDescriptor rejects a truncated 28-byte modern record", async () => {
  const { builder, hierarchy } = createSimpleMsvcRttiFixture();
  const descriptorRva = hierarchy.baseDescriptorRvas[0]!;
  builder.truncateAtRva(descriptorRva + 24);

  const parsed = await parseBaseClassDescriptor(imageFor(builder), descriptorRva);

  assert.equal(parsed, null);
});

