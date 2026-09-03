"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import {
  createPeNativeAotImage,
  getPeNativeAotArchitecture,
  indexPeNativeAotPointerSites,
  isPeNativeAotRvaRange
} from "../../../../../analyzers/pe/native-aot/image.js";
import { createNativeAotMetadataFixture } from
  "../../../../helpers/pe-native-aot-metadata-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const makeImage = (pointerSize: 4 | 8 = 8) => {
  const fixture = createNativeAotMetadataFixture(pointerSize);
  const architecture = getPeNativeAotArchitecture(fixture.core);
  assert.ok(architecture);
  const image = createPeNativeAotImage(
    new MockFile(fixture.bytes),
    fixture.core,
    architecture.pointerSize,
    architecture.relocationType
  );
  return { fixture, image };
};

void test("NativeAOT RVA ranges reject malformed arithmetic and accept exact bounds", () => {
  assert.equal(isPeNativeAotRvaRange(0, 1, 1), true);
  assert.equal(isPeNativeAotRvaRange(-1, 1, 1), false);
  assert.equal(isPeNativeAotRvaRange(0.5, 1, 2), false);
  assert.equal(isPeNativeAotRvaRange(0, 0, 1), false);
  assert.equal(isPeNativeAotRvaRange(0, 0.5, 1), false);
  assert.equal(isPeNativeAotRvaRange(Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER), false);
  assert.equal(isPeNativeAotRvaRange(1, 1, 1), false);
});

void test("NativeAOT image reads bounded data and preferred pointers", async () => {
  const { fixture, image } = makeImage();

  const headerRva = await image.readPointerTarget(fixture.modulePointerRva);
  const missingPointer = await image.readPointerTarget(0);

  assert.equal(headerRva, fixture.headerRva);
  assert.equal(missingPointer, null);
  assert.equal(image.isDataRange(fixture.headerRva, 16, 8), true);
  assert.equal(image.isDataRange(-1, 16, 8), false);
  assert.equal(image.isDataRange(fixture.headerRva, 0, 8), false);
  assert.equal(image.isDataRange(fixture.headerRva, 16, 0), false);
  assert.equal(image.isDataRange(fixture.headerRva + 1, 16, 8), false);
  assert.equal(image.isMappedRange(0, 1), false);
  assert.equal(image.preferredVaToRva(fixture.core.opt.ImageBase - 1n), null);
  assert.equal(image.preferredVaToRva(fixture.core.opt.ImageBase + 0x3000n), null);
});

void test("NativeAOT image rejects invalid section and reader ranges", async () => {
  const fixture = createNativeAotMetadataFixture();
  const badOffsetCore = { ...fixture.core, rvaToOff: () => null };
  const invalidSizeCore = {
    ...fixture.core,
    opt: { ...fixture.core.opt, SizeOfImage: 0 }
  };
  const shortReader: FileRangeReader = {
    size: fixture.bytes.length,
    read: async () => new DataView(new ArrayBuffer(0)),
    readBytes: async () => new Uint8Array()
  };
  const badOffset = createPeNativeAotImage(new MockFile(fixture.bytes), badOffsetCore, 8, 10);
  const invalidSize = createPeNativeAotImage(new MockFile(fixture.bytes), invalidSizeCore, 8, 10);
  const short = createPeNativeAotImage(shortReader, fixture.core, 8, 10);

  for (const characteristics of [0, 0x4000_0000, 0x0000_0040, 0x6000_0040]) {
    const core = {
      ...fixture.core,
      sections: [{ ...fixture.core.sections[0]!, characteristics }]
    };
    const image = createPeNativeAotImage(new MockFile(fixture.bytes), core, 8, 10);
    assert.equal(image.isDataRange(fixture.headerRva, 16, 8), false);
  }
  assert.equal(await badOffset.readData(fixture.headerRva, 16, 8), null);
  assert.equal(invalidSize.isDataRange(fixture.headerRva, 16, 8), false);
  assert.equal(await short.readData(fixture.headerRva, 16, 8), null);
});

void test("NativeAOT relocation index validates blocks, offsets, types, and duplicates", () => {
  const { fixture, image } = makeImage();
  const invalidOffset = structuredClone(fixture.relocations);
  invalidOffset.blocks[0]!.entries[0]!.offset = 0x1000;
  const negativeOffset = structuredClone(fixture.relocations);
  negativeOffset.blocks[0]!.entries[0]!.offset = -1;
  const fractionalOffset = structuredClone(fixture.relocations);
  fractionalOffset.blocks[0]!.entries[0]!.offset += 0.5;
  const duplicate = structuredClone(fixture.relocations);
  duplicate.blocks[0]!.entries[1] = { ...duplicate.blocks[0]!.entries[0]! };
  const wrongTypes = structuredClone(fixture.relocations);
  wrongTypes.blocks[0]!.entries.forEach(entry => { entry.type = 0; });
  const outsideData = structuredClone(fixture.relocations);
  outsideData.blocks[0]!.entries.push({ type: 10, offset: 0xfff });
  outsideData.blocks[0]!.count += 1;
  outsideData.blocks[0]!.size += 2;
  outsideData.blocks[0]!.size += outsideData.blocks[0]!.size % 4;
  outsideData.totalEntries += 1;

  assert.equal(indexPeNativeAotPointerSites(invalidOffset, image), null);
  assert.equal(indexPeNativeAotPointerSites(negativeOffset, image), null);
  assert.equal(indexPeNativeAotPointerSites(fractionalOffset, image), null);
  assert.equal(indexPeNativeAotPointerSites(duplicate, image), null);
  assert.equal(indexPeNativeAotPointerSites(wrongTypes, image), null);
  assert.deepEqual(indexPeNativeAotPointerSites(outsideData, image),
    indexPeNativeAotPointerSites(fixture.relocations, image));
  assert.ok(indexPeNativeAotPointerSites(fixture.relocations, image)
    ?.has(fixture.modulePointerRva));
});

void test("NativeAOT relocation index rejects every malformed block field", () => {
  const { fixture, image } = makeImage();
  const invalidBlocks = [
    { pageRva: Number.NaN, size: 8, count: 0, entries: [] },
    { pageRva: -0x1000, size: 8, count: 0, entries: [] },
    { pageRva: 0x1_0000_0000, size: 8, count: 0, entries: [] },
    { pageRva: 1, size: 8, count: 0, entries: [] },
    { pageRva: 0, size: Number.NaN, count: 0, entries: [] },
    { pageRva: 0, size: 4, count: 0, entries: [] },
    { pageRva: 0, size: 10, count: 0, entries: [] },
    { pageRva: 0, size: 8, count: 1, entries: [] }
  ];

  for (const block of invalidBlocks) {
    const relocations = {
      blocks: [...fixture.relocations.blocks, block],
      totalEntries: fixture.relocations.totalEntries
    };
    assert.equal(indexPeNativeAotPointerSites(relocations, image), null);
  }
});

void test("NativeAOT architecture requires matching machine and optional-header formats", () => {
  const x64 = createNativeAotMetadataFixture();
  const x86 = createNativeAotMetadataFixture(4);

  assert.deepEqual(getPeNativeAotArchitecture(x64.core), { pointerSize: 8, relocationType: 10 });
  assert.deepEqual(getPeNativeAotArchitecture(x86.core), { pointerSize: 4, relocationType: 3 });
  assert.equal(getPeNativeAotArchitecture({
    ...x64.core,
    opt: { ...x64.core.opt, Magic: 0x10b }
  } as typeof x64.core), null);
  assert.equal(getPeNativeAotArchitecture({
    ...x86.core,
    opt: { ...x86.core.opt, Magic: 0x20b }
  } as typeof x86.core), null);
});
