"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { NativeAotVirtualImage } from
  "../../../../analyzers/native-aot/virtual-image-types.js";
import {
  findNativeAotMetadata,
  parseNativeAotReadyToRunHeader
} from "../../../../analyzers/native-aot/ready-to-run.js";
import {
  MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES
} from "../../../../analyzers/native-aot/reflection-metadata.js";
import {
  createNativeAotMetadataFixture,
  type NativeAotMetadataFixture
} from "../../../helpers/pe-native-aot-metadata-fixture.js";

const SECTION_RVA = 0x1000;

const createVirtualImage = (fixture: NativeAotMetadataFixture): NativeAotVirtualImage => {
  const isMappedRange = (address: number, size: number): boolean =>
    Number.isSafeInteger(address) && Number.isSafeInteger(size) && size > 0 &&
    address >= SECTION_RVA && address - SECTION_RVA <= fixture.bytes.byteLength - size;
  const readData = async (
    address: number,
    size: number,
    alignment: number
  ): Promise<DataView | null> => {
    if (!isMappedRange(address, size) || alignment <= 0 || address % alignment !== 0) return null;
    return new DataView(
      fixture.bytes.buffer,
      fixture.bytes.byteOffset + address - SECTION_RVA,
      size
    );
  };
  const readPointerValue = async (address: number): Promise<bigint | null> => {
    const view = await readData(address, fixture.pointerSize, fixture.pointerSize);
    if (!view) return null;
    return fixture.pointerSize === 8
      ? view.getBigUint64(0, true)
      : BigInt(view.getUint32(0, true));
  };
  const readPointerTarget = async (address: number): Promise<number | null> => {
    const value = await readPointerValue(address);
    if (value == null || value < fixture.core.opt.ImageBase) return null;
    const relative = value - fixture.core.opt.ImageBase;
    return relative <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(relative) : null;
  };
  return {
    pointerSize: fixture.pointerSize,
    isDataRange: (address, size, alignment) =>
      alignment > 0 && address % alignment === 0 && isMappedRange(address, size),
    isMappedRange,
    readData,
    readPointerValue,
    readPointerTarget
  };
};

const fixturePointerSites = (fixture: NativeAotMetadataFixture): Set<number> =>
  new Set(fixture.relocations.blocks.flatMap(block => block.entries
    .filter(entry => entry.type !== 0)
    .map(entry => block.pageRva + entry.offset)));

void test("logical ReadyToRun parsing uses a container-provided virtual image", async () => {
  const fixture = createNativeAotMetadataFixture();
  const image = createVirtualImage(fixture);
  const sites = fixturePointerSites(fixture);

  const header = await parseNativeAotReadyToRunHeader(image, sites, fixture.headerRva);
  const metadata = await findNativeAotMetadata(image, sites);

  assert.equal(header?.headerRva, fixture.headerRva);
  assert.equal(header?.sections.length, fixture.sectionCount);
  assert.equal(metadata?.modulePointerRva, fixture.modulePointerRva);
  assert.equal(metadata?.status, "confirmed");
});

void test("logical ReadyToRun parsing rejects missing container evidence", async () => {
  const fixture = createNativeAotMetadataFixture();
  const image = createVirtualImage(fixture);

  const missingHeader = await parseNativeAotReadyToRunHeader(
    image,
    fixturePointerSites(fixture),
    fixture.headerRva + 1
  );
  const missingPointerSites = await findNativeAotMetadata(image, new Set<number>());

  assert.equal(missingHeader, null);
  assert.equal(missingPointerSites, null);
});

void test("logical ReadyToRun discovery checks duplicate header targets once", async () => {
  const fixture = createNativeAotMetadataFixture();
  const secondPointerRva = fixture.modulePointerRva + 0x10;
  fixture.view.setBigUint64(
    secondPointerRva - SECTION_RVA,
    fixture.core.opt.ImageBase + BigInt(fixture.headerRva),
    true
  );
  fixture.view.setUint32(fixture.headerRva - SECTION_RVA, 0, true);
  const image = createVirtualImage(fixture);
  let headerReads = 0;
  const countingImage: NativeAotVirtualImage = {
    ...image,
    readData: async (address, size, alignment) => {
      if (address === fixture.headerRva) headerReads += 1;
      return image.readData(address, size, alignment);
    }
  };
  const sites = fixturePointerSites(fixture);
  sites.add(secondPointerRva);

  const metadata = await findNativeAotMetadata(countingImage, sites);

  assert.equal(metadata, null);
  assert.equal(headerReads, 1);
});

const imageAllowingMetadataSize = (
  fixture: NativeAotMetadataFixture,
  metadataSize: number
): NativeAotVirtualImage => {
  const image = createVirtualImage(fixture);
  const isDeclaredMetadata = (address: number, size: number): boolean =>
    address === fixture.embeddedMetadataRva && size === metadataSize;
  return {
    ...image,
    isDataRange: (address, size, alignment) => isDeclaredMetadata(address, size) ||
      image.isDataRange(address, size, alignment),
    isMappedRange: (address, size) => isDeclaredMetadata(address, size) ||
      image.isMappedRange(address, size)
  };
};

const setSizePointerMetadataSize = (
  fixture: NativeAotMetadataFixture,
  metadataSize: number
): void => {
  const metadataEntry = fixture.headerRva - SECTION_RVA + 16 + fixture.entrySize;
  fixture.view.setUint32(metadataEntry + 4, metadataSize, true);
};

void test("logical ReadyToRun parsing distinguishes the NativeFormat size boundary", async () => {
  const oversized = createNativeAotMetadataFixture(8, "size-pointer");
  const oversizedBytes = MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES + 1;
  setSizePointerMetadataSize(oversized, oversizedBytes);
  const boundary = createNativeAotMetadataFixture(8, "size-pointer");
  setSizePointerMetadataSize(boundary, MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES);

  const oversizedResult = await findNativeAotMetadata(
    imageAllowingMetadataSize(oversized, oversizedBytes),
    fixturePointerSites(oversized)
  );
  const boundaryResult = await findNativeAotMetadata(
    imageAllowingMetadataSize(boundary, MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES),
    fixturePointerSites(boundary)
  );

  assert.match(oversizedResult?.reflection?.warnings?.[0] ?? "", /32 MiB/);
  assert.match(boundaryResult?.reflection?.warnings?.[0] ?? "", /could not be read/i);
});
