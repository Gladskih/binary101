"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  analyzePeNativeAotMetadata
} from "../../../../analyzers/pe/native-aot-metadata.js";
import {
  NATIVE_AOT_EMBEDDED_METADATA_SECTION,
  NATIVE_AOT_METADATA_SIGNATURE,
  NATIVE_AOT_READY_TO_RUN_SIGNATURE
} from "../../../../analyzers/pe/native-aot/format.js";
import {
  createNativeAotMetadataFixture,
  parseNativeAotMetadataFixture
} from "../../../helpers/pe-native-aot-metadata-fixture.js";
import { MockFile } from "../../../helpers/mock-file.js";
import type { PeWindowsCore } from "../../../../analyzers/pe/types.js";

const HEADER_OFFSET = 0x100;

void test("analyzePeNativeAotMetadata confirms x64 pointer-range metadata", async () => {
  const fixture = createNativeAotMetadataFixture();

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.status, "confirmed");
  assert.equal(parsed.layout, "nativeaot-readytorun-pointer-range-v1");
  assert.equal(parsed.headerRva, fixture.headerRva);
  assert.equal(parsed.modulePointerRva, fixture.modulePointerRva);
  assert.equal(parsed.majorVersion, 16);
  assert.equal(parsed.minorVersion, 0);
  assert.deepEqual(parsed.sections, [
    { type: 201, rva: 0x1300, size: 0x20 },
    {
      type: NATIVE_AOT_EMBEDDED_METADATA_SECTION,
      rva: fixture.embeddedMetadataRva,
      size: fixture.metadataSize
    }
  ]);
});

void test("analyzePeNativeAotMetadata confirms x86 pointer-range metadata", async () => {
  const fixture = createNativeAotMetadataFixture(4);

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.layout, "nativeaot-readytorun-pointer-range-v1");
});

void test("analyzePeNativeAotMetadata confirms size-pointer metadata", async () => {
  const fixture = createNativeAotMetadataFixture(8, "size-pointer");

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.ok(parsed);
  assert.equal(parsed.layout, "nativeaot-readytorun-size-pointer-v1");
});

void test("analyzePeNativeAotMetadata accepts zero-sized and singleton sections", async () => {
  const emptyRange = createNativeAotMetadataFixture();
  const rangeStart = emptyRange.view.getBigUint64(HEADER_OFFSET + 16 + 8, true);
  emptyRange.view.setBigUint64(HEADER_OFFSET + 16 + 16, rangeStart, true);
  const singleton = createNativeAotMetadataFixture();
  singleton.view.setUint32(HEADER_OFFSET + 16 + 4, 0, true);
  singleton.view.setBigUint64(HEADER_OFFSET + 16 + 16, 0n, true);
  singleton.relocations.blocks[0]!.entries.splice(2, 1);
  singleton.relocations.blocks[0]!.count -= 1;
  singleton.relocations.totalEntries -= 1;
  const explicitEmpty = createNativeAotMetadataFixture(8, "size-pointer");
  explicitEmpty.view.setUint32(HEADER_OFFSET + 16 + 4, 0, true);

  const results = await Promise.all([
    parseNativeAotMetadataFixture(emptyRange),
    parseNativeAotMetadataFixture(singleton),
    parseNativeAotMetadataFixture(explicitEmpty)
  ]);

  assert.equal(results[0]?.sections[0]?.size, 0);
  assert.equal(results[1]?.sections[0]?.size, null);
  assert.equal(results[2]?.sections[0]?.size, 0);
});

void test("analyzePeNativeAotMetadata rejects unsupported PE architectures", async () => {
  const fixture = createNativeAotMetadataFixture();
  const machine = { ...fixture.core, coff: { ...fixture.core.coff, Machine: 0xaa64 } };
  const magic = {
    ...fixture.core,
    opt: { ...fixture.core.opt, Magic: 0x10b }
  } as PeWindowsCore;

  const unsupportedMachine = await analyzePeNativeAotMetadata(
    new MockFile(fixture.bytes),
    machine,
    fixture.relocations
  );
  const mismatchedMagic = await analyzePeNativeAotMetadata(
    new MockFile(fixture.bytes),
    magic,
    fixture.relocations
  );

  assert.equal(unsupportedMachine, null);
  assert.equal(mismatchedMagic, null);
});

void test("analyzePeNativeAotMetadata requires a clean relocation graph", async () => {
  const fixture = createNativeAotMetadataFixture();
  const warning = { ...fixture.relocations, warnings: ["truncated"] };
  const inconsistent = {
    ...fixture.relocations,
    totalEntries: fixture.relocations.totalEntries + 1
  };

  const absent = await analyzePeNativeAotMetadata(new MockFile(fixture.bytes), fixture.core, null);
  const warned = await analyzePeNativeAotMetadata(
    new MockFile(fixture.bytes), fixture.core, warning);
  const mismatched = await analyzePeNativeAotMetadata(
    new MockFile(fixture.bytes),
    fixture.core,
    inconsistent
  );

  assert.equal(absent, null);
  assert.equal(warned, null);
  assert.equal(mismatched, null);
});

void test("analyzePeNativeAotMetadata requires a relocation-backed module pointer", async () => {
  const fixture = createNativeAotMetadataFixture();
  fixture.relocations.blocks[0]!.entries.shift();
  fixture.relocations.blocks[0]!.count -= 1;
  fixture.relocations.totalEntries -= 1;

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.equal(parsed, null);
});

void test("analyzePeNativeAotMetadata rejects malformed ReadyToRun headers", async () => {
  const cases = [
    { offset: 0, size: 4, value: NATIVE_AOT_READY_TO_RUN_SIGNATURE ^ 1 },
    { offset: 4, size: 2, value: 0 },
    { offset: 8, size: 4, value: 1 },
    { offset: 12, size: 2, value: 0 },
    { offset: 12, size: 2, value: 0x401 },
    { offset: 14, size: 1, value: 15 },
    { offset: 15, size: 1, value: 2 }
  ];
  for (const item of cases) {
    const fixture = createNativeAotMetadataFixture();
    if (item.size === 4) fixture.view.setUint32(HEADER_OFFSET + item.offset, item.value, true);
    else if (item.size === 2) fixture.view.setUint16(HEADER_OFFSET + item.offset, item.value, true);
    else fixture.view.setUint8(HEADER_OFFSET + item.offset, item.value);

    const parsed = await parseNativeAotMetadataFixture(fixture);

    assert.equal(parsed, null);
  }
});

void test("analyzePeNativeAotMetadata rejects malformed section entries", async () => {
  const badFlags = createNativeAotMetadataFixture();
  badFlags.view.setUint32(HEADER_OFFSET + 16 + 4, 2, true);
  const unsorted = createNativeAotMetadataFixture();
  unsorted.view.setUint32(HEADER_OFFSET + 16, NATIVE_AOT_EMBEDDED_METADATA_SECTION, true);
  unsorted.view.setUint32(HEADER_OFFSET + 16 + unsorted.entrySize, 201, true);
  const unsupportedType = createNativeAotMetadataFixture();
  unsupportedType.view.setUint32(HEADER_OFFSET + 16, 100, true);

  const results = await Promise.all([
    parseNativeAotMetadataFixture(badFlags),
    parseNativeAotMetadataFixture(unsorted),
    parseNativeAotMetadataFixture(unsupportedType)
  ]);

  assert.deepEqual(results, [null, null, null]);
});

void test("analyzePeNativeAotMetadata validates entry pointer relocations", async () => {
  const fixture = createNativeAotMetadataFixture();
  fixture.relocations.blocks[0]!.entries.splice(1, 1);
  fixture.relocations.blocks[0]!.count -= 1;
  fixture.relocations.totalEntries -= 1;

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.equal(parsed, null);
});

void test("analyzePeNativeAotMetadata validates section ranges", async () => {
  const fixture = createNativeAotMetadataFixture(8, "size-pointer");
  fixture.view.setUint32(HEADER_OFFSET + 16 + 4, 0xffff_ffff, true);

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.equal(parsed, null);
});

void test("analyzePeNativeAotMetadata requires runtime and metadata sections", async () => {
  const noRuntime = createNativeAotMetadataFixture();
  noRuntime.view.setUint32(HEADER_OFFSET + 16, 124, true);
  const noMetadata = createNativeAotMetadataFixture();
  noMetadata.view.setUint32(HEADER_OFFSET + 16 + noMetadata.entrySize, 314, true);

  const results = await Promise.all([
    parseNativeAotMetadataFixture(noRuntime),
    parseNativeAotMetadataFixture(noMetadata)
  ]);

  assert.deepEqual(results, [null, null]);
});

void test("analyzePeNativeAotMetadata validates the NativeFormat metadata signature", async () => {
  const fixture = createNativeAotMetadataFixture();
  fixture.view.setUint32(
    fixture.embeddedMetadataRva - 0x1000,
    NATIVE_AOT_METADATA_SIGNATURE ^ 1,
    true
  );

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.equal(parsed, null);
});

void test("analyzePeNativeAotMetadata tolerates rejected candidates without throwing", async () => {
  const fixture = createNativeAotMetadataFixture();
  fixture.core.sections[0]!.sizeOfRawData = HEADER_OFFSET + 8;

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.equal(parsed, null);
  assert.equal(fixture.view.getUint32(fixture.embeddedMetadataRva - 0x1000, true),
    NATIVE_AOT_METADATA_SIGNATURE);
});
