"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { analyzePeNativeAotMetadata } from "../../../../analyzers/pe/native-aot-metadata.js";
import {
  createNativeAotMetadataFixture,
  insertNativeAotPointerRangeSection,
  parseNativeAotMetadataFixture
} from "../../../helpers/pe-native-aot-metadata-fixture.js";
import { MockFile } from "../../../helpers/mock-file.js";

const HEADER_OFFSET = 0x100;

void test("analyzePeNativeAotMetadata rejects malformed pointer-range variants", async () => {
  const singletonRelocation = createNativeAotMetadataFixture();
  singletonRelocation.view.setUint32(HEADER_OFFSET + 16 + 4, 0, true);
  singletonRelocation.view.setBigUint64(HEADER_OFFSET + 16 + 16, 0n, true);
  const singletonValue = createNativeAotMetadataFixture();
  singletonValue.view.setUint32(HEADER_OFFSET + 16 + 4, 0, true);
  singletonValue.relocations.blocks[0]!.entries.splice(2, 1);
  singletonValue.relocations.blocks[0]!.count -= 1;
  singletonValue.relocations.totalEntries -= 1;
  const missingEnd = createNativeAotMetadataFixture();
  missingEnd.relocations.blocks[0]!.entries.splice(2, 1);
  missingEnd.relocations.blocks[0]!.count -= 1;
  missingEnd.relocations.totalEntries -= 1;
  const reversed = createNativeAotMetadataFixture();
  reversed.view.setBigUint64(HEADER_OFFSET + 16 + 16, reversed.core.opt.ImageBase + 0x12ffn, true);

  const results = await Promise.all([
    parseNativeAotMetadataFixture(singletonRelocation),
    parseNativeAotMetadataFixture(singletonValue),
    parseNativeAotMetadataFixture(missingEnd),
    parseNativeAotMetadataFixture(reversed)
  ]);

  assert.deepEqual(results, [null, null, null, null]);
});

void test("analyzePeNativeAotMetadata rejects missing and invalid entry pointers", async () => {
  const invalidStart = createNativeAotMetadataFixture();
  invalidStart.view.setBigUint64(
    HEADER_OFFSET + 16 + 8,
    invalidStart.core.opt.ImageBase - 1n,
    true
  );
  const missingSizePointer = createNativeAotMetadataFixture(8, "size-pointer");
  missingSizePointer.relocations.blocks[0]!.entries.splice(1, 1);
  missingSizePointer.relocations.blocks[0]!.count -= 1;
  missingSizePointer.relocations.totalEntries -= 1;

  const results = await Promise.all([
    parseNativeAotMetadataFixture(invalidStart),
    parseNativeAotMetadataFixture(missingSizePointer)
  ]);

  assert.deepEqual(results, [null, null]);
});

void test("analyzePeNativeAotMetadata validates the complete metadata extent", async () => {
  const tooSmall = createNativeAotMetadataFixture(8, "size-pointer");
  tooSmall.view.setUint32(HEADER_OFFSET + 16 + tooSmall.entrySize + 4, 3, true);
  const exactHeader = createNativeAotMetadataFixture(8, "size-pointer");
  exactHeader.view.setUint32(HEADER_OFFSET + 16 + exactHeader.entrySize + 4, 4, true);
  const outsideData = createNativeAotMetadataFixture(8, "size-pointer");
  outsideData.view.setUint32(HEADER_OFFSET + 16 + outsideData.entrySize + 4, 0xc01, true);

  const results = await Promise.all([
    parseNativeAotMetadataFixture(tooSmall),
    parseNativeAotMetadataFixture(exactHeader),
    parseNativeAotMetadataFixture(outsideData)
  ]);

  assert.equal(results[0], null);
  assert.equal(results[1]?.sections[1]?.size, 4);
  assert.equal(results[2], null);
});

void test("analyzePeNativeAotMetadata accepts runtime type 215 and version bytes", async () => {
  const fixture = createNativeAotMetadataFixture();
  fixture.view.setUint32(HEADER_OFFSET + 16, 215, true);
  fixture.view.setUint16(HEADER_OFFSET + 6, 0x1234, true);

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.equal(parsed?.sections[0]?.type, 215);
  assert.equal(parsed?.minorVersion, 0x1234);
});

void test("analyzePeNativeAotMetadata enforces sorted supported section types", async () => {
  const unsupported = createNativeAotMetadataFixture();
  insertNativeAotPointerRangeSection(unsupported, 250);
  const duplicate = createNativeAotMetadataFixture();
  insertNativeAotPointerRangeSection(duplicate, 201);

  const results = await Promise.all([
    parseNativeAotMetadataFixture(unsupported),
    parseNativeAotMetadataFixture(duplicate)
  ]);

  assert.deepEqual(results, [null, null]);
});

void test("analyzePeNativeAotMetadata requires file-backed embedded metadata", async () => {
  const fixture = createNativeAotMetadataFixture();
  fixture.core.sections[0]!.sizeOfRawData = 0x404;

  const parsed = await parseNativeAotMetadataFixture(fixture);

  assert.equal(parsed, null);
});

void test("analyzePeNativeAotMetadata contains unexpected reader failures", async () => {
  const fixture = createNativeAotMetadataFixture();
  const throwingReader: FileRangeReader = {
    size: fixture.bytes.length,
    read: () => Promise.reject(new Error("fixture read failure")),
    readBytes: () => Promise.reject(new Error("fixture read failure"))
  };

  const parsed = await analyzePeNativeAotMetadata(
    throwingReader,
    fixture.core,
    fixture.relocations
  );

  assert.equal(parsed, null);
});

void test("deep metadata read failures preserve confirmed NativeAOT", async () => {
  const fixture = createNativeAotMetadataFixture();
  const backing = new MockFile(fixture.bytes);
  const reader: FileRangeReader = {
    size: backing.size,
    read: (offset, size) => size === fixture.metadataSize
      ? Promise.reject(new Error("deep read failure"))
      : backing.read(offset, size),
    readBytes: (offset, size) => backing.readBytes(offset, size)
  };

  const parsed = await analyzePeNativeAotMetadata(reader, fixture.core, fixture.relocations);

  assert.equal(parsed?.status, "confirmed");
  assert.deepEqual(parsed?.reflection, {
    scopes: [],
    warnings: ["NativeFormat metadata could not be read."]
  });
});
