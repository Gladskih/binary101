"use strict";

import { MockFile } from "../helpers/mock-file.js";
import {
  createSyntheticBinaryName,
  createSyntheticLongPdbPath,
  createSyntheticPdbPath
} from "./pe-debug-payload-subject.js";

const encoder = new TextEncoder();
// Microsoft PE/COFF, IMAGE_DEBUG_DIRECTORY entry size is 28 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
const IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE = 28;
// Microsoft PE/COFF debug types used in these fixtures.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const IMAGE_DEBUG_TYPE_MISC = 4;
// RSDS is the modern CodeView signature:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
const RSDS_SIGNATURE = 0x53445352;
const RSDS_HEADER_SIZE = 24;
// Regression boundary: an older parser stopped after the first 16 debug entries.
export const LEGACY_DEBUG_ENTRY_SCAN_LIMIT = 16;
// Implementation detail in analyzers/pe/debug-codeview.ts:
// path reads are chunked to 64 bytes to avoid unbounded slice sizes.
export const EXPECTED_MAX_CODEVIEW_READ = 64;
export const RSDS_TEST_GUID_TEXT = "04030201-0605-0807-090a-0b0c0d0e0f10";
const RSDS_TEST_GUID_BYTES = Uint8Array.from([
  0x01, 0x02, 0x03, 0x04,
  0x05, 0x06,
  0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
]);

export const createSyntheticAge = (seed = 0): number => seed + 1;

export const createRsdsRecordSize = (path: string): number =>
  RSDS_HEADER_SIZE + encoder.encode(`${path}\0`).length;

const createMockDebugFile = (bytes: Uint8Array, seed: number): MockFile =>
  new MockFile(bytes, createSyntheticBinaryName(seed));

const createDebugDirectoryDataDir = (seed: number, size: number) => ({
  name: "DEBUG",
  rva: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE * (seed + 1),
  size
});

const writeDebugDirectoryEntry = (
  view: DataView,
  entryRva: number,
  type: number,
  sizeOfData: number,
  dataRva: number
): void => {
  view.setUint32(entryRva + 12, type, true);
  view.setUint32(entryRva + 16, sizeOfData, true);
  view.setUint32(entryRva + 20, dataRva, true);
  view.setUint32(entryRva + 24, dataRva, true);
};

const writeRsdsRecord = (
  view: DataView,
  bytes: Uint8Array,
  debugRva: number,
  dataRva: number,
  age: number,
  path: string,
  declaredSize = createRsdsRecordSize(path)
): void => {
  const pathBytes = encoder.encode(`${path}\0`);
  writeDebugDirectoryEntry(
    view,
    debugRva,
    IMAGE_DEBUG_TYPE_CODEVIEW,
    declaredSize,
    dataRva
  );
  view.setUint32(dataRva, RSDS_SIGNATURE, true);
  bytes.set(RSDS_TEST_GUID_BYTES, dataRva + 4);
  view.setUint32(dataRva + 20, age, true);
  bytes.set(pathBytes, dataRva + RSDS_HEADER_SIZE);
};

export const createCodeViewSubject = (
  seed = 0,
  path = createSyntheticPdbPath(seed),
  age = createSyntheticAge(seed),
  declaredSize = createRsdsRecordSize(path)
) => {
  const dataDir = createDebugDirectoryDataDir(seed, IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  const dataRva = dataDir.rva + dataDir.size;
  const bytes = new Uint8Array(dataRva + createRsdsRecordSize(path)).fill(0);
  writeRsdsRecord(new DataView(bytes.buffer), bytes, dataDir.rva, dataRva, age, path, declaredSize);
  return { age, bytes, dataDir, declaredSize, file: createMockDebugFile(bytes, seed), path };
};

export const createLargeDeclaredCodeViewSubject = (seed = 0) => {
  const path = createSyntheticPdbPath(seed);
  const declaredSize = createRsdsRecordSize(path) * createRsdsRecordSize(path);
  return createCodeViewSubject(seed, path, createSyntheticAge(seed), declaredSize);
};

export const createLongPathCodeViewSubject = (seed = 0) =>
  createCodeViewSubject(seed, createSyntheticLongPdbPath(1025, seed));

export const createClampedCodeViewSubject = (seed = 0) =>
  createCodeViewSubject(
    seed,
    createSyntheticPdbPath(seed),
    createSyntheticAge(seed),
    RSDS_HEADER_SIZE + 1
  );

export const createShortDebugDirectorySubject = (seed = 0) => ({
  dataDir: createDebugDirectoryDataDir(seed, IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE - 1),
  file: createMockDebugFile(
    new Uint8Array(
      createDebugDirectoryDataDir(seed, IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE - 1).rva +
        IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE
    ).fill(0),
    seed
  )
});

export const createTrailingDebugDirectorySubject = (seed = 0) => {
  const dataDir = createDebugDirectoryDataDir(seed, IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE + 1);
  const bytes = new Uint8Array(dataDir.rva + dataDir.size).fill(0);
  new DataView(bytes.buffer).setUint32(dataDir.rva + 12, 0, true);
  return { dataDir, file: createMockDebugFile(bytes, seed) };
};

export const createGapCodeViewSubject = (seed = 0) => {
  const path = createSyntheticPdbPath(seed);
  const entryCount = 2;
  const dataDir = createDebugDirectoryDataDir(seed, entryCount * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  const secondEntryRva = dataDir.rva + IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
  const dataRva = dataDir.rva + dataDir.size;
  const bytes = new Uint8Array(dataRva + createRsdsRecordSize(path)).fill(0);
  writeRsdsRecord(
    new DataView(bytes.buffer),
    bytes,
    secondEntryRva,
    dataRva,
    createSyntheticAge(seed),
    path
  );
  return { dataDir, file: createMockDebugFile(bytes, seed) };
};

export const createLateCodeViewSubject = (seed = 0) => {
  const path = createSyntheticPdbPath(seed);
  const age = createSyntheticAge(seed);
  const entryCount = LEGACY_DEBUG_ENTRY_SCAN_LIMIT + 1;
  const dataDir = createDebugDirectoryDataDir(seed, entryCount * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  const dataRva = dataDir.rva + dataDir.size;
  const bytes = new Uint8Array(dataRva + createRsdsRecordSize(path)).fill(0);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < LEGACY_DEBUG_ENTRY_SCAN_LIMIT; index += 1) {
    view.setUint32(dataDir.rva + index * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE + 12, 0, true);
  }
  writeRsdsRecord(
    view,
    bytes,
    dataDir.rva + LEGACY_DEBUG_ENTRY_SCAN_LIMIT * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE,
    dataRva,
    age,
    path
  );
  return { age, dataDir, file: createMockDebugFile(bytes, seed), path };
};

export const createMixedDebugDirectorySubject = (seed = 0) => {
  const path = createSyntheticPdbPath(seed);
  const entryCount = 2;
  const miscSize = RSDS_HEADER_SIZE;
  const dataDir = createDebugDirectoryDataDir(seed, entryCount * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE);
  const miscDataRva = dataDir.rva + dataDir.size;
  const rsdsDataRva = miscDataRva + miscSize;
  const bytes = new Uint8Array(rsdsDataRva + createRsdsRecordSize(path)).fill(0);
  const view = new DataView(bytes.buffer);
  writeDebugDirectoryEntry(view, dataDir.rva, IMAGE_DEBUG_TYPE_MISC, miscSize, miscDataRva);
  writeRsdsRecord(
    view,
    bytes,
    dataDir.rva + IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE,
    rsdsDataRva,
    createSyntheticAge(seed),
    path
  );
  return {
    dataDir,
    file: createMockDebugFile(bytes, seed),
    miscDataRva,
    miscSize,
    path,
    rsdsDataRva
  };
};
