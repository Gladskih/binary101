"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDirectory } from "../../analyzers/pe/exception.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const coverageAdd = (_label: string, _start: number, _size: number): void => {};
const identityRvaToOff = (rva: number): number => rva;
// Microsoft x64 exception handling: RUNTIME_FUNCTION is three ULONG values in .pdata.
const RUNTIME_FUNCTION_ENTRY_SIZE_BYTES = 12;
// Microsoft x64 exception handling: UNWIND_INFO version is currently 1.
const UNWIND_INFO_VERSION_1 = 1;
// parseExceptionDirectory reads the fixed 4-byte UNWIND_INFO header first.
const UNWIND_INFO_HEADER_SIZE_BYTES = Uint32Array.BYTES_PER_ELEMENT;

const createOffsetAllocator = (
  start: number
): ((size: number) => number) => {
  let nextOffset = start;
  return (size: number): number => {
    const currentOffset = nextOffset;
    nextOffset += size;
    return currentOffset;
  };
};

const createByteBuffer = (size: number): Uint8Array => new Uint8Array(size).fill(0);
const copyToArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
};

const writeRuntimeFunction = (
  view: DataView,
  offset: number,
  begin: number,
  end: number,
  unwindInfoRva: number
): void => {
  view.setUint32(offset, begin, true);
  view.setUint32(offset + 4, end, true);
  view.setUint32(offset + 8, unwindInfoRva, true);
};

const createDiscontiguousExceptionFixture = (): {
  bytes: Uint8Array;
  directoryRva: number;
  directorySize: number;
  expectedBeginRvas: number[];
  mapRvaToOff: (rva: number) => number | null;
} => {
  const entryCount = 2; // Need two entries to prove the directory mapping is not contiguous in the file.
  const directorySize = entryCount * RUNTIME_FUNCTION_ENTRY_SIZE_BYTES;
  const allocateRva = createOffsetAllocator(1); // Keep RVA non-zero so the fixture does not trip zero-is-absent checks.
  const allocateFileOffset = createOffsetAllocator(0);
  const functionSizeBytes = 1; // Smallest valid non-empty [BeginAddress, EndAddress) range.
  const directoryRva = allocateRva(directorySize);
  const firstFunctionRva = allocateRva(functionSizeBytes);
  const secondFunctionRva = allocateRva(functionSizeBytes);
  const unwindInfoRva = allocateRva(UNWIND_INFO_HEADER_SIZE_BYTES);
  const firstEntryFileOffset = allocateFileOffset(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
  allocateFileOffset(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
  const secondEntryFileOffset = allocateFileOffset(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
  const firstFunctionFileOffset = allocateFileOffset(functionSizeBytes);
  const secondFunctionFileOffset = allocateFileOffset(functionSizeBytes);
  const unwindInfoFileOffset = allocateFileOffset(UNWIND_INFO_HEADER_SIZE_BYTES);
  const bytes = createByteBuffer(unwindInfoFileOffset + UNWIND_INFO_HEADER_SIZE_BYTES);
  const view = new DataView(bytes.buffer);
  writeRuntimeFunction(
    view,
    firstEntryFileOffset,
    firstFunctionRva,
    firstFunctionRva + functionSizeBytes,
    unwindInfoRva
  );
  writeRuntimeFunction(
    view,
    secondEntryFileOffset,
    secondFunctionRva,
    secondFunctionRva + functionSizeBytes,
    unwindInfoRva
  );
  bytes[unwindInfoFileOffset] = UNWIND_INFO_VERSION_1;
  const mapRvaToOff = (rva: number): number | null => {
    if (rva >= directoryRva && rva < directoryRva + RUNTIME_FUNCTION_ENTRY_SIZE_BYTES) {
      return firstEntryFileOffset + (rva - directoryRva);
    }
    if (
      rva >= directoryRva + RUNTIME_FUNCTION_ENTRY_SIZE_BYTES &&
      rva < directoryRva + directorySize
    ) {
      return secondEntryFileOffset + (rva - directoryRva - RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
    }
    if (rva >= firstFunctionRva && rva < firstFunctionRva + functionSizeBytes) {
      return firstFunctionFileOffset + (rva - firstFunctionRva);
    }
    if (rva >= secondFunctionRva && rva < secondFunctionRva + functionSizeBytes) {
      return secondFunctionFileOffset + (rva - secondFunctionRva);
    }
    if (rva === unwindInfoRva) return unwindInfoFileOffset;
    return null;
  };
  return {
    bytes,
    directoryRva,
    directorySize,
    expectedBeginRvas: [firstFunctionRva, secondFunctionRva],
    mapRvaToOff
  };
};

const createTrackedContiguousExceptionFixture = (): {
  file: File;
  directoryRva: number;
  directorySize: number;
  entryCount: number;
  trackedRequestSizes: number[];
} => {
  const entryCount = 2; // Two entries are enough to distinguish one bulk read from two per-entry 12-byte slices.
  const functionSizeBytes = 1; // Smallest valid non-empty [BeginAddress, EndAddress) range.
  const directoryRva = 1; // Keep directory RVA non-zero because parseExceptionDirectory treats 0 as absent.
  const directorySize = entryCount * RUNTIME_FUNCTION_ENTRY_SIZE_BYTES;
  const firstFunctionRva = directoryRva + directorySize;
  const unwindInfoRva = firstFunctionRva + entryCount * functionSizeBytes;
  const bytes = createByteBuffer(unwindInfoRva + UNWIND_INFO_HEADER_SIZE_BYTES);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < entryCount; index += 1) {
    const begin = firstFunctionRva + index * functionSizeBytes;
    writeRuntimeFunction(
      view,
      directoryRva + index * RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
      begin,
      begin + functionSizeBytes,
      unwindInfoRva
    );
  }
  bytes[unwindInfoRva] = UNWIND_INFO_VERSION_1;
  const tracked = createSliceTrackingFile(bytes, bytes.length, "exception-tracked.bin");
  return {
    file: tracked.file,
    directoryRva,
    directorySize,
    entryCount,
    trackedRequestSizes: tracked.requests
  };
};

void test("parseExceptionDirectory follows discontiguous RUNTIME_FUNCTION file mappings", async () => {
  const fixture = createDiscontiguousExceptionFixture();
  const parsed = await parseExceptionDirectory(
    new File([copyToArrayBuffer(fixture.bytes)], "exception-discontiguous-pdata.bin"),
    [{ name: "EXCEPTION", rva: fixture.directoryRva, size: fixture.directorySize }],
    fixture.mapRvaToOff,
    coverageAdd
  );
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, fixture.expectedBeginRvas.length);
  assert.deepEqual(parsed.beginRvas, fixture.expectedBeginRvas);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 1);
});

void test("parseExceptionDirectory does not read each contiguous pdata entry as a separate 12-byte slice", async () => {
  const fixture = createTrackedContiguousExceptionFixture();
  const parsed = await parseExceptionDirectory(
    fixture.file,
    [{ name: "EXCEPTION", rva: fixture.directoryRva, size: fixture.directorySize }],
    identityRvaToOff,
    coverageAdd
  );
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, fixture.entryCount);
  assert.strictEqual(
    fixture.trackedRequestSizes.filter(size => size === RUNTIME_FUNCTION_ENTRY_SIZE_BYTES).length,
    0
  );
  assert.ok(fixture.trackedRequestSizes.some(size => size >= fixture.directorySize));
});
