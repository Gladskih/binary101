"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectDebugExceptionConsistencyFindings } from "../../../../../analyzers/pe/debug/exception-consistency.js";
import type { PeDebugDirectoryEntry } from "../../../../../analyzers/pe/debug/directory.js";
import type { PeDataDirectory, RvaToOffset } from "../../../../../analyzers/pe/types.js";
import type { FileRangeReader } from "../../../../../analyzers/file-range-reader.js";

// Windows SDK winnt.h defines IMAGE_DEBUG_TYPE_EXCEPTION as 5.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
const IMAGE_DEBUG_TYPE_EXCEPTION = 5;
const MAIN_EXCEPTION_RVA = 0x1000;
const MAIN_EXCEPTION_OFFSET = 0x20;
const DEBUG_EXCEPTION_RVA = 0x2000;
const DEBUG_EXCEPTION_OFFSET = 0x40;

const createReader = (bytes: Uint8Array): FileRangeReader & { getReadByteCalls: () => number } => {
  let readByteCalls = 0;
  return {
    size: bytes.byteLength,
    read: async (offset, size) => {
      const start = Math.max(0, Math.min(offset, bytes.byteLength));
      const end = Math.max(start, Math.min(offset + size, bytes.byteLength));
      return new DataView(bytes.buffer, bytes.byteOffset + start, end - start);
    },
    readBytes: async (offset, size) => {
      const start = Math.max(0, Math.min(offset, bytes.byteLength));
      const end = Math.max(start, Math.min(offset + size, bytes.byteLength));
      readByteCalls += 1;
      return bytes.subarray(start, end);
    },
    getReadByteCalls: () => readByteCalls
  };
};

const createRvaToOff = (): RvaToOffset => rva => {
  if (rva === MAIN_EXCEPTION_RVA) return MAIN_EXCEPTION_OFFSET;
  if (rva === DEBUG_EXCEPTION_RVA) return DEBUG_EXCEPTION_OFFSET;
  return null;
};

const createExceptionDirectory = (size: number): PeDataDirectory => ({
  name: "EXCEPTION",
  rva: MAIN_EXCEPTION_RVA,
  size
});

const createDebugEntry = (
  type: number,
  sizeOfData = 4,
  pointerToRawData = DEBUG_EXCEPTION_OFFSET
): PeDebugDirectoryEntry => ({
  characteristics: 0,
  type,
  typeName: type === IMAGE_DEBUG_TYPE_EXCEPTION ? "EXCEPTION" : `TYPE_${type}`,
  sizeOfData,
  addressOfRawData: DEBUG_EXCEPTION_RVA,
  pointerToRawData
});

void test("collectDebugExceptionConsistencyFindings ignores non-EXCEPTION debug entries", async () => {
  const findings = await collectDebugExceptionConsistencyFindings(
    createReader(new Uint8Array(0x80)),
    [],
    createRvaToOff(),
    [createDebugEntry(2)]
  );

  assert.deepEqual(findings, { notes: [], warnings: [] });
});

void test("collectDebugExceptionConsistencyFindings reports EXCEPTION debug entry without main table", async () => {
  const findings = await collectDebugExceptionConsistencyFindings(
    createReader(new Uint8Array(0x80)),
    [],
    createRvaToOff(),
    [createDebugEntry(IMAGE_DEBUG_TYPE_EXCEPTION)]
  );

  assert.deepEqual(findings.notes, []);
  assert.equal(findings.warnings.length, 1);
  assert.match(findings.warnings[0] ?? "", /Exception Table data directory is absent/i);
});

void test("collectDebugExceptionConsistencyFindings reports separate matching .pdata bytes", async () => {
  const bytes = new Uint8Array(0x80);
  bytes.set([1, 2, 3, 4], MAIN_EXCEPTION_OFFSET);
  bytes.set([1, 2, 3, 4], DEBUG_EXCEPTION_OFFSET);
  const findings = await collectDebugExceptionConsistencyFindings(
    createReader(bytes),
    [createExceptionDirectory(4)],
    createRvaToOff(),
    [createDebugEntry(IMAGE_DEBUG_TYPE_EXCEPTION)]
  );

  assert.equal(findings.notes.length, 1);
  assert.match(findings.notes[0] ?? "", /separate physical byte range/i);
  assert.deepEqual(findings.warnings, []);
});

void test("collectDebugExceptionConsistencyFindings reports same physical .pdata range without byte scan", async () => {
  const reader = createReader(new Uint8Array(0x80));
  const findings = await collectDebugExceptionConsistencyFindings(
    reader,
    [createExceptionDirectory(4)],
    createRvaToOff(),
    [createDebugEntry(IMAGE_DEBUG_TYPE_EXCEPTION, 4, MAIN_EXCEPTION_OFFSET)]
  );

  assert.equal(reader.getReadByteCalls(), 0);
  assert.equal(findings.notes.length, 1);
  assert.match(findings.notes[0] ?? "", /same physical byte range/i);
  assert.deepEqual(findings.warnings, []);
});

void test("collectDebugExceptionConsistencyFindings reports overlapping ranges without byte scan", async () => {
  const reader = createReader(new Uint8Array(0x80));
  const findings = await collectDebugExceptionConsistencyFindings(
    reader,
    [createExceptionDirectory(8)],
    createRvaToOff(),
    [createDebugEntry(IMAGE_DEBUG_TYPE_EXCEPTION, 8, MAIN_EXCEPTION_OFFSET + 4)]
  );

  assert.equal(reader.getReadByteCalls(), 0);
  assert.deepEqual(findings.notes, []);
  assert.equal(findings.warnings.length, 1);
  assert.match(findings.warnings[0] ?? "", /partially overlaps/i);
});

void test("collectDebugExceptionConsistencyFindings reports .pdata byte mismatches", async () => {
  const bytes = new Uint8Array(0x80);
  bytes.set([1, 2, 3, 4], MAIN_EXCEPTION_OFFSET);
  bytes.set([1, 2, 3, 5], DEBUG_EXCEPTION_OFFSET);
  const findings = await collectDebugExceptionConsistencyFindings(
    createReader(bytes),
    [createExceptionDirectory(4)],
    createRvaToOff(),
    [createDebugEntry(IMAGE_DEBUG_TYPE_EXCEPTION)]
  );

  assert.equal(findings.notes.length, 1);
  assert.match(findings.notes[0] ?? "", /separate physical byte range/i);
  assert.equal(findings.warnings.length, 1);
  assert.match(findings.warnings[0] ?? "", /does not match/i);
});

void test("collectDebugExceptionConsistencyFindings reports .pdata size mismatches", async () => {
  const bytes = new Uint8Array(0x80);
  bytes.set([1, 2, 3, 4], MAIN_EXCEPTION_OFFSET);
  bytes.set([1, 2, 3, 4, 5], DEBUG_EXCEPTION_OFFSET);
  const findings = await collectDebugExceptionConsistencyFindings(
    createReader(bytes),
    [createExceptionDirectory(4)],
    createRvaToOff(),
    [createDebugEntry(IMAGE_DEBUG_TYPE_EXCEPTION, 5)]
  );

  assert.equal(findings.notes.length, 1);
  assert.match(findings.notes[0] ?? "", /separate physical byte range/i);
  assert.equal(findings.warnings.length, 1);
  assert.match(findings.warnings[0] ?? "", /does not match/i);
});

void test("collectDebugExceptionConsistencyFindings does not report invalid main table as absent", async () => {
  const findings = await collectDebugExceptionConsistencyFindings(
    createReader(new Uint8Array(0x30)),
    [createExceptionDirectory(0x20)],
    createRvaToOff(),
    [createDebugEntry(IMAGE_DEBUG_TYPE_EXCEPTION)]
  );

  assert.equal(findings.notes.length, 1);
  assert.match(findings.notes[0] ?? "", /could not be determined/i);
  assert.deepEqual(findings.warnings, []);
});
