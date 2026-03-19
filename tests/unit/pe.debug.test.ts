"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDebugDirectory } from "../../analyzers/pe/debug-directory.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const encoder = new TextEncoder();
const IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE = 28;
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const RSDS_SIGNATURE = 0x53445352;
const RSDS_HEADER_SIZE = 24;
const RSDS_TEST_GUID_BYTES = Uint8Array.from([
  0x01, 0x02, 0x03, 0x04,
  0x05, 0x06,
  0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
]);
const RSDS_TEST_GUID_TEXT = "04030201-0605-0807-090a-0b0c0d0e0f10";

const writeRsdsRecord = (
  view: DataView,
  bytes: Uint8Array,
  debugRva: number,
  dataRva: number,
  age: number,
  path: string,
  declaredSize = RSDS_HEADER_SIZE + encoder.encode(`${path}\0`).length
): void => {
  const pathBytes = encoder.encode(`${path}\0`);
  view.setUint32(debugRva + 12, IMAGE_DEBUG_TYPE_CODEVIEW, true);
  view.setUint32(debugRva + 16, declaredSize, true);
  view.setUint32(debugRva + 20, dataRva, true);
  view.setUint32(debugRva + 24, dataRva, true);
  // Microsoft PE/COFF debug data: RSDS is the CodeView record signature.
  view.setUint32(dataRva + 0, RSDS_SIGNATURE, true);
  bytes.set(RSDS_TEST_GUID_BYTES, dataRva + 4);
  view.setUint32(dataRva + 20, age, true);
  bytes.set(pathBytes, dataRva + RSDS_HEADER_SIZE);
};

void test("parseDebugDirectory reads CodeView RSDS entry", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const dataRva = 0x120;
  writeRsdsRecord(dv, bytes, debugRva, dataRva, 3, "C:\\path\\app.pdb");

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug.bin"),
    [{ name: "DEBUG", rva: debugRva, size: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE }],
    value => value,
    () => {}
  );

  const entry = expectDefined(result.entry);
  assert.equal(entry.age, 3);
  assert.equal(entry.guid, RSDS_TEST_GUID_TEXT);
  assert.match(entry.path, /app\.pdb/);
});

void test("parseDebugDirectory bounds CodeView reads to header and path chunks", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const dataRva = 0x120;
  writeRsdsRecord(dv, bytes, debugRva, dataRva, 7, "C:\\tracked\\app.pdb", 0x200000);

  const tracked = createSliceTrackingFile(bytes, 0x400000, "debug-bounded-read.bin");
  const result = await parseDebugDirectory(
    tracked.file,
    [{ name: "DEBUG", rva: debugRva, size: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE }],
    value => value,
    () => {}
  );

  assert.equal(result.entry?.age, 7);
  assert.ok(
    Math.max(...tracked.requests) <= 64,
    `Expected bounded CodeView reads, got requests ${tracked.requests.join(", ")}`
  );
});

void test("parseDebugDirectory clamps the CodeView path to SizeOfData", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const dataRva = 0x120;
  // The stored path is longer than SizeOfData allows, so only the initial "A" is valid.
  writeRsdsRecord(dv, bytes, debugRva, dataRva, 9, "ABC", 25);

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug-sizeofdata.bin"),
    [{ name: "DEBUG", rva: debugRva, size: IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE }],
    value => value,
    () => {}
  );

  const entry = expectDefined(result.entry);
  assert.equal(entry.path, "A");
});

void test("parseDebugDirectory warns when the declared directory is smaller than one IMAGE_DEBUG_DIRECTORY entry", async () => {
  const result = await parseDebugDirectory(
    new MockFile(new Uint8Array(64).fill(0), "debug-short.bin"),
    [{ name: "DEBUG", rva: 0x20, size: 16 }],
    value => value,
    () => {}
  );

  assert.equal(result.entry, null);
  assert.ok(result.warning && /smaller|truncated/i.test(result.warning));
});

void test("parseDebugDirectory continues past the first 16 entries to find later CodeView records", async () => {
  const bytes = new Uint8Array(2048).fill(0);
  const dv = new DataView(bytes.buffer);
  const debugRva = 0x40;
  const entryCount = 17;
  const dataRva = 0x300;

  // Microsoft PE/COFF spec, Debug Directory:
  // the directory is an array whose full extent comes from the optional-header size field.
  for (let index = 0; index < entryCount - 1; index += 1) {
    dv.setUint32(debugRva + index * 28 + 12, 0, true);
  }

  const lastEntryOffset = debugRva + (entryCount - 1) * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE;
  writeRsdsRecord(dv, bytes, lastEntryOffset, dataRva, 11, "C:\\symbols\\late-entry.pdb");

  const result = await parseDebugDirectory(
    new MockFile(bytes, "debug-late-codeview.bin"),
    [{ name: "DEBUG", rva: debugRva, size: entryCount * IMAGE_DEBUG_DIRECTORY_ENTRY_SIZE }],
    value => value,
    () => {}
  );

  const entry = expectDefined(result.entry);
  assert.equal(entry.age, 11);
  assert.match(entry.path, /late-entry\.pdb/);
});
