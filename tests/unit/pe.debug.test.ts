"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDebugDirectory } from "../../analyzers/pe/debug-directory.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";
import {
  EXPECTED_MAX_CODEVIEW_READ,
  RSDS_TEST_GUID_TEXT,
  createClampedCodeViewSubject,
  createCodeViewSubject,
  createGapCodeViewSubject,
  createLargeDeclaredCodeViewSubject,
  createLateCodeViewSubject,
  createMixedDebugDirectorySubject,
  createRsdsRecordSize,
  createShortDebugDirectorySubject,
  createTrailingDebugDirectorySubject,
  createLongPathCodeViewSubject
} from "../fixtures/pe-debug-directory-subject.js";
import {
  createPogoDebugDirectorySubject,
  createVcFeatureDebugDirectorySubject
} from "../fixtures/pe-debug-payload-subject.js";

// Microsoft PE/COFF debug types used in these tests.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const IMAGE_DEBUG_TYPE_MISC = 4;
void test("parseDebugDirectory reads CodeView RSDS entry", async () => {
  const subject = createCodeViewSubject();

  const result = await parseDebugDirectory(
    subject.file,
    [subject.dataDir],
    value => value
  );

  const entry = expectDefined(result.entry);
  assert.equal(entry.age, subject.age);
  assert.equal(entry.guid, RSDS_TEST_GUID_TEXT);
  assert.equal(entry.path, subject.path);
});

void test("parseDebugDirectory bounds CodeView reads to header and path chunks", async () => {
  const subject = createLargeDeclaredCodeViewSubject();

  const tracked = createSliceTrackingFile(
    subject.bytes,
    subject.bytes.length + subject.declaredSize,
    subject.file.name
  );
  const result = await parseDebugDirectory(
    tracked.file,
    [subject.dataDir],
    value => value
  );

  assert.equal(result.entry?.age, subject.age);
  assert.ok(
    Math.max(...tracked.requests) <= EXPECTED_MAX_CODEVIEW_READ,
    `Expected bounded CodeView reads, got requests ${tracked.requests.join(", ")}`
  );
});

void test("parseDebugDirectory reads CodeView paths beyond the old 1024-byte parser cap", async () => {
  const subject = createLongPathCodeViewSubject();

  const result = await parseDebugDirectory(
    subject.file,
    [subject.dataDir],
    value => value
  );

  assert.equal(expectDefined(result.entry).path, subject.path);
});

void test("parseDebugDirectory clamps the CodeView path to SizeOfData", async () => {
  // The stored path is longer than SizeOfData allows, so only the initial byte is valid.
  const subject = createClampedCodeViewSubject();

  const result = await parseDebugDirectory(
    subject.file,
    [subject.dataDir],
    value => value
  );

  const entry = expectDefined(result.entry);
  assert.equal(entry.path, subject.path.slice(0, 1));
});

void test("parseDebugDirectory warns when the declared directory is smaller than one IMAGE_DEBUG_DIRECTORY entry", async () => {
  const subject = createShortDebugDirectorySubject();
  const result = await parseDebugDirectory(
    subject.file,
    [subject.dataDir],
    value => value
  );

  assert.equal(result.entry, null);
  assert.ok(result.warning && /smaller|truncated/i.test(result.warning));
});

void test("parseDebugDirectory warns when the directory size leaves trailing bytes after whole entries", async () => {
  const subject = createTrailingDebugDirectorySubject();
  const result = await parseDebugDirectory(
    subject.file,
    [subject.dataDir],
    value => value
  );

  assert.equal(result.entry, null);
  assert.ok(result.warning && /multiple|truncated|trailing/i.test(result.warning));
});

void test("parseDebugDirectory does not decode entries past an rvaToOff gap", async () => {
  const subject = createGapCodeViewSubject();

  const result = await parseDebugDirectory(
    subject.file,
    [subject.dataDir],
    value => (value === subject.dataDir.rva ? subject.dataDir.rva : null)
  );

  assert.equal(result.entry, null);
});

void test("parseDebugDirectory continues past the first 16 entries to find later CodeView records", async () => {
  const subject = createLateCodeViewSubject();

  const result = await parseDebugDirectory(
    subject.file,
    [subject.dataDir],
    value => value
  );

  const entry = expectDefined(result.entry);
  assert.equal(entry.age, subject.age);
  assert.equal(entry.path, subject.path);
});

void test("parseDebugDirectory preserves every debug-directory entry instead of only the first CodeView record", async () => {
  const subject = createMixedDebugDirectorySubject();

  const result = await parseDebugDirectory(
    subject.file,
    [subject.dataDir],
    value => value
  );

  assert.equal(result.entries?.length, 2);
  assert.deepEqual(
    result.entries?.map(entry => ({
      type: entry.type,
      sizeOfData: entry.sizeOfData,
      pointerToRawData: entry.pointerToRawData
    })),
    [
      {
        type: IMAGE_DEBUG_TYPE_MISC,
        sizeOfData: subject.miscSize,
        pointerToRawData: subject.miscDataRva
      },
      {
        type: IMAGE_DEBUG_TYPE_CODEVIEW,
        sizeOfData: createRsdsRecordSize(subject.path),
        pointerToRawData: subject.rsdsDataRva
      }
    ]
  );
  assert.equal(expectDefined(result.entries?.[1]).codeView?.path, subject.path);
  assert.equal(expectDefined(result.entry).path, subject.path);
});

void test("parseDebugDirectory decodes VC_FEATURE counters on matching entries", async () => {
  const { file, dataDirs, expected } = createVcFeatureDebugDirectorySubject();

  const result = await parseDebugDirectory(file, dataDirs, value => value);

  assert.deepEqual(expectDefined(result.entries?.[0]).vcFeature, expected);
});

void test("parseDebugDirectory decodes POGO signature and records on matching entries", async () => {
  const { file, dataDirs, expected } = createPogoDebugDirectorySubject();

  const result = await parseDebugDirectory(file, dataDirs, value => value);

  assert.deepEqual(expectDefined(result.entries?.[0]).pogo, expected);
});
