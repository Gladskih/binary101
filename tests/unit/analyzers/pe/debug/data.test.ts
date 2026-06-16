"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getReadableDebugData, readDebugBytes } from "../../../../../analyzers/pe/debug/data.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../../../../fixtures/pe-debug-extra-payloads.js";

void test("getReadableDebugData resolves pointer-backed payloads", () => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(Uint8Array.from([0x10, 0x20]));

  const result = getReadableDebugData(
    "TEST",
    subject.file.size,
    identityRvaToOff,
    0,
    subject.offset,
    subject.declaredSize,
    message => warnings.push(message)
  );

  assert.deepEqual(result, { offset: subject.offset, size: subject.declaredSize });
  assert.deepEqual(warnings, []);
});

void test("getReadableDebugData resolves RVA-backed payloads when file pointer is absent", () => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(Uint8Array.from([0x10]));

  const result = getReadableDebugData(
    "TEST",
    subject.file.size,
    identityRvaToOff,
    subject.offset,
    0,
    subject.declaredSize,
    message => warnings.push(message)
  );

  assert.deepEqual(result, { offset: subject.offset, size: subject.declaredSize });
  assert.deepEqual(warnings, []);
});

void test("getReadableDebugData reports missing and unmapped payload locations", () => {
  const noLocationWarnings: string[] = [];
  const unmappedWarnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(Uint8Array.from([0x10]));

  const noLocation = getReadableDebugData(
    "TEST",
    subject.file.size,
    identityRvaToOff,
    0,
    0,
    subject.declaredSize,
    message => noLocationWarnings.push(message)
  );
  const unmapped = getReadableDebugData(
    "TEST",
    subject.file.size,
    () => null,
    subject.offset,
    0,
    subject.declaredSize,
    message => unmappedWarnings.push(message)
  );

  assert.equal(noLocation, null);
  assert.match(noLocationWarnings.join(" | "), /no PointerToRawData\/AddressOfRawData/i);
  assert.equal(unmapped, null);
  assert.match(unmappedWarnings.join(" | "), /does not map/i);
});

void test("getReadableDebugData clamps truncated payloads and rejects starts past EOF", () => {
  const truncatedWarnings: string[] = [];
  const pastEndWarnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(Uint8Array.from([0x10, 0x20]));

  const truncated = getReadableDebugData(
    "TEST",
    subject.file.size,
    identityRvaToOff,
    0,
    subject.offset,
    subject.declaredSize + 1,
    message => truncatedWarnings.push(message)
  );
  const pastEnd = getReadableDebugData(
    "TEST",
    subject.file.size,
    identityRvaToOff,
    0,
    subject.file.size,
    1,
    message => pastEndWarnings.push(message)
  );

  assert.deepEqual(truncated, { offset: subject.offset, size: subject.declaredSize });
  assert.match(truncatedWarnings.join(" | "), /shorter than its declared SizeOfData/i);
  assert.equal(pastEnd, null);
  assert.match(pastEndWarnings.join(" | "), /starts past end of file/i);
});

void test("readDebugBytes honors the preview byte limit", async () => {
  const subject = createExtraDebugPayloadSubject(Uint8Array.from([0x10, 0x20, 0x30]));

  const result = await readDebugBytes(subject.file, { offset: subject.offset, size: 3 }, 2);

  assert.deepEqual(result, [0x10, 0x20]);
});
