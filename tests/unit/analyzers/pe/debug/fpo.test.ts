"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFpoInfo } from "../../../../../analyzers/pe/debug/fpo.js";
import { createExtraDebugPayloadSubject, identityRvaToOff, writeU32 } from "../../../../fixtures/pe-debug-extra-payloads.js";

const FPO_RECORD_SIZE = 16;

const createFpoRecordPayload = (packed: number): Uint8Array => {
  const bytes = new Uint8Array(FPO_RECORD_SIZE);
  const view = new DataView(bytes.buffer);
  writeU32(bytes, 0, 0x1000);
  writeU32(bytes, 4, 0x20);
  writeU32(bytes, 8, 2);
  view.setUint16(12, 3, true);
  view.setUint16(14, packed, true);
  return bytes;
};

const parseSubject = async (payload: Uint8Array, declaredSize = payload.length) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload, declaredSize);
  const result = await parseFpoInfo(
    subject.file,
    subject.file.size,
    identityRvaToOff,
    0,
    subject.offset,
    subject.declaredSize,
    message => warnings.push(message)
  );
  return { result, warnings };
};

void test("parseFpoInfo decodes packed FPO_DATA records", async () => {
  // FPO_DATA packs prolog(8), saved regs(3), SEH(1), BP use(1), and frame type(2)
  // into the final WORD.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
  const packed = 0x8000 | 0x1000 | 0x0800 | 0x0500 | 0x12;

  const { result, warnings } = await parseSubject(createFpoRecordPayload(packed));

  assert.deepEqual(result?.records[0], {
    startOffset: 0x1000,
    procedureSize: 0x20,
    localDwordCount: 2,
    parameterDwordCount: 3,
    prologByteCount: 0x12,
    savedRegisterCount: 5,
    hasStructuredExceptionHandling: true,
    usesBasePointer: true,
    frameType: 2
  });
  assert.deepEqual(warnings, []);
});

void test("parseFpoInfo decodes multiple records", async () => {
  const first = createFpoRecordPayload(0);
  const second = createFpoRecordPayload(1);

  const { result, warnings } = await parseSubject(new Uint8Array([...first, ...second]));

  assert.equal(result?.records.length, 2);
  assert.deepEqual(warnings, []);
});

void test("parseFpoInfo rejects payloads smaller than one FPO_DATA record", async () => {
  const { result, warnings } = await parseSubject(new Uint8Array(FPO_RECORD_SIZE - 1));

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /smaller than one FPO_DATA record/i);
});

void test("parseFpoInfo ignores trailing bytes after whole records with a warning", async () => {
  const payload = new Uint8Array([...createFpoRecordPayload(0), 0xff]);

  const { result, warnings } = await parseSubject(payload);

  assert.equal(result?.records.length, 1);
  assert.match(warnings.join(" | "), /trailing bytes/i);
});

void test("parseFpoInfo reports truncated declared payloads", async () => {
  const payload = createFpoRecordPayload(0);

  const { result, warnings } = await parseSubject(payload, payload.length + 1);

  assert.equal(result?.records.length, 1);
  assert.match(warnings.join(" | "), /shorter than its declared SizeOfData/i);
});
