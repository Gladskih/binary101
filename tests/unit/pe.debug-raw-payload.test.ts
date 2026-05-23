"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRawDebugPayload } from "../../analyzers/pe/debug/raw-payload.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../fixtures/pe-debug-extra-payloads.js";

const parseSubject = async (payload: Uint8Array, declaredSize = payload.length) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload, declaredSize);
  const result = await parseRawDebugPayload(
    "RAW",
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

void test("parseRawDebugPayload returns a bounded 32-byte preview", async () => {
  const payload = Uint8Array.from({ length: 40 }, (_, index) => index);

  const { result, warnings } = await parseSubject(payload);

  assert.equal(result?.previewBytes.length, 32);
  assert.deepEqual(result?.previewBytes.slice(0, 4), [0, 1, 2, 3]);
  assert.deepEqual(warnings, []);
});

void test("parseRawDebugPayload keeps short previews intact", async () => {
  const { result, warnings } = await parseSubject(Uint8Array.from([0xb4, 0x9c, 0x03, 0xbb]));

  assert.deepEqual(result, { previewBytes: [0xb4, 0x9c, 0x03, 0xbb] });
  assert.deepEqual(warnings, []);
});

void test("parseRawDebugPayload reports unresolved locations", async () => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(Uint8Array.from([0x01]));

  const result = await parseRawDebugPayload(
    "RAW",
    subject.file,
    subject.file.size,
    () => null,
    subject.offset,
    0,
    subject.declaredSize,
    message => warnings.push(message)
  );

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /does not map/i);
});

void test("parseRawDebugPayload reports truncated declared payloads", async () => {
  const payload = Uint8Array.from([0x01, 0x02]);

  const { result, warnings } = await parseSubject(payload, payload.length + 1);

  assert.deepEqual(result, { previewBytes: [0x01, 0x02] });
  assert.match(warnings.join(" | "), /shorter than its declared SizeOfData/i);
});
