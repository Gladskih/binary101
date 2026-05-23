"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseReproInfo } from "../../analyzers/pe/debug/repro.js";
import { createExtraDebugPayloadSubject, identityRvaToOff, writeU32 } from "../fixtures/pe-debug-extra-payloads.js";

const parseSubject = async (payload: Uint8Array, declaredSize = payload.length) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload, declaredSize);
  const result = await parseReproInfo(
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

void test("parseReproInfo decodes empty deterministic-build markers", async () => {
  const { result, warnings } = await parseSubject(new Uint8Array(0));

  assert.deepEqual(result, { hashLength: null, hashBytes: [] });
  assert.deepEqual(warnings, []);
});

void test("parseReproInfo decodes hash-length-prefixed hashes", async () => {
  const payload = Uint8Array.from([3, 0, 0, 0, 0xaa, 0xbb, 0xcc]);

  const { result, warnings } = await parseSubject(payload);

  assert.deepEqual(result, { hashLength: 3, hashBytes: [0xaa, 0xbb, 0xcc] });
  assert.deepEqual(warnings, []);
});

void test("parseReproInfo reports payloads smaller than the hash-length field", async () => {
  const { result, warnings } = await parseSubject(Uint8Array.from([0x03, 0x00, 0x00]));

  assert.deepEqual(result, { hashLength: null, hashBytes: [] });
  assert.match(warnings.join(" | "), /smaller than the hash-length field/i);
});

void test("parseReproInfo reports declared hash length beyond available bytes", async () => {
  const payload = Uint8Array.from([4, 0, 0, 0, 0xaa]);

  const { result, warnings } = await parseSubject(payload);

  assert.deepEqual(result, { hashLength: 4, hashBytes: [0xaa] });
  assert.match(warnings.join(" | "), /hash is shorter than its declared length/i);
});

void test("parseReproInfo reports trailing bytes after the declared hash", async () => {
  const payload = Uint8Array.from([1, 0, 0, 0, 0xaa, 0xbb]);

  const { result, warnings } = await parseSubject(payload);

  assert.deepEqual(result, { hashLength: 1, hashBytes: [0xaa] });
  assert.match(warnings.join(" | "), /trailing bytes/i);
});

void test("parseReproInfo reports truncated file data without throwing", async () => {
  const payload = new Uint8Array(4);
  writeU32(payload, 0, 2);

  const { result, warnings } = await parseSubject(payload, payload.length + 1);

  assert.deepEqual(result, { hashLength: 2, hashBytes: [] });
  assert.match(warnings.join(" | "), /shorter than its declared SizeOfData|shorter than its declared length/i);
});
