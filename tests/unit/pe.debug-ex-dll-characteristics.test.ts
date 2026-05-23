"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExDllCharacteristicsInfo } from "../../analyzers/pe/debug/ex-dll-characteristics.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../fixtures/pe-debug-extra-payloads.js";

const parseSubject = async (payload: Uint8Array, declaredSize = payload.length) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload, declaredSize);
  const result = await parseExDllCharacteristicsInfo(
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

void test("parseExDllCharacteristicsInfo decodes the 4-byte bit field", async () => {
  // Observed Windows drivers use bit 0 for CET shadow-stack compatibility.
  const { result, warnings } = await parseSubject(Uint8Array.from([0x01, 0x00, 0x00, 0x00]));

  assert.deepEqual(result, { value: 1 });
  assert.deepEqual(warnings, []);
});

void test("parseExDllCharacteristicsInfo reports payloads smaller than the bit field", async () => {
  const { result, warnings } = await parseSubject(Uint8Array.from([0x01, 0x00, 0x00]));

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /smaller than the 4-byte bit field/i);
});

void test("parseExDllCharacteristicsInfo reports trailing bytes after the bit field", async () => {
  const { result, warnings } = await parseSubject(Uint8Array.from([0x41, 0x00, 0x00, 0x00, 0xff]));

  assert.deepEqual(result, { value: 0x41 });
  assert.match(warnings.join(" | "), /trailing bytes/i);
});

void test("parseExDllCharacteristicsInfo reports unmapped payload locations", async () => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(Uint8Array.from([0x01, 0x00, 0x00, 0x00]));

  const result = await parseExDllCharacteristicsInfo(
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
