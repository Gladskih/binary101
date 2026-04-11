"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePogoInfo } from "../../analyzers/pe/debug-pogo.js";
import {
  createOffsetPayloadSubject,
  createPogoSubjectInfo,
  createTruncatedPogoPayload,
  createPogoPayload,
} from "../fixtures/pe-debug-payload-subject.js";

const identityRvaToOff = (value: number): number => value;

void test("parsePogoInfo reads the signature and aligned entries", async () => {
  const warnings: string[] = [];
  const expected = createPogoSubjectInfo();
  const { file, offset } = createOffsetPayloadSubject(
    createPogoPayload(expected.signature, expected.entries)
  );

  const result = await parsePogoInfo(
    file,
    file.size,
    identityRvaToOff,
    0,
    offset,
    file.size - offset,
    message => warnings.push(message)
  );

  assert.deepEqual(result, expected);
  assert.deepEqual(warnings, []);
});

void test("parsePogoInfo warns when an entry name is not NUL-terminated", async () => {
  const warnings: string[] = [];
  const expected = createPogoSubjectInfo(1);
  const { file, offset } = createOffsetPayloadSubject(createTruncatedPogoPayload());

  const result = await parsePogoInfo(
    file,
    file.size,
    identityRvaToOff,
    0,
    offset,
    file.size - offset,
    message => warnings.push(message)
  );

  assert.equal(result?.signatureName, expected.signatureName);
  assert.deepEqual(result?.entries, []);
  assert.match(warnings.join(" | "), /POGO|NUL|terminated|truncated/i);
});
