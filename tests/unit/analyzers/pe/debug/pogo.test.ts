"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePogoInfo } from "../../../../../analyzers/pe/debug/pogo.js";
import {
  createOffsetPayloadSubject,
  createPogoSubjectInfo,
  createSpgoPogoSubjectInfo,
  createTruncatedPogoPayload,
  createPogoPayload,
} from "../../../../fixtures/pe-debug-payload-subject.js";

const identityRvaToOff = (value: number): number => value;

void test("POGO reads large names in bounded windows", async () => {
  const expected = createPogoSubjectInfo(1);
  expected.entries[0]!.name = "n".repeat(65537);
  const subject = createOffsetPayloadSubject(createPogoPayload(expected.signature, expected.entries));
  const reads: number[] = [];
  const reader = { size: subject.file.size, readBytes: subject.file.readBytes.bind(subject.file),
    read: (offset: number, size: number) => { reads.push(size); return subject.file.read(offset, size); } };
  const result = await parsePogoInfo(reader, reader.size, identityRvaToOff,
    0, subject.offset, reader.size - subject.offset, () => undefined);

  assert.equal(result?.entries[0]?.name.length, 65537);
  assert.ok(Math.max(...reads) <= 64 * 1024);
});

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

void test("parsePogoInfo reads SPGO signature maps emitted by current MSVC tools", async () => {
  const warnings: string[] = [];
  const expected = createSpgoPogoSubjectInfo();
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
