"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeDebugEntryPayload } from "../../analyzers/pe/debug/entry-decoders.js";
import {
  createExtraDebugPayloadSubject,
  encodeNullTerminatedAscii,
  identityRvaToOff,
  writeU32
} from "../fixtures/pe-debug-extra-payloads.js";

const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const IMAGE_DEBUG_TYPE_REPRO = 16;
const UNKNOWN_DEBUG_TYPE = 0xff;
const RSDS_SIGNATURE = 0x53445352;

const createDecodeSubject = async (type: number, payload: Uint8Array, typeName = `TYPE_${type}`) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload);
  const result = await decodeDebugEntryPayload(
    subject.file,
    {
      type,
      typeName,
      fileSize: subject.file.size,
      rvaToOff: identityRvaToOff,
      addressOfRawDataRva: 0,
      pointerToRawDataOff: subject.offset,
      dataSize: subject.declaredSize
    },
    message => warnings.push(message)
  );
  return { result, warnings };
};

const createRsdsPayload = (): Uint8Array => {
  const path = encodeNullTerminatedAscii("sample.pdb");
  const bytes = new Uint8Array(24 + path.length);
  writeU32(bytes, 0, RSDS_SIGNATURE);
  bytes.set(Uint8Array.from([1, 2, 3, 4]), 4);
  writeU32(bytes, 20, 1);
  bytes.set(path, 24);
  return bytes;
};

void test("decodeDebugEntryPayload returns known decoded payloads without raw fallback", async () => {
  const { result, warnings } = await createDecodeSubject(IMAGE_DEBUG_TYPE_REPRO, new Uint8Array(0), "REPRO");

  assert.deepEqual(result, { repro: { hashLength: null, hashBytes: [] } });
  assert.deepEqual(warnings, []);
});

void test("decodeDebugEntryPayload falls back to raw preview when known decoders reject data", async () => {
  const { result, warnings } = await createDecodeSubject(
    IMAGE_DEBUG_TYPE_CODEVIEW,
    Uint8Array.from([0x4d, 0x41, 0x4c, 0x46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    "CODEVIEW"
  );

  assert.deepEqual(result.rawPayload?.previewBytes.slice(0, 4), [0x4d, 0x41, 0x4c, 0x46]);
  assert.match(warnings.join(" | "), /signature is not RSDS or NB10/i);
});

void test("decodeDebugEntryPayload uses raw preview for unknown non-empty payload types", async () => {
  const { result, warnings } = await createDecodeSubject(UNKNOWN_DEBUG_TYPE, Uint8Array.from([0xde, 0xad]));

  assert.deepEqual(result, { rawPayload: { previewBytes: [0xde, 0xad] } });
  assert.deepEqual(warnings, []);
});

void test("decodeDebugEntryPayload leaves unknown zero-sized payloads empty", async () => {
  const { result, warnings } = await createDecodeSubject(UNKNOWN_DEBUG_TYPE, new Uint8Array(0));

  assert.deepEqual(result, {});
  assert.deepEqual(warnings, []);
});

void test("decodeDebugEntryPayload decodes CodeView before considering raw fallback", async () => {
  const { result, warnings } = await createDecodeSubject(IMAGE_DEBUG_TYPE_CODEVIEW, createRsdsPayload(), "CODEVIEW");

  assert.equal(result.codeView?.signature, "RSDS");
  assert.equal(result.rawPayload, undefined);
  assert.deepEqual(warnings, []);
});
