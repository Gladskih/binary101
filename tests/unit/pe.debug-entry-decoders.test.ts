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
const IMAGE_DEBUG_TYPE_R2R_PERFMAP = 21;
const UNKNOWN_DEBUG_TYPE = 0xff;
const RSDS_SIGNATURE = 0x53445352;
const R2R_PERFMAP_MAGIC = 0x4d523252;

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

const createR2rPerfMapPayload = (path = "sample.ni.r2rmap"): Uint8Array => {
  const pathBytes = encodeNullTerminatedAscii(path);
  const bytes = new Uint8Array(24 + pathBytes.length);
  writeU32(bytes, 0, R2R_PERFMAP_MAGIC);
  bytes.set(Array.from({ length: 16 }, (_, index) => index + 1), 4);
  writeU32(bytes, 20, 1);
  bytes.set(pathBytes, 24);
  return bytes;
};

const createR2rPerfMapPayloadWithHeader = (magic: number, version: number): Uint8Array => {
  const bytes = createR2rPerfMapPayload();
  writeU32(bytes, 0, magic);
  writeU32(bytes, 20, version);
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

void test("decodeDebugEntryPayload decodes R2R_PERFMAP metadata without raw fallback", async () => {
  const { result, warnings } = await createDecodeSubject(
    IMAGE_DEBUG_TYPE_R2R_PERFMAP,
    createR2rPerfMapPayload(),
    "R2R_PERFMAP"
  );

  assert.deepEqual(result.r2rPerfMap, {
    magic: "R2RM",
    signatureBytes: Array.from({ length: 16 }, (_, index) => index + 1),
    version: 1,
    path: "sample.ni.r2rmap"
  });
  assert.equal(result.rawPayload, undefined);
  assert.deepEqual(warnings, []);
});

void test("decodeDebugEntryPayload warns when R2R_PERFMAP path is unterminated", async () => {
  const { result, warnings } = await createDecodeSubject(
    IMAGE_DEBUG_TYPE_R2R_PERFMAP,
    createR2rPerfMapPayload("sample.ni.r2rmap").slice(0, -1),
    "R2R_PERFMAP"
  );

  assert.equal(result.r2rPerfMap?.path, "sample.ni.r2rmap");
  assert.match(warnings.join(" | "), /path is not NUL-terminated/i);
});

void test("decodeDebugEntryPayload warns on unexpected R2R_PERFMAP header", async () => {
  const { result, warnings } = await createDecodeSubject(
    IMAGE_DEBUG_TYPE_R2R_PERFMAP,
    createR2rPerfMapPayloadWithHeader(0x464c414d, 2),
    "R2R_PERFMAP"
  );

  assert.equal(result.r2rPerfMap?.magic, "MALF");
  assert.equal(result.r2rPerfMap?.version, 2);
  assert.match(warnings.join(" | "), /magic is not R2RM/i);
  assert.match(warnings.join(" | "), /version 2 is not the supported version 1/i);
});

void test("decodeDebugEntryPayload falls back for short R2R_PERFMAP data", async () => {
  const { result, warnings } = await createDecodeSubject(
    IMAGE_DEBUG_TYPE_R2R_PERFMAP,
    Uint8Array.from([0x52, 0x32, 0x52]),
    "R2R_PERFMAP"
  );

  assert.deepEqual(result.rawPayload?.previewBytes, [0x52, 0x32, 0x52]);
  assert.equal(result.r2rPerfMap, undefined);
  assert.match(warnings.join(" | "), /smaller than the fixed header/i);
});

void test("decodeDebugEntryPayload warns when R2R_PERFMAP path is invalid UTF-8", async () => {
  const payload = createR2rPerfMapPayload();
  payload[payload.length - 2] = 0xff;
  const { result, warnings } = await createDecodeSubject(
    IMAGE_DEBUG_TYPE_R2R_PERFMAP,
    payload,
    "R2R_PERFMAP"
  );

  assert.match(result.r2rPerfMap?.path ?? "", /\uFFFD/);
  assert.match(warnings.join(" | "), /path is not valid UTF-8/i);
});
