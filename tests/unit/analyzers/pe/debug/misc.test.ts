"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMiscDebugInfo } from "../../../../../analyzers/pe/debug/misc.js";
import {
  createExtraDebugPayloadSubject,
  encodeNullTerminatedAscii,
  identityRvaToOff,
  writeU32
} from "../../../../fixtures/pe-debug-extra-payloads.js";

const IMAGE_DEBUG_MISC_EXENAME = 1;
const IMAGE_DEBUG_MISC_FIXED_SIZE = 12;

const createAnsiMiscPayload = (text: string): Uint8Array => {
  const textBytes = encodeNullTerminatedAscii(text);
  const bytes = new Uint8Array(IMAGE_DEBUG_MISC_FIXED_SIZE + textBytes.length);
  writeU32(bytes, 0, IMAGE_DEBUG_MISC_EXENAME);
  writeU32(bytes, 4, bytes.length);
  bytes.set(textBytes, IMAGE_DEBUG_MISC_FIXED_SIZE);
  return bytes;
};

const createUtf16MiscPayload = (text: string): Uint8Array => {
  const characters = [...`${text}\0`];
  const bytes = new Uint8Array(IMAGE_DEBUG_MISC_FIXED_SIZE + characters.length * 2);
  const view = new DataView(bytes.buffer);
  writeU32(bytes, 0, IMAGE_DEBUG_MISC_EXENAME);
  writeU32(bytes, 4, bytes.length);
  view.setUint8(8, 1);
  characters.forEach((char, index) => {
    view.setUint16(IMAGE_DEBUG_MISC_FIXED_SIZE + index * 2, char.charCodeAt(0), true);
  });
  return bytes;
};

const parseSubject = async (payload: Uint8Array, declaredSize = payload.length) => {
  const warnings: string[] = [];
  const subject = createExtraDebugPayloadSubject(payload, declaredSize);
  const result = await parseMiscDebugInfo(
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

void test("parseMiscDebugInfo decodes ANSI DBG file names", async () => {
  // Microsoft PE/COFF defines IMAGE_DEBUG_MISC.DataType 1 as EXENAME.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
  const { result, warnings } = await parseSubject(createAnsiMiscPayload("mfc40_opt.DBG"));

  assert.deepEqual(result, {
    dataType: IMAGE_DEBUG_MISC_EXENAME,
    length: 26,
    unicode: false,
    text: "mfc40_opt.DBG"
  });
  assert.deepEqual(warnings, []);
});

void test("parseMiscDebugInfo decodes UTF-16LE DBG file names", async () => {
  const { result, warnings } = await parseSubject(createUtf16MiscPayload("debug.dbg"));

  assert.equal(result?.unicode, true);
  assert.equal(result?.text, "debug.dbg");
  assert.deepEqual(warnings, []);
});

void test("parseMiscDebugInfo rejects payloads smaller than IMAGE_DEBUG_MISC", async () => {
  const { result, warnings } = await parseSubject(new Uint8Array(IMAGE_DEBUG_MISC_FIXED_SIZE - 1));

  assert.equal(result, null);
  assert.match(warnings.join(" | "), /smaller than IMAGE_DEBUG_MISC/i);
});

void test("parseMiscDebugInfo clamps length fields that exceed SizeOfData", async () => {
  const payload = createAnsiMiscPayload("short.dbg");
  writeU32(payload, 4, payload.length + 1);

  const { result, warnings } = await parseSubject(payload);

  assert.equal(result?.text, "short.dbg");
  assert.match(warnings.join(" | "), /length exceeds SizeOfData/i);
});

void test("parseMiscDebugInfo reports truncated declared payloads", async () => {
  const payload = createAnsiMiscPayload("tail.dbg");

  const { result, warnings } = await parseSubject(payload, payload.length + 1);

  assert.equal(result?.text, "tail.dbg");
  assert.match(warnings.join(" | "), /shorter than its declared SizeOfData/i);
});
