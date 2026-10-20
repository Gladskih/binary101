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
  const bytes = new Uint8Array(Math.ceil((IMAGE_DEBUG_MISC_FIXED_SIZE + textBytes.length) / 4) * 4);
  writeU32(bytes, 0, IMAGE_DEBUG_MISC_EXENAME);
  writeU32(bytes, 4, bytes.length);
  bytes.set(textBytes, IMAGE_DEBUG_MISC_FIXED_SIZE);
  return bytes;
};

const createUtf16MiscPayload = (text: string): Uint8Array => {
  const characters = `${text}\0`.split("");
  const bytes = new Uint8Array(Math.ceil((IMAGE_DEBUG_MISC_FIXED_SIZE + characters.length * 2) / 4) * 4);
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

  assert.deepEqual(result, { records: [{
    dataType: IMAGE_DEBUG_MISC_EXENAME,
    length: 28, // 12-byte header, 14 path bytes, two bytes of DWORD padding.
    unicode: false,
    text: "mfc40_opt.DBG"
  }] });
  assert.deepEqual(warnings, []);
});

void test("parseMiscDebugInfo decodes UTF-16LE DBG file names", async () => {
  const { result, warnings } = await parseSubject(createUtf16MiscPayload("debug.dbg"));

  assert.equal(result?.records[0]?.unicode, true);
  assert.equal(result?.records[0]?.text, "debug.dbg");
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

  assert.equal(result?.records[0]?.text, "short.dbg");
  assert.match(warnings.join(" | "), /length exceeds SizeOfData/i);
});

void test("parseMiscDebugInfo reports truncated declared payloads", async () => {
  const payload = createAnsiMiscPayload("tail.dbg");

  const { result, warnings } = await parseSubject(payload, payload.length + 1);

  assert.equal(result?.records[0]?.text, "tail.dbg");
  assert.match(warnings.join(" | "), /shorter than its declared SizeOfData/i);
});

void test("MISC rejects lengths smaller than its header instead of reading undeclared text", async () => {
  const payload = createAnsiMiscPayload("undeclared.dbg");
  writeU32(payload, 4, 0);

  const { result, warnings } = await parseSubject(payload);

  assert.equal(result?.records[0]?.text, "");
  assert.match(warnings.join(" | "), /length.*smaller/i);
});

void test("MISC decodes all chained records instead of losing later DBG file names", async () => {
  const first = createAnsiMiscPayload("first.dbg");
  const second = createUtf16MiscPayload("second.dbg");
  const { result, warnings } = await parseSubject(Uint8Array.from([...first, ...second]));

  assert.deepEqual(result?.records.map(record => record.text), ["first.dbg", "second.dbg"]);
  assert.deepEqual(warnings, []);
});

void test("MISC reports invalid reserved fields, encoding flags and unrecognized data types", async () => {
  const payload = createAnsiMiscPayload("unknown.dbg");
  writeU32(payload, 0, 2);
  payload[8] = 2;
  payload[9] = 1;
  const { result, warnings } = await parseSubject(payload);

  assert.equal(result?.records[0]?.text, "");
  assert.match(warnings.join(" | "), /unsupported data type/);
  assert.match(warnings.join(" | "), /Unicode flag/);
  assert.match(warnings.join(" | "), /reserved/);
});

void test("MISC preserves UTF-16 surrogate pairs split across read windows", async () => {
  const path = `${"a".repeat(31)}😀.dbg`;
  const { result, warnings } = await parseSubject(createUtf16MiscPayload(path));

  assert.equal(result?.records[0]?.text, path);
  assert.deepEqual(warnings, []);
});

void test("MISC reports unterminated ANSI text and invalid UTF-16", async () => {
  const missing = await parseSubject(createAnsiMiscPayload("abc").slice(0, -1));
  const invalid = await parseSubject(createUtf16MiscPayload("\ud800"));
  const ansi = createAnsiMiscPayload("a.dbg");
  ansi[12] = 0xe9;
  const legacy = await parseSubject(ansi);

  assert.equal(missing.result?.records[0]?.text, "abc");
  assert.match(missing.warnings.join(" | "), /not NUL-terminated/);
  assert.match(invalid.warnings.join(" | "), /not valid utf-16le/i);
  assert.equal(legacy.result?.records[0]?.text, "é.dbg");
  assert.match(legacy.warnings.join(" | "), /code page is not recorded/);
});

void test("MISC reports trailing record bytes and short header reads", async () => {
  const bytes = createAnsiMiscPayload("file.dbg");
  const trailing = await parseSubject(Uint8Array.from([...bytes, 1]));
  const warnings: string[] = [];
  const short = await parseMiscDebugInfo({ size: 20,
    read: async () => new DataView(new ArrayBuffer(4)), readBytes: async () => new Uint8Array(4)
  }, 20, identityRvaToOff, 0, 8, 12, message => warnings.push(message));

  assert.equal(trailing.result?.records.length, 1);
  assert.match(trailing.warnings.join(" | "), /trailing bytes/);
  assert.deepEqual(short, { records: [] });
  assert.match(warnings.join(" | "), /header is truncated/);
});
