"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readPeApiStringCandidate } from "../../../../../analyzers/pe/disassembly/api-string-reader.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_BASE = 0x140000000n;
const STRING_RVA = 0x3000;
const PE_HEADER_RVA_LIMIT = 0x400;

const utf16zFromCodeUnits = (codeUnits: readonly number[]): Uint8Array => {
  const bytes = new Uint8Array((codeUnits.length + 1) * Uint16Array.BYTES_PER_ELEMENT);
  codeUnits.forEach((codeUnit, index) => {
    bytes[index * 2] = codeUnit & 0xff;
    bytes[index * 2 + 1] = codeUnit >> 8;
  });
  return bytes;
};

const utf16CodeUnits = (text: string): number[] =>
  [...text].map(character => character.charCodeAt(0));

const readUtf16 = (codeUnits: readonly number[]) =>
  readPeApiStringCandidate(
    new MockFile(utf16zFromCodeUnits(codeUnits)),
    rva => rva === STRING_RVA ? 0 : null,
    IMAGE_BASE,
    { address: IMAGE_BASE + BigInt(STRING_RVA), encoding: "utf-16le" }
  );

void test("readPeApiStringCandidate rejects alternating Han and ASCII UTF-16 noise", async () => {
  // Reproduces the shape of bytes that decode as repeated Han code units separated by "A".
  assert.equal(await readUtf16([
    0x67f8, 0x0041, 0x6fa4, 0x0041, 0x6fa4, 0x0041, 0x6fa4, 0x0041,
    0x6fa4, 0x0041, 0x6fa4, 0x0041, 0x6fa4, 0x0041, 0x6fa4, 0x002e
  ]), null);
});

void test("readPeApiStringCandidate rejects short alternating Han and ASCII UTF-16 noise", async () => {
  assert.equal(await readUtf16([
    0x6180, 0x0041, 0x6288, 0x0041, 0x0043
  ]), null);
});

void test("readPeApiStringCandidate rejects paired ASCII bytes decoded as UTF-16", async () => {
  // These code units are ASCII byte pairs: "Th", "is", " p", "ro", ...
  assert.equal(await readUtf16([
    0x1f0e, 0x0eba, 0xb400, 0xcd09, 0xb821, 0x4c01, 0x21cd, 0x6854,
    0x7369, 0x7020, 0x6f72, 0x7267, 0x6d61, 0x6320, 0x6e61, 0x6f6e,
    0x2074, 0x6562, 0x7220, 0x6e75, 0x6920, 0x206e, 0x4f44, 0x2053,
    0x6f6d, 0x6564, 0x0d2e, 0x0a0d, 0x0024
  ]), null);
});

void test("readPeApiStringCandidate rejects short paired ASCII bytes decoded as UTF-16", async () => {
  assert.equal(await readUtf16([
    0x6162, 0x2064, 0x7865, 0x6563, 0x7470, 0x6f69, 0x006e
  ]), null);
});

void test("readPeApiStringCandidate rejects C1-control characters in UTF-16 candidates", async () => {
  assert.equal(await readUtf16(utf16CodeUnits("bad\u0093text")), null);
});

void test("readPeApiStringCandidate rejects mixed script UTF-16 binary noise", async () => {
  assert.equal(await readUtf16([
    0x0d8b, 0x128c, 0x0059, 0x8b64, 0x8b09, 0xe203, 0x8b0c, 0x0442
  ]), null);
});

void test("readPeApiStringCandidate rejects candidates in mapped PE headers", async () => {
  // PE SizeOfHeaders commonly maps the DOS/PE headers at low RVAs; "MZx" is not payload text.
  assert.equal(await readPeApiStringCandidate(
    new MockFile(new Uint8Array([0x4d, 0x5a, 0x78, 0x00])),
    rva => rva === 0 ? 0 : null,
    IMAGE_BASE,
    { address: IMAGE_BASE, encoding: "ascii" },
    { headerRvaLimit: PE_HEADER_RVA_LIMIT }
  ), null);
});

void test("readPeApiStringCandidate keeps ASCII text stored as UTF-16", async () => {
  const decoded = await readUtf16(utf16CodeUnits("mscoree.dll"));

  assert.deepEqual(decoded, {
    rva: STRING_RVA,
    encoding: "utf-16le",
    byteLength: 22,
    text: "mscoree.dll"
  });
});

void test("readPeApiStringCandidate keeps localized CJK UTF-16 strings", async () => {
  const decoded = await readUtf16([0x65e5, 0x672c, 0x8a9e, 0x30c6, 0x30b9, 0x30c8]);

  assert.deepEqual(decoded, {
    rva: STRING_RVA,
    encoding: "utf-16le",
    byteLength: 12,
    text: String.fromCharCode(0x65e5, 0x672c, 0x8a9e, 0x30c6, 0x30b9, 0x30c8)
  });
});
