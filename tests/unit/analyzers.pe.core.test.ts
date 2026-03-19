"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePeHeaders } from "../../analyzers/pe/core.js";
import { MockFile } from "../helpers/mock-file.js";

const DOS_SIGNATURE_MZ = 0x5a4d;
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE_OFFSET = 0x80;

void test("parsePeHeaders returns null when e_lfanew points past file end", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, bytes.length + 72, true);

  const parsed = await parsePeHeaders(new MockFile(bytes, "bad-e_lfanew.exe"));

  assert.strictEqual(parsed, null);
});

void test("parsePeHeaders returns null when PE signature is missing", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  // "PX\0\0" is intentionally close to the real "PE\0\0" signature so this exercises signature validation,
  // not an unrelated truncation path.
  bytes.set([0x50, 0x58, 0x00, 0x00], PE_SIGNATURE_OFFSET);

  const parsed = await parsePeHeaders(new MockFile(bytes, "bad-pe-sig.exe"));

  assert.strictEqual(parsed, null);
});

void test("parsePeHeaders does not read optional-header fields from section-header bytes past SizeOfOptionalHeader", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const view = new DataView(bytes.buffer);
  const coffOffset = PE_SIGNATURE_OFFSET + 4;
  const optionalHeaderOffset = coffOffset + 20;
  const shortOptionalHeaderSize = 0x20;
  const sectionHeaderOffset = optionalHeaderOffset + shortOptionalHeaderSize;

  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], PE_SIGNATURE_OFFSET); // "PE\0\0"
  view.setUint16(coffOffset, 0x014c, true); // IMAGE_FILE_MACHINE_I386
  view.setUint16(coffOffset + 2, 1, true);
  view.setUint16(coffOffset + 16, shortOptionalHeaderSize, true);
  view.setUint16(optionalHeaderOffset, 0x10b, true); // PE32 optional header magic
  view.setUint32(optionalHeaderOffset + 28, 0x00400000, true); // Typical PE32 ImageBase
  // These sentinel values are intentionally distinctive so any read past SizeOfOptionalHeader is obvious.
  view.setUint32(sectionHeaderOffset + 0, 0x1234_5678, true);
  view.setUint32(sectionHeaderOffset + 4, 0x9abc_def0, true);
  view.setUint32(sectionHeaderOffset + 8, 0x0102_0304, true);
  view.setUint32(sectionHeaderOffset + 12, 0x0506_0708, true);
  view.setUint32(sectionHeaderOffset + 16, 0x20, true);
  view.setUint32(sectionHeaderOffset + 20, 0x180, true);
  view.setUint32(sectionHeaderOffset + 36, 0x6000_0020, true);

  const parsed = await parsePeHeaders(new MockFile(bytes, "short-opt.exe"));

  assert.ok(parsed);
  assert.strictEqual(parsed.opt.SectionAlignment, 0);
  assert.strictEqual(parsed.opt.SizeOfImage, 0);
  assert.strictEqual(parsed.opt.NumberOfRvaAndSizes, 0);
  assert.deepStrictEqual(parsed.dataDirs, []);
});
