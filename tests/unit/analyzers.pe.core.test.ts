"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePeHeaders } from "../../analyzers/pe/core.js";
import {
  PE32_OPTIONAL_HEADER_MAGIC,
  ROM_OPTIONAL_HEADER_MAGIC
} from "../../analyzers/pe/optional-header-magic.js";
import type { PeOptionalHeader, PeWindowsOptionalHeader } from "../../analyzers/pe/types.js";
import { MockFile } from "../helpers/mock-file.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const DOS_SIGNATURE_MZ = 0x5a4d;
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE_OFFSET = 0x80;
const IMAGE_FILE_MACHINE_I386 = 0x014c;

const getWindowsOptionalHeader = (opt: PeOptionalHeader | null): PeWindowsOptionalHeader => {
  if (!opt || opt.Magic === ROM_OPTIONAL_HEADER_MAGIC) {
    throw new Error("Expected a Windows optional header.");
  }
  return opt;
};
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

void test("parsePeHeaders returns null when the COFF file header is truncated after a valid PE signature", async () => {
  // The buffer ends immediately after the 4-byte "PE\0\0" signature, so the 20-byte COFF header is absent.
  const bytes = new Uint8Array(PE_SIGNATURE_OFFSET + 4).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], PE_SIGNATURE_OFFSET); // "PE\0\0"

  const parsed = await parsePeHeaders(new MockFile(bytes, "truncated-coff.exe"));

  assert.strictEqual(parsed, null);
});

void test("parsePeHeaders reads the full declared section-table span without a private section-count cap", async () => {
  const coffOffset = PE_SIGNATURE_OFFSET + 4;
  // This buffer is only large enough for DOS + PE signatures + the COFF header.
  const bytes = new Uint8Array(coffOffset + 20).fill(0);
  const view = new DataView(bytes.buffer);

  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], PE_SIGNATURE_OFFSET); // "PE\0\0"
  view.setUint16(coffOffset, IMAGE_FILE_MACHINE_I386, true);
  // Microsoft PE format: the Windows loader limits the number of sections to 96.
  view.setUint16(coffOffset + 2, 0xffff, true); // Deliberately absurd to prove the parser does not impose a private cap.
  view.setUint16(coffOffset + 16, 0, true); // SizeOfOptionalHeader = 0, so only the section table read is under test.

  // Advertise a large logical file size so oversize slice requests remain observable instead of being clipped by File.size.
  const tracked = createSliceTrackingFile(
    bytes,
    coffOffset + 20 + 0xffff * 40,
    "section-count-cap.exe"
  );
  await parsePeHeaders(tracked.file);

  assert.ok(
    tracked.requests.includes(0xffff * 40),
    `Expected a full declared section-table read, got requests ${tracked.requests.join(", ")}`
  );
});

void test("parsePeHeaders preserves the raw COFF NumberOfSections field while reading section headers", async () => {
  const coffOffset = PE_SIGNATURE_OFFSET + 4;
  const bytes = new Uint8Array(coffOffset + 20).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], PE_SIGNATURE_OFFSET); // "PE\0\0"
  view.setUint16(coffOffset, IMAGE_FILE_MACHINE_I386, true);
  // PE/COFF file header: NumberOfSections is the raw 16-bit header field value.
  view.setUint16(coffOffset + 2, 0xffff, true);
  view.setUint16(coffOffset + 16, 0, true);

  const parsed = await parsePeHeaders(new MockFile(bytes, "raw-section-count.exe"));

  assert.ok(parsed);
  assert.strictEqual(parsed.coff.NumberOfSections, 0xffff);
  assert.strictEqual(parsed.sections.length, 0);
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
  view.setUint16(coffOffset, IMAGE_FILE_MACHINE_I386, true);
  view.setUint16(coffOffset + 2, 1, true);
  view.setUint16(coffOffset + 16, shortOptionalHeaderSize, true);
  view.setUint16(optionalHeaderOffset, PE32_OPTIONAL_HEADER_MAGIC, true);
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
  const opt = getWindowsOptionalHeader(parsed.opt);
  assert.strictEqual(opt.SectionAlignment, 0);
  assert.strictEqual(opt.SizeOfImage, 0);
  assert.strictEqual(opt.NumberOfRvaAndSizes, 0);
  assert.deepStrictEqual(parsed.dataDirs, []);
});

void test("parsePeHeaders keeps truncated optional headers visible with warnings", async () => {
  const coffOffset = PE_SIGNATURE_OFFSET + 4;
  const bytes = new Uint8Array(coffOffset + 20 + 8).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], PE_SIGNATURE_OFFSET); // "PE\0\0"
  view.setUint16(coffOffset, IMAGE_FILE_MACHINE_I386, true);
  view.setUint16(coffOffset + 2, 0, true);
  view.setUint16(coffOffset + 16, 0xe0, true); // Typical PE32 optional header size
  // Microsoft PE format:
  // every image file requires an optional header, so a declared image header that is physically truncated is invalid.
  view.setUint16(coffOffset + 20, PE32_OPTIONAL_HEADER_MAGIC, true);

  const parsed = await parsePeHeaders(new MockFile(bytes, "truncated-optional-header.exe"));

  assert.ok(parsed);
  assert.ok(parsed.opt);
  assert.strictEqual(parsed.opt.Magic, PE32_OPTIONAL_HEADER_MAGIC);
  assert.ok(parsed.warnings?.some(warning => /optional header|truncated/i.test(warning)));
});

void test("parsePeHeaders keeps images with unrecognized OptionalHeader.Magic visible with warnings", async () => {
  const coffOffset = PE_SIGNATURE_OFFSET + 4;
  const optionalHeaderSize = 0xe0;
  const bytes = new Uint8Array(coffOffset + 20 + optionalHeaderSize).fill(0);
  const view = new DataView(bytes.buffer);

  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], PE_SIGNATURE_OFFSET); // "PE\0\0"
  view.setUint16(coffOffset, IMAGE_FILE_MACHINE_I386, true);
  view.setUint16(coffOffset + 2, 0, true);
  view.setUint16(coffOffset + 16, optionalHeaderSize, true);
  // Microsoft PE format says the optional-header magic must be validated for format compatibility.
  view.setUint16(coffOffset + 20, 0x1337, true);

  const parsed = await parsePeHeaders(new MockFile(bytes, "unknown-optional-magic.exe"));

  assert.ok(parsed);
  assert.strictEqual(parsed.opt, null);
  assert.deepStrictEqual(parsed.dataDirs, []);
  assert.ok(parsed.warnings?.some(warning => /magic/i.test(warning)));
});

void test("parsePeHeaders honors declared optional headers larger than the old private 0x600 cap", async () => {
  const coffOffset = PE_SIGNATURE_OFFSET + 4;
  const optionalHeaderSize = 0x700;
  const bytes = new Uint8Array(coffOffset + 20 + optionalHeaderSize).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], PE_SIGNATURE_OFFSET); // "PE\0\0"
  view.setUint16(coffOffset, IMAGE_FILE_MACHINE_I386, true);
  view.setUint16(coffOffset + 16, optionalHeaderSize, true);
  // COFF SizeOfOptionalHeader is a 16-bit field; larger-but-present headers must not be rejected by a private cap.
  view.setUint16(coffOffset + 20, PE32_OPTIONAL_HEADER_MAGIC, true);
  view.setUint32(coffOffset + 24 + 28, 0x00400000, true); // ImageBase in the PE32 layout.

  const parsed = await parsePeHeaders(new MockFile(bytes, "large-optional-header.exe"));

  assert.ok(parsed);
  assert.ok(parsed.opt);
  assert.strictEqual(parsed.opt.Magic, PE32_OPTIONAL_HEADER_MAGIC);
  assert.deepStrictEqual(parsed.warnings ?? [], []);
});

void test("parsePeHeaders scans the full DOS stub instead of stopping at 64 KiB", async () => {
  const stubMessage = "custom stub message past 64 KiB";
  const stubStart = 0x40;
  const peOffset = stubStart + 0x10000 + stubMessage.length + 1;
  const bytes = new Uint8Array(peOffset + 24).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, peOffset, true);
  bytes.set(new TextEncoder().encode(stubMessage), stubStart + 0x10000);
  bytes.set([0x50, 0x45, 0x00, 0x00], peOffset); // "PE\0\0"
  view.setUint16(peOffset + 4, IMAGE_FILE_MACHINE_I386, true);

  const parsed = await parsePeHeaders(new MockFile(bytes, "full-stub-scan.exe"));

  assert.ok(parsed);
  assert.ok(parsed.dos.stub.strings?.includes(stubMessage));
});

void test("parsePeHeaders reports a truncated section table when NumberOfSections exceeds the bytes on disk", async () => {
  const coffOffset = PE_SIGNATURE_OFFSET + 4;
  const optionalHeaderSize = 0xe0;
  const optionalHeaderOffset = coffOffset + 20;
  const sectionHeaderOffset = optionalHeaderOffset + optionalHeaderSize;
  const bytes = new Uint8Array(sectionHeaderOffset + 40).fill(0);
  const view = new DataView(bytes.buffer);

  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, PE_SIGNATURE_OFFSET, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], PE_SIGNATURE_OFFSET);
  view.setUint16(coffOffset, IMAGE_FILE_MACHINE_I386, true);
  // Microsoft PE format: NumberOfSections determines the size of the section table.
  view.setUint16(coffOffset + 2, 2, true);
  view.setUint16(coffOffset + 16, optionalHeaderSize, true);
  view.setUint16(optionalHeaderOffset, PE32_OPTIONAL_HEADER_MAGIC, true);
  view.setUint32(sectionHeaderOffset + 16, 0x20, true);
  view.setUint32(sectionHeaderOffset + 20, 0x180, true);
  // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ.
  view.setUint32(sectionHeaderOffset + 36, 0x60000020, true);

  const parsed = await parsePeHeaders(new MockFile(bytes, "truncated-section-table.exe"));

  assert.ok(parsed);
  assert.strictEqual(parsed.sections.length, 1);
  assert.ok(parsed.warnings?.some(warning => /section header|truncated/i.test(warning)));
});
