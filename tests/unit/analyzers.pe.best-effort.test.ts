"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";
import { MockFile } from "../helpers/mock-file.js";

const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;
const PE_TEXT_SECTION_CHARACTERISTICS = 0x60000020;
const EXPECTED_IMAGE_SIZE_WITH_0X600_SECTION_ALIGNMENT = 0x0c00;

const writeSignatureAndCoff = (bytes: Uint8Array, peOffset: number, optionalSize: number, sections: number): void => {
  bytes.set([0x50, 0x45, 0x00, 0x00], peOffset); // "PE\0\0"
  const dv = new DataView(bytes.buffer, bytes.byteOffset + peOffset + 4, 20);
  dv.setUint16(0, 0x014c, true); // IMAGE_FILE_MACHINE_I386
  dv.setUint16(2, sections, true);
  dv.setUint32(4, 0, true); // TimeDateStamp
  dv.setUint32(8, 0, true); // PointerToSymbolTable
  dv.setUint32(12, 0, true); // NumberOfSymbols
  dv.setUint16(16, optionalSize, true);
  dv.setUint16(18, 0x0102, true); // Characteristics (executable)
};

void test("parsePe does not invent an optional header when SizeOfOptionalHeader is zero", async () => {
  const peOffset = 0x10;
  const buffer = new Uint8Array(0x80);
  const dv = new DataView(buffer.buffer);
  dv.setUint16(0, 0x5a4d, true); // MZ
  dv.setUint32(0x3c, peOffset, true); // e_lfanew points inside DOS area
  writeSignatureAndCoff(buffer, peOffset, 0, 0);
  // SizeOfOptionalHeader=0 means the image did not declare an optional header at all.
  // Bytes after the COFF header must not be guessed as IMAGE_OPTIONAL_HEADER fields.
  dv.setUint16(peOffset + 24, PE32_OPTIONAL_HEADER_MAGIC, true);

  const parsed = await parsePe(new MockFile(buffer, "tiny-pe.exe"));
  assert.ok(parsed, "Expected parsePe to return result for tiny PE");
  assert.strictEqual(parsed.signature, "PE");
  assert.strictEqual(parsed.opt, null);
  assert.strictEqual(parsed.sections.length, 0);
  assert.ok(parsed.warnings?.some(warning => /optional header|size/i.test(warning)));
});

void test("parsePe tolerates truncated optional header and reads section table", async () => {
  const peOffset = 0x40;
  const optionalSize = 224;
  const sectionOffset = peOffset + 24 + optionalSize;
  const rawPointer = 0x200;
  const rawSize = 0x100;
  const totalSize = sectionOffset + 40 + rawPointer + rawSize;
  const buffer = new Uint8Array(totalSize);
  const dv = new DataView(buffer.buffer);
  dv.setUint16(0, 0x5a4d, true);
  dv.setUint32(0x3c, peOffset, true);
  writeSignatureAndCoff(buffer, peOffset, optionalSize, 1);
  // Write just the magic of optional header; rest left zero.
  dv.setUint16(peOffset + 24, PE32_OPTIONAL_HEADER_MAGIC, true);
  // Section header at declared offset, despite optional header being mostly zeros.
  const sh = new DataView(buffer.buffer, buffer.byteOffset + sectionOffset, 40);
  sh.setUint32(8, rawSize, true); // virtual size
  sh.setUint32(12, 0x1000, true); // virtual address
  sh.setUint32(16, rawSize, true); // size of raw data
  sh.setUint32(20, rawPointer, true); // pointer to raw data
  sh.setUint32(36, PE_TEXT_SECTION_CHARACTERISTICS, true);

  const parsed = await parsePe(new MockFile(buffer, "truncated-optional.exe"));
  assert.ok(parsed, "Expected parsePe to parse truncated optional header");
  assert.strictEqual(parsed.signature, "PE");
  assert.strictEqual(parsed.sections.length, 1);
  // RVA mapping should still work for the declared section.
  assert.strictEqual(parsed.rvaToOff(0x1000), rawPointer);
});

void test("parsePe locates section table using declared SizeOfOptionalHeader", async () => {
  const peOffset = 0x40;
  const optionalSize = 0x20;
  const sectionOffset = peOffset + 24 + optionalSize;
  const rawPointer = 0x200;
  const rawSize = 0x80;
  const totalSize = rawPointer + rawSize;
  const buffer = new Uint8Array(totalSize);
  const dv = new DataView(buffer.buffer);

  dv.setUint16(0, 0x5a4d, true);
  dv.setUint32(0x3c, peOffset, true);
  writeSignatureAndCoff(buffer, peOffset, optionalSize, 1);
  dv.setUint16(peOffset + 24, PE32_OPTIONAL_HEADER_MAGIC, true);

  const sh = new DataView(buffer.buffer, buffer.byteOffset + sectionOffset, 40);
  sh.setUint32(8, rawSize, true);
  sh.setUint32(12, 0x1000, true);
  sh.setUint32(16, rawSize, true);
  sh.setUint32(20, rawPointer, true);
  sh.setUint32(36, PE_TEXT_SECTION_CHARACTERISTICS, true);

  const parsed = await parsePe(new MockFile(buffer, "small-optional-header.exe"));
  assert.ok(parsed, "Expected parsePe to parse PE with tiny declared optional header");
  assert.strictEqual(parsed.sections.length, 1, "Section table should be read from declared boundary");
  assert.strictEqual(parsed.sections[0]?.virtualAddress, 0x1000);
  assert.strictEqual(parsed.rvaToOff(0x1000), rawPointer);
});

void test("parsePe keeps physically truncated optional headers visible with warnings", async () => {
  const peOffset = 0x40;
  const optionalSize = 0xe0;
  const buffer = new Uint8Array(peOffset + 24 + 2);
  const dv = new DataView(buffer.buffer);
  dv.setUint16(0, 0x5a4d, true);
  dv.setUint32(0x3c, peOffset, true);
  writeSignatureAndCoff(buffer, peOffset, optionalSize, 0);
  dv.setUint16(peOffset + 24, PE32_OPTIONAL_HEADER_MAGIC, true);

  const parsed = await parsePe(new MockFile(buffer, "truncated-optional-visible.exe"));

  assert.ok(parsed);
  assert.strictEqual(parsed.signature, "PE");
  assert.ok(parsed.warnings?.some(warning => /optional header|truncated/i.test(warning)));
});

void test("parsePe computes imageEnd correctly for valid SectionAlignment values that are not powers of two", async () => {
  const peOffset = 0x40;
  const optionalSize = 0xe0;
  const sectionAlignment = 0x600;
  const fileAlignment = 0x200;
  const sectionOffset = peOffset + 24 + optionalSize;
  const rawPointer = fileAlignment;
  const rawSize = fileAlignment;
  const buffer = new Uint8Array(rawPointer + rawSize).fill(0);
  const dv = new DataView(buffer.buffer);

  dv.setUint16(0, 0x5a4d, true);
  dv.setUint32(0x3c, peOffset, true);
  writeSignatureAndCoff(buffer, peOffset, optionalSize, 1);

  let optPos = peOffset + 24;
  dv.setUint16(optPos, PE32_OPTIONAL_HEADER_MAGIC, true); optPos += 2;
  // LinkerMajor is incidental here; any non-zero value keeps the synthetic header looking realistic.
  dv.setUint8(optPos, 14); optPos += 1;
  dv.setUint8(optPos, 0); optPos += 1;
  dv.setUint32(optPos, rawSize, true); optPos += 4;
  dv.setUint32(optPos, rawSize, true); optPos += 4;
  dv.setUint32(optPos, 0, true); optPos += 4;
  dv.setUint32(optPos, sectionAlignment, true); optPos += 4;
  dv.setUint32(optPos, sectionAlignment, true); optPos += 4;
  dv.setUint32(optPos, sectionAlignment, true); optPos += 4;
  dv.setUint32(optPos, 0x00400000, true); optPos += 4; // Typical PE32 ImageBase
  // Microsoft PE format: SectionAlignment must be >= FileAlignment; it is not restricted to powers of two.
  dv.setUint32(optPos, sectionAlignment, true); optPos += 4;
  dv.setUint32(optPos, fileAlignment, true); optPos += 4;
  optPos += 12;
  dv.setUint32(optPos, 0, true); optPos += 4;
  dv.setUint32(optPos, EXPECTED_IMAGE_SIZE_WITH_0X600_SECTION_ALIGNMENT, true); optPos += 4;
  dv.setUint32(optPos, fileAlignment, true); optPos += 4;
  optPos += 4;
  dv.setUint16(optPos, 2, true); optPos += 2;
  dv.setUint16(optPos, 0, true); optPos += 2;
  dv.setUint32(optPos, 0x100000, true); optPos += 4;
  dv.setUint32(optPos, 0x1000, true); optPos += 4;
  dv.setUint32(optPos, 0x100000, true); optPos += 4;
  dv.setUint32(optPos, 0x1000, true); optPos += 4;
  dv.setUint32(optPos, 0, true); optPos += 4;
  dv.setUint32(optPos, 16, true);

  const sh = new DataView(buffer.buffer, buffer.byteOffset + sectionOffset, 40);
  sh.setUint32(8, 0x200, true);
  sh.setUint32(12, sectionAlignment, true);
  sh.setUint32(16, rawSize, true);
  sh.setUint32(20, rawPointer, true);
  // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ.
  sh.setUint32(36, PE_TEXT_SECTION_CHARACTERISTICS, true);

  const parsed = await parsePe(new MockFile(buffer, "section-alignment-0x600.exe"));

  assert.ok(parsed);
  assert.strictEqual(parsed.imageEnd, EXPECTED_IMAGE_SIZE_WITH_0X600_SECTION_ALIGNMENT);
  assert.strictEqual(parsed.imageSizeMismatch, false);
});
