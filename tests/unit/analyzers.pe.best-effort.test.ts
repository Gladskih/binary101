"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";
import { MockFile } from "../helpers/mock-file.js";

const writeSignatureAndCoff = (bytes: Uint8Array, peOffset: number, optionalSize: number, sections: number): void => {
  bytes.set([0x50, 0x45, 0x00, 0x00], peOffset); // "PE\0\0"
  const dv = new DataView(bytes.buffer, bytes.byteOffset + peOffset + 4, 20);
  dv.setUint16(0, 0x014c, true); // Machine
  dv.setUint16(2, sections, true);
  dv.setUint32(4, 0, true); // TimeDateStamp
  dv.setUint32(8, 0, true); // PointerToSymbolTable
  dv.setUint32(12, 0, true); // NumberOfSymbols
  dv.setUint16(16, optionalSize, true);
  dv.setUint16(18, 0x0102, true); // Characteristics (executable)
};

void test("parsePe accepts PE signature inside DOS area with zero optional header", async () => {
  const peOffset = 0x10;
  const buffer = new Uint8Array(0x80);
  const dv = new DataView(buffer.buffer);
  dv.setUint16(0, 0x5a4d, true); // MZ
  dv.setUint32(0x3c, peOffset, true); // e_lfanew points inside DOS area
  writeSignatureAndCoff(buffer, peOffset, 0, 0);
  dv.setUint16(peOffset + 24, 0x10b, true); // optional header exists but SizeOfOptionalHeader is zero

  const parsed = await parsePe(new MockFile(buffer, "tiny-pe.exe"));
  assert.ok(parsed, "Expected parsePe to return result for tiny PE");
  assert.strictEqual(parsed.signature, "PE");
  assert.strictEqual(parsed.opt.Magic, 0x10b);
  assert.strictEqual(parsed.sections.length, 0);
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
  dv.setUint16(peOffset + 24, 0x10b, true);
  // Section header at declared offset, despite optional header being mostly zeros.
  const sh = new DataView(buffer.buffer, buffer.byteOffset + sectionOffset, 40);
  sh.setUint32(8, rawSize, true); // virtual size
  sh.setUint32(12, 0x1000, true); // virtual address
  sh.setUint32(16, rawSize, true); // size of raw data
  sh.setUint32(20, rawPointer, true); // pointer to raw data
  sh.setUint32(36, 0x60000020, true); // characteristics

  const parsed = await parsePe(new MockFile(buffer, "truncated-optional.exe"));
  assert.ok(parsed, "Expected parsePe to parse truncated optional header");
  assert.strictEqual(parsed.signature, "PE");
  assert.strictEqual(parsed.sections.length, 1);
  // RVA mapping should still work for the declared section.
  assert.strictEqual(parsed.rvaToOff(0x1000), rawPointer);
});
