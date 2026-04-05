"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOptionalHeaderAndDirectories } from "../../analyzers/pe/optional-header-parse.js";
import { MockFile } from "../helpers/mock-file.js";

const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;
const ROM_OPTIONAL_HEADER_MAGIC = 0x107;
const patternedSentinelWord = (index: number): number => ((index + 1) * 0x11111111) >>> 0;

void test("parseOptionalHeaderAndDirectories preserves data directories beyond index 15", async () => {
  const dataDirectoryCount = 17;
  const optionalHeaderSize = 0x60 + dataDirectoryCount * 8;
  const fileBytes = new Uint8Array(24 + optionalHeaderSize).fill(0);
  const view = new DataView(fileBytes.buffer);
  const optionalHeaderOffset = 24;
  const dataDirectoryOffset = optionalHeaderOffset + 0x60;

  view.setUint16(optionalHeaderOffset, PE32_OPTIONAL_HEADER_MAGIC, true);
  view.setUint32(optionalHeaderOffset + 28, 0x00400000, true); // ImageBase
  view.setUint32(optionalHeaderOffset + 32, 0x1000, true); // SectionAlignment
  view.setUint32(optionalHeaderOffset + 36, 0x0200, true); // FileAlignment
  view.setUint32(optionalHeaderOffset + 56, 0x2000, true); // SizeOfImage
  view.setUint32(optionalHeaderOffset + 60, 0x0200, true); // SizeOfHeaders
  view.setUint32(optionalHeaderOffset + 92, dataDirectoryCount, true); // NumberOfRvaAndSizes
  view.setUint32(dataDirectoryOffset + 16 * 8, 0x13572468, true);
  view.setUint32(dataDirectoryOffset + 16 * 8 + 4, 0x24681357, true);

  const parsed = await parseOptionalHeaderAndDirectories(
    new MockFile(fileBytes, "extra-data-directories.bin"),
    0,
    optionalHeaderSize
  );

  assert.strictEqual(parsed.ddCount, dataDirectoryCount);
  assert.strictEqual(parsed.dataDirs.length, dataDirectoryCount);
  assert.deepStrictEqual(parsed.dataDirs[16], {
    index: 16,
    name: "",
    rva: 0x13572468,
    size: 0x24681357
  });
});

void test("parseOptionalHeaderAndDirectories decodes IMAGE_ROM_OPTIONAL_HEADER without inventing data directories", async () => {
  const optionalHeaderSize = 0x38;
  const fileBytes = new Uint8Array(24 + optionalHeaderSize).fill(0);
  const view = new DataView(fileBytes.buffer);
  const optionalHeaderOffset = 24;

  // Microsoft PE/COFF spec: 0x10b is PE32, 0x20b is PE32+, and 0x107 identifies a ROM image.
  // IMAGE_ROM_OPTIONAL_HEADER layout comes from ntimage.h:
  // https://doxygen.reactos.org/d5/d44/ntimage_8h_source.html#l627
  view.setUint16(optionalHeaderOffset, ROM_OPTIONAL_HEADER_MAGIC, true);
  view.setUint8(optionalHeaderOffset + 2, 2);
  view.setUint8(optionalHeaderOffset + 3, 7);
  view.setUint32(optionalHeaderOffset + 4, patternedSentinelWord(0), true);
  view.setUint32(optionalHeaderOffset + 8, patternedSentinelWord(1), true);
  view.setUint32(optionalHeaderOffset + 12, patternedSentinelWord(2), true);
  view.setUint32(optionalHeaderOffset + 16, patternedSentinelWord(3), true);
  view.setUint32(optionalHeaderOffset + 20, patternedSentinelWord(4), true);
  view.setUint32(optionalHeaderOffset + 24, patternedSentinelWord(5), true);
  view.setUint32(optionalHeaderOffset + 28, patternedSentinelWord(6), true);
  view.setUint32(optionalHeaderOffset + 32, patternedSentinelWord(7), true);
  view.setUint32(optionalHeaderOffset + 36, patternedSentinelWord(8), true);
  view.setUint32(optionalHeaderOffset + 40, patternedSentinelWord(9), true);
  view.setUint32(optionalHeaderOffset + 44, patternedSentinelWord(10), true);
  view.setUint32(optionalHeaderOffset + 48, patternedSentinelWord(11), true);
  view.setUint32(optionalHeaderOffset + 52, patternedSentinelWord(12), true);

  const parsed = await parseOptionalHeaderAndDirectories(
    new MockFile(fileBytes, "rom-optional-header.bin"),
    0,
    optionalHeaderSize
  );

  assert.ok(parsed.opt);
  assert.strictEqual(parsed.opt.Magic, ROM_OPTIONAL_HEADER_MAGIC);
  assert.strictEqual(parsed.opt.LinkerMajor, 2);
  assert.strictEqual(parsed.opt.LinkerMinor, 7);
  assert.strictEqual(parsed.opt.SizeOfCode, patternedSentinelWord(0));
  assert.strictEqual(parsed.opt.SizeOfInitializedData, patternedSentinelWord(1));
  assert.strictEqual(parsed.opt.SizeOfUninitializedData, patternedSentinelWord(2));
  assert.strictEqual(parsed.opt.AddressOfEntryPoint, patternedSentinelWord(3));
  assert.strictEqual(parsed.opt.BaseOfCode, patternedSentinelWord(4));
  assert.strictEqual(parsed.opt.BaseOfData, patternedSentinelWord(5));
  assert.deepStrictEqual(parsed.opt.rom, {
    BaseOfBss: patternedSentinelWord(6),
    GprMask: patternedSentinelWord(7),
    CprMask: [
      patternedSentinelWord(8),
      patternedSentinelWord(9),
      patternedSentinelWord(10),
      patternedSentinelWord(11)
    ],
    GpValue: patternedSentinelWord(12)
  });
  assert.deepStrictEqual(parsed.dataDirs, []);
  assert.deepStrictEqual(parsed.warnings ?? [], []);
});
