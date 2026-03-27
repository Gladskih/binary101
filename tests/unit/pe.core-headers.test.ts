"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOptionalHeaderAndDirectories } from "../../analyzers/pe/core-headers.js";
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

void test("parseOptionalHeaderAndDirectories does not treat ROM optional headers as PE32", async () => {
  const optionalHeaderSize = 0x60;
  const fileBytes = new Uint8Array(24 + optionalHeaderSize).fill(0);
  const view = new DataView(fileBytes.buffer);
  const optionalHeaderOffset = 24;

  // Microsoft PE/COFF spec: 0x10b is PE32, 0x20b is PE32+, and 0x107 identifies a ROM image.
  // A ROM optional header is not format-compatible with IMAGE_OPTIONAL_HEADER32.
  view.setUint16(optionalHeaderOffset, ROM_OPTIONAL_HEADER_MAGIC, true);
  // Patterned non-zero words make accidental PE32 decoding obvious without pretending these values are meaningful.
  view.setUint32(optionalHeaderOffset + 28, patternedSentinelWord(0), true);
  view.setUint32(optionalHeaderOffset + 32, patternedSentinelWord(1), true);
  view.setUint32(optionalHeaderOffset + 36, patternedSentinelWord(2), true);
  view.setUint32(optionalHeaderOffset + 56, patternedSentinelWord(3), true);
  view.setUint32(optionalHeaderOffset + 60, patternedSentinelWord(4), true);
  // Any non-zero count is enough here; the regression checks that ROM headers do not decode PE32 data directories at all.
  view.setUint32(optionalHeaderOffset + 92, 7, true);

  const parsed = await parseOptionalHeaderAndDirectories(
    new MockFile(fileBytes, "rom-optional-header.bin"),
    0,
    optionalHeaderSize
  );

  assert.strictEqual(parsed.opt.Magic, ROM_OPTIONAL_HEADER_MAGIC);
  assert.strictEqual(parsed.opt.is32, false);
  assert.strictEqual(parsed.opt.isPlus, false);
  assert.strictEqual(parsed.opt.ImageBase, 0n);
  assert.strictEqual(parsed.opt.NumberOfRvaAndSizes, 0);
  assert.deepStrictEqual(parsed.dataDirs, []);
  assert.ok(parsed.warnings?.some(warning => /rom|pe32|pe32\+/i.test(warning)));
});
