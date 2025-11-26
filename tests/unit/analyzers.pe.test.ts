import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../dist/analyzers/pe/index.js";

// Mock the File object for Node.js environment
class MockFile {
  buffer: Uint8Array;
  name: string;
  size: number;

  constructor(buffer: Uint8Array, name: string) {
    this.buffer = buffer;
    this.name = name;
    this.size = buffer.length;
  }

  slice(start: number, end?: number): MockFile {
    return new MockFile(this.buffer.slice(start, end), this.name);
  }

  async arrayBuffer(): Promise<ArrayBuffer> {
    return this.buffer.slice().buffer;
  }
}

/**
 * Creates a byte array for a minimal valid PE32 header.
 * This is useful for testing the PE parser without requiring an actual file.
 * The structure includes a DOS header, PE signature, COFF header, and a minimal Optional header.
 * @returns {Uint8Array}
 */
function createTinyPEHeader() {
  const peSignatureOffset = 64;
  const coffHeaderSize = 20;
  const optionalHeaderSize = 224;
  const totalHeaderSize = peSignatureOffset + 4 + coffHeaderSize + optionalHeaderSize;

  const buffer = new ArrayBuffer(totalHeaderSize);
  const view = new DataView(buffer);

  // DOS Header
  view.setUint16(0, 0x5a4d, true); // 'MZ'
  view.setUint32(0x3c, peSignatureOffset, true); // e_lfanew

  // PE Signature
  view.setUint32(peSignatureOffset, 0x00004550, true); // 'PE\0\0'

  // COFF File Header
  const coffHeaderOffset = peSignatureOffset + 4;
  view.setUint16(coffHeaderOffset, 0x014c, true); // Machine: x86
  view.setUint16(coffHeaderOffset + 2, 0, true); // NumberOfSections
  view.setUint32(coffHeaderOffset + 4, 0, true); // TimeDateStamp
  view.setUint32(coffHeaderOffset + 8, 0, true); // PointerToSymbolTable
  view.setUint32(coffHeaderOffset + 12, 0, true); // NumberOfSymbols
  view.setUint16(coffHeaderOffset + 16, optionalHeaderSize, true); // SizeOfOptionalHeader
  view.setUint16(coffHeaderOffset + 18, 0x0102, true); // Characteristics

  // Optional Header (PE32)
  const optionalHeaderOffset = coffHeaderOffset + coffHeaderSize;
  view.setUint16(optionalHeaderOffset, 0x10b, true); // Magic: PE32
  view.setUint32(optionalHeaderOffset + 28, 0x00400000, true); // ImageBase
  view.setUint32(optionalHeaderOffset + 56, totalHeaderSize, true); // SizeOfHeaders

  return new Uint8Array(buffer);
}

test("parsePe correctly parses a minimal PE header", async () => {
  const peBytes = createTinyPEHeader();
  const mockFile = new MockFile(peBytes, "minimal.exe");

  const result = await parsePe(mockFile);

  assert.ok(result, "parsePe should return a result for a valid PE file");
  assert.strictEqual(result.dos.e_lfanew, 64, "DOS header should point to the PE signature");
  assert.strictEqual(result.coff.Machine, 0x014c, "COFF header Machine should be x86");
  assert.strictEqual(result.coff.NumberOfSections, 0, "COFF header should report 0 sections");
  assert.ok(result.opt, "Optional header should be parsed");
  assert.strictEqual(result.opt.Magic, 0x10b, "Optional header magic should be PE32");
  assert.strictEqual(result.opt.ImageBase, 0x00400000, "Optional header ImageBase should be parsed correctly");
});

test("parsePe returns null for a non-PE file", async () => {
  const notPeBytes = new Uint8Array(256).fill(0xff);
  const mockFile = new MockFile(notPeBytes, "not-a-pe.bin");

  const result = await parsePe(mockFile);

  assert.strictEqual(result, null, "parsePe should return null for a file that is not a PE");
});

function createPeWithSectionAndIat() {
  const peHeaderOffset = 0x80;
  const coffHeaderSize = 20;
  const optionalHeaderSize = 0xe0;
  const numberOfSections = 1;
  const fileAlignment = 0x200;
  const sectionAlignment = 0x1000;
  const sectionVirtualAddress = 0x1000;
  const sectionVirtualSize = 0x200;
  const sizeOfRawData = fileAlignment;
  const pointerToRawData = fileAlignment;
  const addressOfEntryPoint = 0x1100;
  const iatRva = 0x1100;
  const iatSize = 0x40;
  const sizeOfImage = 0x2000;
  const overlaySize = 0x20;
  const fileSize = pointerToRawData + sizeOfRawData + overlaySize;

  const buffer = new ArrayBuffer(fileSize);
  const view = new DataView(buffer);

  view.setUint16(0x00, 0x5a4d, true);
  view.setUint32(0x3c, peHeaderOffset, true);

  const peSignatureOffset = peHeaderOffset;
  view.setUint32(peSignatureOffset, 0x00004550, true);

  const coffOffset = peSignatureOffset + 4;
  view.setUint16(coffOffset, 0x014c, true);
  view.setUint16(coffOffset + 2, numberOfSections, true);
  view.setUint32(coffOffset + 4, 0x65c0e6a0, true);
  view.setUint32(coffOffset + 8, 0, true);
  view.setUint32(coffOffset + 12, 0, true);
  view.setUint16(coffOffset + 16, optionalHeaderSize, true);
  view.setUint16(coffOffset + 18, 0x0002, true);

  const optionalOffset = coffOffset + coffHeaderSize;
  let optPos = optionalOffset;
  view.setUint16(optPos, 0x10b, true); optPos += 2;
  view.setUint8(optPos, 14); optPos += 1;
  view.setUint8(optPos, 0); optPos += 1;
  view.setUint32(optPos, sizeOfRawData, true); optPos += 4;
  view.setUint32(optPos, sizeOfRawData, true); optPos += 4;
  view.setUint32(optPos, 0, true); optPos += 4;
  view.setUint32(optPos, addressOfEntryPoint, true); optPos += 4;
  view.setUint32(optPos, sectionVirtualAddress, true); optPos += 4;
  view.setUint32(optPos, sectionVirtualAddress, true); optPos += 4;
  view.setUint32(optPos, 0x00400000, true); optPos += 4;
  view.setUint32(optPos, sectionAlignment, true); optPos += 4;
  view.setUint32(optPos, fileAlignment, true); optPos += 4;
  view.setUint16(optPos, 6, true);
  view.setUint16(optPos + 2, 0, true);
  optPos += 4;
  view.setUint16(optPos, 1, true);
  view.setUint16(optPos + 2, 0, true);
  optPos += 4;
  view.setUint16(optPos, 5, true);
  view.setUint16(optPos + 2, 1, true);
  optPos += 4;
  view.setUint32(optPos, 0, true); optPos += 4;
  view.setUint32(optPos, sizeOfImage, true); optPos += 4;
  view.setUint32(optPos, fileAlignment, true); optPos += 4;
  view.setUint32(optPos, 0, true); optPos += 4;
  view.setUint16(optPos, 2, true); optPos += 2;
  view.setUint16(optPos, 0, true); optPos += 2;
  view.setUint32(optPos, 0x100000, true); optPos += 4;
  view.setUint32(optPos, 0x1000, true); optPos += 4;
  view.setUint32(optPos, 0x100000, true); optPos += 4;
  view.setUint32(optPos, 0x1000, true); optPos += 4;
  view.setUint32(optPos, 0, true); optPos += 4;
  view.setUint32(optPos, 16, true); optPos += 4;

  const dataDirectoryOffset = optPos + 12 * 8;
  view.setUint32(dataDirectoryOffset, iatRva, true);
  view.setUint32(dataDirectoryOffset + 4, iatSize, true);

  const sectionHeaderOffset = optionalOffset + optionalHeaderSize;
  const nameBytes = [0x2e, 0x74, 0x65, 0x78, 0x74];
  for (let index = 0; index < nameBytes.length; index += 1) {
    view.setUint8(sectionHeaderOffset + index, nameBytes[index]);
  }
  view.setUint32(sectionHeaderOffset + 8, sectionVirtualSize, true);
  view.setUint32(sectionHeaderOffset + 12, sectionVirtualAddress, true);
  view.setUint32(sectionHeaderOffset + 16, sizeOfRawData, true);
  view.setUint32(sectionHeaderOffset + 20, pointerToRawData, true);
  view.setUint32(sectionHeaderOffset + 36, 0x60000020, true);

  return new Uint8Array(buffer);
}

test("parsePe returns coverage and mapping for PE32 with one section and IAT", async () => {
  const peBytes = createPeWithSectionAndIat();
  const mockFile = new MockFile(peBytes, "section.exe");

  const result = await parsePe(mockFile);
  assert.ok(result, "parsePe should return a parsed object");

  assert.deepStrictEqual(result.entrySection, { name: ".text", index: 0 }, "Entry point should map to .text");
  assert.strictEqual(result.rvaToOff(0x1100), 0x300, "IAT RVA should resolve to file offset");
  assert.ok(result.iat, "IAT data directory should be recognized");
  assert.strictEqual(result.iat.rva, 0x1100);
  assert.strictEqual(result.iat.size, 0x40);

  const iatCoverage = result.coverage.find(region => region.label === "IAT");
  assert.ok(iatCoverage, "Coverage should include IAT region");
  assert.strictEqual(iatCoverage.off, 0x300);
  assert.strictEqual(iatCoverage.size, 0x40);

  const overlayCoverage = result.coverage.find(region => region.label.startsWith("Overlay"));
  assert.ok(overlayCoverage, "Overlay region should be tracked");
  assert.strictEqual(overlayCoverage.off, 0x400);
  assert.strictEqual(overlayCoverage.size, 0x20);

  assert.strictEqual(result.overlaySize, 0x20);
  assert.strictEqual(result.imageEnd, 0x2000);
  assert.strictEqual(result.imageSizeMismatch, false);
  assert.strictEqual(result.hasCert, false);
});
