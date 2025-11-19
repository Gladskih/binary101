import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";

// Mock the File object for Node.js environment
class MockFile {
  constructor(buffer, name) {
    this.buffer = buffer;
    this.name = name;
    this.size = buffer.length;
  }

  slice(start, end) {
    return new MockFile(this.buffer.slice(start, end));
  }

  async arrayBuffer() {
    return this.buffer.buffer;
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
