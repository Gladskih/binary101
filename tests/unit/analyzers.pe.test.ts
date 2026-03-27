import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";
import { createPeWithSectionAndIat as createSamplePeWithSectionAndIat } from "../fixtures/sample-files-pe.js";
import { MockFile } from "../helpers/mock-file.js";

const DOS_SIGNATURE = 0x5a4d;
const PE_SIGNATURE = 0x00004550;
const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
// Microsoft PE/COFF: IMAGE_OPTIONAL_HEADER32.DataDirectory begins 96 bytes into the optional header.
const PE32_DATA_DIRECTORIES_OFFSET = 0x60;
// Microsoft PE format: data-directory indices for SECURITY, DEBUG, and IAT.
const IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
const IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
const IMAGE_DIRECTORY_ENTRY_IAT = 12;

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
  view.setUint16(0, DOS_SIGNATURE, true); // 'MZ'
  view.setUint32(0x3c, peSignatureOffset, true); // e_lfanew

  // PE Signature
  view.setUint32(peSignatureOffset, PE_SIGNATURE, true); // 'PE\0\0'

  // COFF File Header
  const coffHeaderOffset = peSignatureOffset + 4;
  view.setUint16(coffHeaderOffset, IMAGE_FILE_MACHINE_I386, true); // Machine: x86
  view.setUint16(coffHeaderOffset + 2, 0, true); // NumberOfSections
  view.setUint32(coffHeaderOffset + 4, 0, true); // TimeDateStamp
  view.setUint32(coffHeaderOffset + 8, 0, true); // PointerToSymbolTable
  view.setUint32(coffHeaderOffset + 12, 0, true); // NumberOfSymbols
  view.setUint16(coffHeaderOffset + 16, optionalHeaderSize, true); // SizeOfOptionalHeader
  view.setUint16(coffHeaderOffset + 18, IMAGE_FILE_EXECUTABLE_IMAGE, true); // Characteristics

  // Optional Header (PE32)
  const optionalHeaderOffset = coffHeaderOffset + coffHeaderSize;
  view.setUint16(optionalHeaderOffset, IMAGE_NT_OPTIONAL_HDR32_MAGIC, true); // Magic: PE32
  view.setUint32(optionalHeaderOffset + 28, 0x00400000, true); // ImageBase
  view.setUint32(optionalHeaderOffset + 56, totalHeaderSize, true); // SizeOfHeaders

  return new Uint8Array(buffer);
}

function createHeadersOnlyPeWithAlignedImageSize() {
  const peSignatureOffset = 64;
  const coffHeaderSize = 20;
  const optionalHeaderSize = 224;
  const fileAlignment = 0x200;
  const sectionAlignment = 0x1000;
  const sizeOfHeaders = fileAlignment;
  const sizeOfImage = sectionAlignment;

  const buffer = new ArrayBuffer(sizeOfHeaders);
  const view = new DataView(buffer);

  view.setUint16(0, DOS_SIGNATURE, true); // 'MZ'
  view.setUint32(0x3c, peSignatureOffset, true); // e_lfanew
  view.setUint32(peSignatureOffset, PE_SIGNATURE, true); // 'PE\0\0'

  const coffHeaderOffset = peSignatureOffset + 4;
  view.setUint16(coffHeaderOffset, IMAGE_FILE_MACHINE_I386, true); // Machine: x86
  view.setUint16(coffHeaderOffset + 2, 0, true); // NumberOfSections
  view.setUint16(coffHeaderOffset + 16, optionalHeaderSize, true);
  view.setUint16(coffHeaderOffset + 18, IMAGE_FILE_EXECUTABLE_IMAGE, true);

  const optionalHeaderOffset = coffHeaderOffset + coffHeaderSize;
  view.setUint16(optionalHeaderOffset, IMAGE_NT_OPTIONAL_HDR32_MAGIC, true); // Magic: PE32
  view.setUint32(optionalHeaderOffset + 28, 0x00400000, true); // ImageBase
  view.setUint32(optionalHeaderOffset + 32, sectionAlignment, true);
  view.setUint32(optionalHeaderOffset + 36, fileAlignment, true);
  view.setUint32(optionalHeaderOffset + 56, sizeOfImage, true);
  view.setUint32(optionalHeaderOffset + 60, sizeOfHeaders, true);

  return new Uint8Array(buffer);
}

void test("parsePe correctly parses a minimal PE header", async () => {
  const peBytes = createTinyPEHeader();
  const mockFile = new MockFile(peBytes, "minimal.exe");

  const result = await parsePe(mockFile);

  assert.ok(result, "parsePe should return a result for a valid PE file");
  assert.strictEqual(result.dos.e_lfanew, 64, "DOS header should point to the PE signature");
  assert.strictEqual(result.coff.Machine, IMAGE_FILE_MACHINE_I386, "COFF header Machine should be x86");
  assert.strictEqual(result.coff.NumberOfSections, 0, "COFF header should report 0 sections");
  assert.ok(result.opt, "Optional header should be parsed");
  assert.strictEqual(result.opt.Magic, IMAGE_NT_OPTIONAL_HDR32_MAGIC, "Optional header magic should be PE32");
  assert.strictEqual(result.opt.ImageBase, 0x00400000n, "Optional header ImageBase should be parsed correctly");
});

void test("parsePe does not treat a headers-only image as overlay data", async () => {
  const peBytes = createTinyPEHeader();
  const result = await parsePe(new MockFile(peBytes, "headers-only.exe"));

  assert.ok(result, "parsePe should return a parsed object for a valid PE file");
  assert.strictEqual(result.overlaySize, 0, "Header bytes are not overlay when the image has no sections");
});

void test("parsePe includes the aligned headers in imageEnd for sectionless images", async () => {
  const peBytes = createHeadersOnlyPeWithAlignedImageSize();

  const result = await parsePe(new MockFile(peBytes, "headers-sizeofimage.exe"));

  assert.ok(result, "parsePe should return a parsed object for a valid PE file");
  assert.strictEqual(
    result.imageEnd,
    0x1000,
    "SizeOfImage includes all headers rounded to SectionAlignment even when the image has no sections"
  );
  assert.strictEqual(result.overlaySize, 0);
  assert.strictEqual(result.imageSizeMismatch, false);
});

void test("parsePe maps RVAs inside SizeOfHeaders back to file offsets for sectionless images", async () => {
  const peBytes = createHeadersOnlyPeWithAlignedImageSize();
  const view = new DataView(peBytes.buffer, peBytes.byteOffset, peBytes.byteLength);
  const optionalHeaderOffset = 64 + 4 + 20; // e_lfanew + "PE\0\0" + IMAGE_FILE_HEADER
  // Microsoft PE format and ImageRvaToVa:
  // headers are part of the loaded image, so an RVA inside SizeOfHeaders should resolve inside the file headers.
  view.setUint32(optionalHeaderOffset + 16, 0x80, true); // AddressOfEntryPoint inside SizeOfHeaders (= 0x200)

  const result = await parsePe(new MockFile(peBytes, "header-rva.exe"));

  assert.ok(result, "parsePe should return a parsed object for a valid PE file");
  assert.strictEqual(result.rvaToOff(0x80), 0x80);
});

void test("parsePe returns null for a non-PE file", async () => {
  const notPeBytes = new Uint8Array(256).fill(0xff);
  const mockFile = new MockFile(notPeBytes, "not-a-pe.bin");

  const result = await parsePe(mockFile);

  assert.strictEqual(result, null, "parsePe should return null for a file that is not a PE");
});

const getPeView = (bytes: Uint8Array): DataView => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

const getDataDirectoryEntryOffset = (bytes: Uint8Array, index: number): number => {
  const view = getPeView(bytes);
  const peHeaderOffset = view.getUint32(0x3c, true);
  return peHeaderOffset + 4 + 20 + PE32_DATA_DIRECTORIES_OFFSET + index * 8;
};

function createPeWithSectionAndIat(iatRvaOverride = 0x1100) {
  const bytes = createSamplePeWithSectionAndIat();
  if (iatRvaOverride === 0x1100) return bytes;
  const view = getPeView(bytes);
  view.setUint32(getDataDirectoryEntryOffset(bytes, IMAGE_DIRECTORY_ENTRY_IAT), iatRvaOverride, true);
  return bytes;
}

void test("parsePe returns mapping and overlay info for PE32 with one section and IAT", async () => {
  const peBytes = createPeWithSectionAndIat();
  const mockFile = new MockFile(peBytes, "section.exe");

  const result = await parsePe(mockFile);
  assert.ok(result, "parsePe should return a parsed object");

  assert.deepStrictEqual(result.entrySection, { name: ".text", index: 0 }, "Entry point should map to .text");
  assert.strictEqual(result.rvaToOff(0x1100), 0x300, "IAT RVA should resolve to file offset");
  assert.ok(result.iat, "IAT data directory should be recognized");
  assert.strictEqual(result.iat.rva, 0x1100);
  assert.strictEqual(result.iat.size, 0x40);

  assert.strictEqual(result.overlaySize, 0x20);
  assert.strictEqual(result.imageEnd, 0x2000);
  assert.strictEqual(result.imageSizeMismatch, false);
  assert.strictEqual(result.hasCert, false);
});

void test("parsePe preserves unmapped IAT directories with warnings", async () => {
  const peBytes = createPeWithSectionAndIat(0x3000);
  const mockFile = new MockFile(peBytes, "unmapped-iat.exe");

  const result = await parsePe(mockFile);
  assert.ok(result, "parsePe should return a parsed object");
  assert.deepStrictEqual(result.iat, {
    rva: 0x3000,
    size: 0x40,
    warnings: ["IAT directory RVA could not be mapped to a file offset."]
  });
});

void test("parsePe attaches Authenticode verification when security directory exists", async () => {
  const peBytes = createPeWithSectionAndIat();
  const view = getPeView(peBytes);
  const securityEntryOffset = getDataDirectoryEntryOffset(peBytes, IMAGE_DIRECTORY_ENTRY_SECURITY);
  const certOff = peBytes.length - 0x20;
  const certSize = 0x20;

  view.setUint32(securityEntryOffset, certOff, true);
  view.setUint32(securityEntryOffset + 4, certSize, true);
  view.setUint32(certOff, 12, true);
  view.setUint16(certOff + 4, 0x0200, true);
  view.setUint16(certOff + 6, 0x0002, true);
  peBytes[certOff + 8] = 0x30;

  const result = await parsePe(new MockFile(peBytes, "signed.exe"));
  assert.ok(result);
  assert.ok(result.security);
  const cert = result.security.certs[0];
  assert.ok(cert?.authenticode?.verification);
  assert.ok(cert.authenticode.verification?.warnings?.length);
});

void test("parsePe omits the generic SECURITY tail warning when parsed debug raw data explains the file tail", async () => {
  const baseBytes = createPeWithSectionAndIat();
  const certOff = baseBytes.length - 0x20;
  // RSDS record uses a 24-byte fixed header plus a NUL-terminated path.
  const debugPayloadSize = 26;
  const bytes = new Uint8Array(certOff + 8 + debugPayloadSize);
  bytes.set(baseBytes);
  const view = getPeView(bytes);
  const securityEntryOffset = getDataDirectoryEntryOffset(bytes, IMAGE_DIRECTORY_ENTRY_SECURITY);
  const debugEntryOffset = getDataDirectoryEntryOffset(bytes, IMAGE_DIRECTORY_ENTRY_DEBUG);
  const debugDirectoryRva = 0x1000;
  const debugDirectoryOff = 0x200;
  const debugPayloadOff = certOff + 8;
  const rsdsSignature = 0x53445352;

  // Microsoft PE format: Certificate Table is data-directory entry 4 and stores a file pointer.
  view.setUint32(securityEntryOffset, certOff, true);
  view.setUint32(securityEntryOffset + 4, 8, true);
  view.setUint32(certOff, 8, true);
  view.setUint16(certOff + 4, 0x0200, true);
  view.setUint16(certOff + 6, 0x0001, true);

  // Microsoft PE format: DEBUG directory entry points to raw debug data via PointerToRawData.
  view.setUint32(debugEntryOffset, debugDirectoryRva, true);
  view.setUint32(debugEntryOffset + 4, 28, true);
  view.setUint32(debugDirectoryOff + 12, 2, true);
  view.setUint32(debugDirectoryOff + 16, debugPayloadSize, true);
  view.setUint32(debugDirectoryOff + 20, 0, true);
  view.setUint32(debugDirectoryOff + 24, debugPayloadOff, true);

  view.setUint32(debugPayloadOff + 0, rsdsSignature, true);
  view.setUint32(debugPayloadOff + 20, 1, true);
  bytes[debugPayloadOff + 24] = 0x61; // "a"
  bytes[debugPayloadOff + 25] = 0x00;

  const result = await parsePe(new MockFile(bytes, "cert-followed-by-debug.exe"));

  assert.ok(result);
  assert.ok(result.debug?.entry);
  assert.ok(!result.security?.warnings?.some(warning => /bytes after the declared table/i.test(warning)));
});

void test("parsePe keeps the generic SECURITY tail warning when no proven file span explains the tail", async () => {
  const baseBytes = createPeWithSectionAndIat();
  const trailingByteCount = 8;
  const certOff = baseBytes.length - (8 + trailingByteCount);
  const bytes = new Uint8Array(baseBytes.length);
  bytes.set(baseBytes);
  const view = getPeView(bytes);
  const securityEntryOffset = getDataDirectoryEntryOffset(bytes, IMAGE_DIRECTORY_ENTRY_SECURITY);

  // Microsoft PE format: the Certificate Table directory entry stores a file pointer and byte size.
  view.setUint32(securityEntryOffset, certOff, true);
  view.setUint32(securityEntryOffset + 4, 8, true);
  view.setUint32(certOff, 8, true);
  view.setUint16(certOff + 4, 0x0200, true);
  view.setUint16(certOff + 6, 0x0001, true);

  const result = await parsePe(new MockFile(bytes, "cert-with-unexplained-tail.exe"));

  assert.ok(result);
  assert.ok(result.security?.warnings?.some(warning => /bytes after the declared table/i.test(warning)));
});
