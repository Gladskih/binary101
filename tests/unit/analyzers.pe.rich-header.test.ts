import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";
import { parseRichHeaderFromDosStub } from "../../analyzers/pe/rich-header.js";
import { MockFile } from "../helpers/mock-file.js";

const writeAscii = (view: DataView, offset: number, text: string): void => {
  for (let index = 0; index < text.length; index += 1) {
    view.setUint8(offset + index, text.charCodeAt(index));
  }
};

const createPeWithRichHeader = (): { bytes: Uint8Array; xorKey: number } => {
  const peHeaderOffset = 0x200;
  const coffHeaderSize = 20;
  const optionalHeaderSize = 0xe0;
  const totalSize = peHeaderOffset + 4 + coffHeaderSize + optionalHeaderSize;

  const buffer = new ArrayBuffer(totalSize);
  const view = new DataView(buffer);

  view.setUint16(0, 0x5a4d, true); // "MZ"
  view.setUint32(0x3c, peHeaderOffset, true); // e_lfanew

  const xorKey = 0x12345678;
  const stubRichStart = 0x80;
  let cursor = stubRichStart;

  const dword = (value: number): void => {
    view.setUint32(cursor, (value ^ xorKey) >>> 0, true);
    cursor += 4;
  };

  dword(0x536e6144); // "DanS"
  dword(0); // checksum (best-effort field)
  dword(0);
  dword(0);

  const entry1 = ((0x1111 << 16) | 0x2222) >>> 0;
  const entry2 = ((0x3333 << 16) | 0x4444) >>> 0;
  dword(entry1);
  dword(5);
  dword(entry2);
  dword(12);

  writeAscii(view, cursor, "Rich");
  view.setUint32(cursor + 4, xorKey >>> 0, true);

  view.setUint32(peHeaderOffset, 0x00004550, true); // "PE\0\0"

  const coffOffset = peHeaderOffset + 4;
  view.setUint16(coffOffset, 0x014c, true); // Machine (x86)
  view.setUint16(coffOffset + 2, 0, true); // NumberOfSections
  view.setUint32(coffOffset + 4, 0, true); // TimeDateStamp
  view.setUint32(coffOffset + 8, 0, true); // PointerToSymbolTable
  view.setUint32(coffOffset + 12, 0, true); // NumberOfSymbols
  view.setUint16(coffOffset + 16, optionalHeaderSize, true); // SizeOfOptionalHeader
  view.setUint16(coffOffset + 18, 0x0102, true); // Characteristics

  const optionalHeaderOffset = coffOffset + coffHeaderSize;
  view.setUint16(optionalHeaderOffset, 0x10b, true); // Magic (PE32)
  view.setUint32(optionalHeaderOffset + 28, 0x00400000, true); // ImageBase
  view.setUint32(optionalHeaderOffset + 32, 0x1000, true); // SectionAlignment
  view.setUint32(optionalHeaderOffset + 36, 0x200, true); // FileAlignment

  return { bytes: new Uint8Array(buffer), xorKey };
};

void test("parsePe extracts Rich header entries from the DOS stub", async () => {
  const { bytes, xorKey } = createPeWithRichHeader();
  const result = await parsePe(new MockFile(bytes, "rich.exe"));

  assert.ok(result, "Expected parsePe to return a result");
  assert.ok(result.dos.rich, "Expected Rich header to be detected");
  assert.strictEqual(result.dos.rich.xorKey, xorKey);
  assert.deepStrictEqual(
    result.dos.rich.entries,
    [
      { productId: 0x1111, buildNumber: 0x2222, count: 5 },
      { productId: 0x3333, buildNumber: 0x4444, count: 12 }
    ]
  );
});

void test("parseRichHeaderFromDosStub returns null when Rich signature is missing", () => {
  const stub = new Uint8Array(256);
  assert.strictEqual(parseRichHeaderFromDosStub(stub), null);
});

void test("parseRichHeaderFromDosStub ignores plain-text Rich without a matching DanS marker", () => {
  const stub = new Uint8Array(64);
  const view = new DataView(stub.buffer);
  stub.set([0x52, 0x69, 0x63, 0x68], 16); // "Rich"
  view.setUint32(20, 0x12345678, true); // XOR key
  assert.strictEqual(parseRichHeaderFromDosStub(stub), null);
});

void test("parseRichHeaderFromDosStub reports warnings for truncated DanS header and odd entry dwords", () => {
  const xorKey = 0x89abcdef;
  const stub = new Uint8Array(64);
  const view = new DataView(stub.buffer);

  const writeEncoded = (off: number, value: number): void => {
    view.setUint32(off, (value ^ xorKey) >>> 0, true);
  };

  // Truncated DanS header: only DanS + checksum, then Rich marker.
  writeEncoded(0, 0x536e6144); // DanS
  writeEncoded(4, 0x11223344); // checksum
  stub.set([0x52, 0x69, 0x63, 0x68], 8); // Rich
  view.setUint32(12, xorKey >>> 0, true);

  const truncated = parseRichHeaderFromDosStub(stub);
  assert.ok(truncated);
  assert.ok(truncated.warnings?.some(w => w.includes("too small")), "Expected truncation warning");

  // Full header + one entry + one extra dword (odd count).
  stub.fill(0);
  writeEncoded(0, 0x536e6144);
  writeEncoded(4, 0);
  writeEncoded(8, 0);
  writeEncoded(12, 0);
  writeEncoded(16, ((0x0102 << 16) | 0x0304) >>> 0);
  writeEncoded(20, 7);
  writeEncoded(24, 0xdeadbeef);
  stub.set([0x52, 0x69, 0x63, 0x68], 28);
  view.setUint32(32, xorKey >>> 0, true);

  const odd = parseRichHeaderFromDosStub(stub);
  assert.ok(odd);
  assert.deepStrictEqual(odd.entries, [{ productId: 0x0102, buildNumber: 0x0304, count: 7 }]);
  assert.ok(odd.warnings?.some(w => w.includes("odd")), "Expected odd-dword warning");
});
