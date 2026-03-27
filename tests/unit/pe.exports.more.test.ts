"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExportDirectory } from "../../analyzers/pe/exports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const IMAGE_EXPORT_DIRECTORY_SIZE = 40; // IMAGE_EXPORT_DIRECTORY
const cStringSize = (text: string): number => encoder.encode(`${text}\0`).length;
const createExportLayout = (
  start = IMAGE_EXPORT_DIRECTORY_SIZE
): { reserve: (size: number) => number; size: () => number } => {
  let next = start;
  return {
    reserve: (size: number): number => {
      const offset = next;
      next += size;
      return offset;
    },
    size: (): number => next
  };
};
const parseExportFixture = (
  bytes: Uint8Array | File,
  directory: { rva: number; size: number },
  rvaToOff: (rva: number) => number | null = value => value
) => parseExportDirectory(
  bytes instanceof Uint8Array ? new MockFile(bytes) : bytes,
  [{ name: "EXPORT", ...directory }],
  rvaToOff
);

void test("parseExportDirectory warns when the DLL name stops mapping before its null terminator", async () => {
  const dllName = "AB";
  const rvaLayout = createExportLayout();
  const fileLayout = createExportLayout(0);
  const directoryRva = rvaLayout.reserve(IMAGE_EXPORT_DIRECTORY_SIZE);
  const dllNameRva = rvaLayout.reserve(cStringSize(dllName));
  const eatRva = rvaLayout.reserve(Uint32Array.BYTES_PER_ELEMENT);
  const directoryOffset = fileLayout.reserve(IMAGE_EXPORT_DIRECTORY_SIZE);
  const eatOffset = fileLayout.reserve(Uint32Array.BYTES_PER_ELEMENT);
  const dllNameOffset = fileLayout.reserve(cStringSize(dllName));
  const bytes = new Uint8Array(fileLayout.size()).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(directoryOffset + 12, dllNameRva, true);
  dv.setUint32(directoryOffset + 16, 1, true);
  dv.setUint32(directoryOffset + 20, 1, true);
  dv.setUint32(directoryOffset + 28, eatRva, true);
  dv.setUint32(eatOffset, rvaLayout.reserve(Uint32Array.BYTES_PER_ELEMENT), true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameOffset));

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= directoryRva && rva < directoryRva + IMAGE_EXPORT_DIRECTORY_SIZE) {
      return directoryOffset + (rva - directoryRva);
    }
    if (rva >= eatRva && rva < eatRva + Uint32Array.BYTES_PER_ELEMENT) {
      return eatOffset + (rva - eatRva);
    }
    if (rva === dllNameRva) return dllNameOffset;
    if (rva === dllNameRva + 1) return dllNameOffset + 1;
    return null;
  };

  const result = expectDefined(await parseExportFixture(
    bytes,
    { rva: directoryRva, size: IMAGE_EXPORT_DIRECTORY_SIZE },
    sparseRvaToOff
  ));

  assert.equal(result.dllName, dllName);
  assert.ok(result.issues.some(issue => /truncated|string/i.test(issue)));
});

void test("parseExportDirectory warns when an exported name stops mapping before its null terminator", async () => {
  const dllName = "demo.dll";
  const exportedName = "AB";
  const rvaLayout = createExportLayout();
  const fileLayout = createExportLayout(0);
  const directoryRva = rvaLayout.reserve(IMAGE_EXPORT_DIRECTORY_SIZE);
  const dllNameRva = rvaLayout.reserve(cStringSize(dllName));
  const eatRva = rvaLayout.reserve(Uint32Array.BYTES_PER_ELEMENT);
  const nameTableRva = rvaLayout.reserve(Uint32Array.BYTES_PER_ELEMENT);
  const ordinalTableRva = rvaLayout.reserve(Uint16Array.BYTES_PER_ELEMENT);
  const exportedNameRva = rvaLayout.reserve(cStringSize(exportedName));
  const directoryOffset = fileLayout.reserve(IMAGE_EXPORT_DIRECTORY_SIZE);
  const eatOffset = fileLayout.reserve(Uint32Array.BYTES_PER_ELEMENT);
  const nameTableOffset = fileLayout.reserve(Uint32Array.BYTES_PER_ELEMENT);
  const ordinalTableOffset = fileLayout.reserve(Uint16Array.BYTES_PER_ELEMENT);
  const dllNameOffset = fileLayout.reserve(cStringSize(dllName));
  const exportedNameOffset = fileLayout.reserve(cStringSize(exportedName));
  const bytes = new Uint8Array(fileLayout.size()).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(directoryOffset + 12, dllNameRva, true);
  dv.setUint32(directoryOffset + 16, 1, true);
  dv.setUint32(directoryOffset + 20, 1, true);
  dv.setUint32(directoryOffset + 24, 1, true);
  dv.setUint32(directoryOffset + 28, eatRva, true);
  dv.setUint32(directoryOffset + 32, nameTableRva, true);
  dv.setUint32(directoryOffset + 36, ordinalTableRva, true);
  dv.setUint32(eatOffset, rvaLayout.reserve(Uint32Array.BYTES_PER_ELEMENT), true);
  dv.setUint32(nameTableOffset, exportedNameRva, true);
  dv.setUint16(ordinalTableOffset, 0, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameOffset));
  encoder.encodeInto(`${exportedName}\0`, new Uint8Array(bytes.buffer, exportedNameOffset));

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= directoryRva && rva < directoryRva + IMAGE_EXPORT_DIRECTORY_SIZE) {
      return directoryOffset + (rva - directoryRva);
    }
    if (rva >= eatRva && rva < eatRva + Uint32Array.BYTES_PER_ELEMENT) {
      return eatOffset + (rva - eatRva);
    }
    if (rva >= nameTableRva && rva < nameTableRva + Uint32Array.BYTES_PER_ELEMENT) {
      return nameTableOffset + (rva - nameTableRva);
    }
    if (rva >= ordinalTableRva && rva < ordinalTableRva + Uint16Array.BYTES_PER_ELEMENT) {
      return ordinalTableOffset + (rva - ordinalTableRva);
    }
    if (rva >= dllNameRva && rva < dllNameRva + cStringSize(dllName)) {
      return dllNameOffset + (rva - dllNameRva);
    }
    if (rva === exportedNameRva || rva === exportedNameRva + 1) {
      return exportedNameOffset + (rva - exportedNameRva);
    }
    return null;
  };

  const result = expectDefined(await parseExportFixture(
    bytes,
    { rva: directoryRva, size: IMAGE_EXPORT_DIRECTORY_SIZE },
    sparseRvaToOff
  ));

  assert.equal(result.entries[0]?.name, exportedName);
  assert.ok(result.issues.some(issue => /truncated|string/i.test(issue)));
});

void test("parseExportDirectory reports out-of-range entries in the export ordinal table", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x20;
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 1, true);
  dv.setUint32(directoryRva + 24, 1, true);
  dv.setUint32(directoryRva + 28, 0x80, true);
  dv.setUint32(directoryRva + 32, 0xa0, true);
  dv.setUint32(directoryRva + 36, 0xc0, true);
  dv.setUint32(0x80, 0x1000, true);
  dv.setUint32(0xa0, 0xe0, true);
  dv.setUint16(0xc0, 5, true);
  encoder.encodeInto("BadOrdinal\0", new Uint8Array(bytes.buffer, 0xe0));
  const result = expectDefined(await parseExportFixture(bytes, { rva: directoryRva, size: 64 }));
  assert.ok(result.issues.some(issue => /ordinal/i.test(issue)));
});

void test("parseExportDirectory reports missing export name and ordinal tables when NumberOfNames is non-zero", async () => {
  const directoryRva = IMAGE_EXPORT_DIRECTORY_SIZE;
  const eatRva = directoryRva + IMAGE_EXPORT_DIRECTORY_SIZE;
  const bytes = new Uint8Array(eatRva + Uint32Array.BYTES_PER_ELEMENT).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 1, true);
  dv.setUint32(directoryRva + 24, 1, true);
  dv.setUint32(directoryRva + 28, eatRva, true);
  dv.setUint32(eatRva, 0x1000, true);
  const result = expectDefined(await parseExportFixture(
    bytes,
    { rva: directoryRva, size: IMAGE_EXPORT_DIRECTORY_SIZE }
  ));
  assert.equal(result.entries.length, 1);
  assert.ok(result.issues.some(issue => /name pointer|ordinal table/i.test(issue)));
});

void test("parseExportDirectory reports truncated export strings that run to EOF without a terminator", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x20;
  const eatRva = 0x60;
  const dllNameRva = 0x7f;
  dv.setUint32(directoryRva + 12, dllNameRva, true);
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 1, true);
  dv.setUint32(directoryRva + 28, eatRva, true);
  dv.setUint32(eatRva, 0x1000, true);
  bytes[dllNameRva] = 0x41;
  const result = expectDefined(await parseExportFixture(bytes, { rva: directoryRva, size: 0x60 }));
  assert.equal(result.dllName, "A");
  assert.ok(result.issues.some(issue => /truncated|string/i.test(issue)));
});

void test("parseExportDirectory keeps the packed version field unsigned", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x20;
  const eatRva = 0x60;
  dv.setUint16(directoryRva + 8, 0xffff, true);
  dv.setUint16(directoryRva + 10, 0x0001, true);
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 1, true);
  dv.setUint32(directoryRva + 28, eatRva, true);
  dv.setUint32(eatRva, 0x1000, true);
  const result = expectDefined(await parseExportFixture(bytes, { rva: directoryRva, size: 40 }));
  // MajorVersion and MinorVersion are unsigned 16-bit fields in IMAGE_EXPORT_DIRECTORY.
  assert.equal(result.version, 0xffff0001);
});
