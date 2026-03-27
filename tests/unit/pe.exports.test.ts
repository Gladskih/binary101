"use strict";
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExportDirectory } from "../../analyzers/pe/exports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";
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
void test("parseExportDirectory extracts names and forwarders", async () => {
  const bytes = new Uint8Array(1024).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 128;
  const dllNameRva = 300;
  const functionTableRva = 400;
  const nameTableRva = 420;
  const ordinalTableRva = 430;
  const exportedNameRva = 440;
  const forwarderRva = directoryRva + 64;
  dv.setUint32(directoryRva + 0, 1, true);
  dv.setUint16(directoryRva + 8, 1, true);
  dv.setUint32(directoryRva + 12, dllNameRva, true);
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 2, true);
  dv.setUint32(directoryRva + 24, 1, true);
  dv.setUint32(directoryRva + 28, functionTableRva, true);
  dv.setUint32(directoryRva + 32, nameTableRva, true);
  dv.setUint32(directoryRva + 36, ordinalTableRva, true);
  encoder.encodeInto("demo.dll\0", new Uint8Array(bytes.buffer, dllNameRva));
  dv.setUint32(functionTableRva + 0, 0x7000, true);
  dv.setUint32(functionTableRva + 4, forwarderRva, true);
  dv.setUint32(nameTableRva, exportedNameRva, true);
  dv.setUint16(ordinalTableRva, 1, true);
  encoder.encodeInto("FuncB\0", new Uint8Array(bytes.buffer, exportedNameRva));
  encoder.encodeInto("KERNEL32.Forward\0", new Uint8Array(bytes.buffer, forwarderRva));
  const result = expectDefined(await parseExportFixture(bytes, { rva: directoryRva, size: 96 }));
  assert.equal(result.dllName, "demo.dll");
  assert.equal(result.entries.length, 2);
  assert.equal(expectDefined(result.entries[1]).forwarder, "KERNEL32.Forward");
  assert.equal(expectDefined(result.entries[1]).name, "FuncB");
});
void test("parseExportDirectory does not read forwarder strings past the export-directory range", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x20;
  const directorySize = 0x40;
  const eatRva = 0x70;
  const forwarderRva = directoryRva + directorySize - 2;

  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 1, true);
  dv.setUint32(directoryRva + 28, eatRva, true);
  dv.setUint32(eatRva, forwarderRva, true);
  bytes[forwarderRva] = 0x41; // "A" inside the export directory.
  bytes[forwarderRva + 1] = 0x42; // "B" inside the export directory.
  bytes[forwarderRva + 2] = 0x43; // "C" outside the export directory.
  bytes[forwarderRva + 3] = 0x44; // "D" outside the export directory.
  bytes[forwarderRva + 4] = 0x00; // Terminator also lies outside the export directory.

  const result = expectDefined(await parseExportFixture(bytes, { rva: directoryRva, size: directorySize }));

  // Microsoft PE format, Export Address Table:
  // a forwarder RVA points to a null-terminated ASCII string that "must be within the range that is given by the
  // export table data directory entry". Bytes that happen to follow the export directory are not part of the string.
  assert.equal(result.entries[0]?.forwarder, "AB");
  assert.ok(result.issues.some(issue => /forwarder|string|truncated/i.test(issue)));
});
void test("parseExportDirectory preserves a declared export directory smaller than the fixed header", async () => {
  const bytes = new Uint8Array(64).fill(0);
  const result = await parseExportFixture(bytes, { rva: 0x10, size: IMAGE_EXPORT_DIRECTORY_SIZE - 1 });
  assert.ok(result);
  assert.equal(result.entries.length, 0);
  assert.ok(result.issues.some(issue => /export|truncated|40/i.test(issue)));
});

void test("parseExportDirectory reports an unmappable export directory instead of silently returning null", async () => {
  const result = await parseExportFixture(
    new Uint8Array(IMAGE_EXPORT_DIRECTORY_SIZE).fill(0),
    { rva: 1, size: IMAGE_EXPORT_DIRECTORY_SIZE },
    () => null
  );

  assert.ok(result);
  assert.equal(result?.entries.length, 0);
  assert.ok(result?.issues.some(issue => /map|offset|rva/i.test(issue)));
});
void test("parseExportDirectory stops at available function table size", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x20;
  dv.setUint32(directoryRva + 20, 10, true);
  dv.setUint32(directoryRva + 28, 0x60, true);
  dv.setUint32(0x60, 0x1234, true);
  const result = expectDefined(await parseExportFixture(bytes, { rva: directoryRva, size: 40 }));
  assert.equal(result.entries.length, 8);
  assert.equal(expectDefined(result.entries[0]).rva, 0x1234);
  assert.equal(result.entries[7]?.rva, 0);
});
void test("parseExportDirectory truncates entries when EAT is shorter than NumberOfFunctions", async () => {
  const bytes = new Uint8Array(0x48).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x10;
  dv.setUint32(directoryRva + 20, 10, true);
  dv.setUint32(directoryRva + 28, 0x40, true);
  dv.setUint32(0x40, 0x1111, true);
  dv.setUint32(0x44, 0x2222, true);
  const result = expectDefined(await parseExportFixture(bytes, { rva: directoryRva, size: 64 }));
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[0]?.rva, 0x1111);
  assert.equal(result.entries[1]?.rva, 0x2222);
});
void test("parseExportDirectory ignores names beyond available name and ordinal tables", async () => {
  const bytes = new Uint8Array(0xe0).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x20;
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 2, true);
  dv.setUint32(directoryRva + 24, 3, true);
  dv.setUint32(directoryRva + 28, 0x80, true);
  dv.setUint32(directoryRva + 32, 0xd4, true);
  dv.setUint32(directoryRva + 36, 0xdc, true);
  dv.setUint32(0x80, 0x1000, true);
  dv.setUint32(0x84, 0x2000, true);
  dv.setUint32(0xd4, 0xc0, true);
  dv.setUint16(0xdc, 0, true);
  dv.setUint16(0xde, 1, true);
  encoder.encodeInto("OnlyName\0", new Uint8Array(bytes.buffer, 0xc0));
  const result = expectDefined(await parseExportFixture(bytes, { rva: directoryRva, size: 80 }));
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[0]?.name, "OnlyName");
  assert.ok(result.entries[1]?.name === null || result.entries[1]?.name === "");
});
void test("parseExportDirectory does not read EAT slots past an rvaToOff gap", async () => {
  const directoryRva = IMAGE_EXPORT_DIRECTORY_SIZE;
  const eatRva = directoryRva + IMAGE_EXPORT_DIRECTORY_SIZE;
  const firstTargetRva = 0x1111;
  const bytes = new Uint8Array(eatRva + Uint32Array.BYTES_PER_ELEMENT * 2).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 2, true);
  dv.setUint32(directoryRva + 28, eatRva, true);
  dv.setUint32(eatRva, firstTargetRva, true);
  dv.setUint32(eatRva + Uint32Array.BYTES_PER_ELEMENT, 0x2222, true);
  const result = expectDefined(await parseExportFixture(
    bytes,
    { rva: directoryRva, size: IMAGE_EXPORT_DIRECTORY_SIZE },
    rva => (rva === directoryRva || rva === eatRva ? rva : null)
  ));
  assert.equal(result.entries.length, 1);
  assert.equal(result.entries[0]?.rva, firstTargetRva);
});
void test("parseExportDirectory bounds the initial directory read to the fixed header size", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x20;
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 1, true);
  dv.setUint32(directoryRva + 28, 0x2000, true);
  const tracked = createSliceTrackingFile(bytes, 0x400000, "exports-bounded-read.bin");
  const result = expectDefined(await parseExportFixture(
    tracked.file,
    { rva: directoryRva, size: 0x200000 },
    value => (value < bytes.length ? value : null)
  ));
  assert.ok(result.issues.some(issue => /does not map/i.test(issue)));
  assert.ok(
    Math.max(...tracked.requests) <= IMAGE_EXPORT_DIRECTORY_SIZE,
    `Expected fixed-size export header read, got requests ${tracked.requests.join(", ")}`
  );
});
void test("parseExportDirectory stops reading export strings at EOF without unbounded retries", async () => {
  const bytes = new Uint8Array(0x41).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x10;
  dv.setUint32(directoryRva + 12, 0x40, true);
  bytes[0x40] = 0x41;
  let sliceCalls = 0;
  const file = {
    lastModified: 0,
    name: "exports-eof-string.bin",
    size: bytes.length,
    type: "application/octet-stream",
    webkitRelativePath: "",
    slice(start?: number, end?: number, contentType?: string): Blob {
      sliceCalls += 1;
      if (sliceCalls > 4) throw new Error("Too many export string reads");
      const sliceStart = Math.max(0, Math.trunc(start ?? 0));
      const sliceEnd = Math.max(sliceStart, Math.trunc(end ?? bytes.length));
      const actualStart = Math.min(sliceStart, bytes.length);
      const actualEnd = Math.min(sliceEnd, bytes.length);
      return new Blob([bytes.slice(actualStart, actualEnd)], {
        type: contentType ?? "application/octet-stream"
      });
    }
  } as File;
  const result = await parseExportFixture(file, { rva: directoryRva, size: 40 });
  assert.equal(expectDefined(result).dllName, "A");
});
void test("parseExportDirectory reads export strings beyond the old 1024-byte parser cap", async () => {
  const longDllName = `${"d".repeat(1025)}.dll`;
  const nameBytes = encoder.encode(`${longDllName}\0`);
  const directoryRva = 0x20;
  const nameRva = 0x80;
  const eatRva = nameRva + nameBytes.length;
  const bytes = new Uint8Array(eatRva + Uint32Array.BYTES_PER_ELEMENT).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(directoryRva + 12, nameRva, true);
  dv.setUint32(directoryRva + 16, 1, true);
  dv.setUint32(directoryRva + 20, 1, true);
  dv.setUint32(directoryRva + 28, eatRva, true);
  dv.setUint32(eatRva, 0x1000, true);
  bytes.set(nameBytes, nameRva);
  const result = expectDefined(await parseExportFixture(
    bytes,
    { rva: directoryRva, size: IMAGE_EXPORT_DIRECTORY_SIZE }
  ));
  assert.equal(result.dllName, longDllName);
});
void test("parseExportDirectory reports when a mapped DLL name offset falls past EOF", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const directoryRva = 0x10;
  dv.setUint32(directoryRva + 12, 0x40, true);
  dv.setUint32(directoryRva + 20, 1, true);
  dv.setUint32(directoryRva + 28, 0x60, true);
  dv.setUint32(0x60, 0x1234, true);
  const result = expectDefined(await parseExportFixture(
    bytes,
    { rva: directoryRva, size: 40 },
    value => (value === directoryRva || value === 0x60 ? value : value === 0 ? null : value + 0x200)
  ));
  assert.ok(result.issues.some(issue => /name/i.test(issue)));
});

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
