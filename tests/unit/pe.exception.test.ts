"use strict";
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { MockFile } from "../helpers/mock-file.js";
const rvaToOff = (rva: number): number => rva;
const IMAGE_FILE_MACHINE_I386 = 0x014c;
const writeRuntimeFunction = (
  view: DataView,
  offset: number,
  begin: number,
  end: number,
  unwindInfoRva: number
): void => {
  view.setUint32(offset + 0, begin, true);
  view.setUint32(offset + 4, end, true);
  view.setUint32(offset + 8, unwindInfoRva, true);
};
const parseExceptionFixture = (
  bytes: Uint8Array,
  fileName: string,
  directoryRva: number,
  directorySize: number,
  mapping: (rva: number) => number | null = rvaToOff,
  machine?: number
) => parseExceptionDirectory(
  new MockFile(bytes, fileName),
  [{ name: "EXCEPTION", rva: directoryRva, size: directorySize }],
  mapping,
  machine
);
void test("parseExceptionDirectory parses pdata entries and unwind info stats", async () => {
  const bytes = new Uint8Array(0x3000).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff + 0, 0x1000, 0x1010, 0x2000);
  writeRuntimeFunction(dv, exOff + 12, 0x1100, 0x1120, 0x2010);
  bytes[0x2000] = 0x09;
  dv.setUint32(0x2000 + 4, 0x1500, true);
  bytes[0x2010] = 0x21;
  const parsed = await parseExceptionFixture(bytes, "exception.bin", exOff, 24);
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 2);
  assert.deepEqual(parsed.beginRvas, [0x1000, 0x1100]);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 2);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 1);
  assert.strictEqual(parsed.chainedUnwindInfoCount, 1);
  assert.strictEqual(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.handlerRvas, [0x1500]);
  assert.deepEqual(parsed.issues, []);
});
void test("parseExceptionDirectory reports misaligned directory sizes", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x10, 0x20, 0);
  const parsed = await parseExceptionFixture(bytes, "exception-misaligned.bin", exOff, 13);
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 1);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("not a multiple")));
});

void test("parseExceptionDirectory reports an unmappable directory base instead of silently returning null", async () => {
  const parsed = await parseExceptionFixture(
    new Uint8Array(Uint32Array.BYTES_PER_ELEMENT * 3).fill(0),
    "exception-unmapped.bin",
    1,
    Uint32Array.BYTES_PER_ELEMENT * 3,
    () => null
  );

  assert.ok(parsed);
  assert.strictEqual(parsed?.functionCount, 0);
  assert.ok(parsed?.issues.some(issue => /map|offset|rva/i.test(issue)));
});

void test("parseExceptionDirectory reports unsorted RUNTIME_FUNCTION entries", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  // Microsoft x64 exception-handling docs:
  // RUNTIME_FUNCTION entries are sorted by function start address before emission into .pdata.
  writeRuntimeFunction(dv, exOff + 0, 0x100, 0x110, 0x200);
  writeRuntimeFunction(dv, exOff + 12, 0x80, 0x90, 0x210);
  bytes[0x200] = 0x01;
  bytes[0x210] = 0x01;
  const parsed = await parseExceptionFixture(bytes, "exception-unsorted.bin", exOff, 24);
  assert.ok(parsed);
  assert.ok(parsed.issues.some(issue => /sorted|order/i.test(issue)));
});
void test("parseExceptionDirectory reports truncation when the directory spills past EOF", async () => {
  const exOff = 0x80;
  const bytes = new Uint8Array(exOff + 12).fill(0);
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x10, 0x20, 0);
  const parsed = await parseExceptionFixture(bytes, "exception-truncated.bin", exOff, 24);
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 1);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("truncated")));
});
void test("parseExceptionDirectory preserves a declared EXCEPTION directory that is smaller than one RUNTIME_FUNCTION entry", async () => {
  const exOff = 0x80;
  const bytes = new Uint8Array(exOff + 8).fill(0);
  // Microsoft x64 pdata entries are 12-byte RUNTIME_FUNCTION records.
  const parsed = await parseExceptionFixture(bytes, "exception-too-small-directory.bin", exOff, 8);
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 0);
  assert.ok(parsed.issues.some(issue => /runtime_function|truncated|12 bytes/i.test(issue)));
});
void test("parseExceptionDirectory stops when later RUNTIME_FUNCTION slots no longer map through rvaToOff", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exRva = 0x80;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, 0x00, 0x1000, 0x1010, 0x2000);
  writeRuntimeFunction(dv, 0x0c, 0x1200, 0x1210, 0x2200);
  bytes[0x60] = 0x01;
  bytes[0xa0] = 0x01;
  const sparseRvaToOff = (rva: number): number | null => {
    // Only the first pdata slot is actually mapped; the second logical slot must not be read from flat bytes.
    if (rva === exRva) return 0;
    if (rva >= 0x1000 && rva < 0x1010) return 0x20 + (rva - 0x1000);
    if (rva >= 0x1200 && rva < 0x1210) return 0x40 + (rva - 0x1200);
    if (rva === 0x2000) return 0x60;
    if (rva === 0x2200) return 0xa0;
    return null;
  };
  const parsed = await parseExceptionFixture(bytes, "exception-gap.bin", exRva, 24, sparseRvaToOff);
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 1);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("truncated")));
});
void test("parseExceptionDirectory returns empty stats when no complete entry is available", async () => {
  const exOff = 0x80;
  const bytes = new Uint8Array(exOff + 6).fill(0);
  const parsed = await parseExceptionFixture(bytes, "exception-too-small.bin", exOff, 12);
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 0);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("truncated")));
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("does not contain")));
});
void test("parseExceptionDirectory reports unreadable UNWIND_INFO blocks", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x10, 0x20, 0x300);
  const parsed = await parseExceptionFixture(bytes, "exception-unwind-missing.bin", exOff, 12);
  assert.ok(parsed);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 1);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 0);
  assert.strictEqual(parsed.chainedUnwindInfoCount, 0);
  assert.strictEqual(parsed.invalidEntryCount, 1);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("could not be read")));
});
void test("parseExceptionDirectory reports unexpected UNWIND_INFO versions", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const exOff = 0x80;
  const unwindInfoRva = 0x200;
  bytes[unwindInfoRva] = 0x00;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x10, 0x20, unwindInfoRva);
  const parsed = await parseExceptionFixture(bytes, "exception-unwind-version.bin", exOff, 12);
  assert.ok(parsed);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 1);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 0);
  assert.strictEqual(parsed.chainedUnwindInfoCount, 0);
  assert.strictEqual(parsed.invalidEntryCount, 0);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("unexpected version")));
});
void test("parseExceptionDirectory counts invalid RUNTIME_FUNCTION ranges", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x10, 0x20, 0);
  writeRuntimeFunction(dv, exOff + 12, 0x30, 0x20, 0);
  const parsed = await parseExceptionFixture(bytes, "exception-invalid-range.bin", exOff, 24);
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 2);
  assert.strictEqual(parsed.invalidEntryCount, 1);
});
void test("parseExceptionDirectory does not expose invalid function ranges as unwind begin seeds", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x10, 0x20, 0);
  writeRuntimeFunction(dv, exOff + 12, 0x30, 0x20, 0);
  const parsed = await parseExceptionFixture(bytes, "exception-invalid-seed.bin", exOff, 24);
  assert.ok(parsed);
  assert.strictEqual(parsed.invalidEntryCount, 1);
  assert.deepEqual(parsed.beginRvas, [0x10]);
});
void test("parseExceptionDirectory does not parse aligned-down UNWIND_INFO after the recorded RVA is invalid", async () => {
  const bytes = new Uint8Array(0x2400).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x1000, 0x1010, 0x2002);
  bytes[0x2000] = 0x09;
  dv.setUint32(0x2004, 0x1500, true);
  const alignedOnlyRvaToOff = (rva: number): number | null => {
    if (rva === exOff) return exOff;
    // 0x2002 is invalid, but 0x2000 is mapped; the parser must not invent a handler by rounding down.
    if (rva >= 0x1000 && rva < 0x1010) return 0x1000 + (rva - 0x1000);
    if (rva === 0x2000) return 0x2000;
    return null;
  };
  const parsed = await parseExceptionFixture(
    bytes,
    "exception-unaligned-unwind.bin",
    exOff,
    12,
    alignedOnlyRvaToOff
  );
  assert.ok(parsed);
  assert.strictEqual(parsed.invalidEntryCount, 1);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 0);
  assert.deepEqual(parsed.handlerRvas, []);
});
void test("parseExceptionDirectory reports truncated handler payloads after UNWIND_INFO code slots", async () => {
  const bytes = new Uint8Array(0x204).fill(0);
  const exOff = 0x80;
  const unwindInfoRva = 0x200;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x10, 0x20, unwindInfoRva);
  // Microsoft x64 exception-handling docs:
  // when EHANDLER/UHANDLER is set, a 4-byte handler RVA follows the aligned UNWIND_CODE array.
  bytes[unwindInfoRva] = 0x09; // version 1 | UNW_FLAG_EHANDLER
  const parsed = await parseExceptionFixture(bytes, "exception-truncated-handler-tail.bin", exOff, 12);
  assert.ok(parsed);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 1);
  assert.deepEqual(parsed.handlerRvas, []);
  assert.ok(parsed.issues.some(issue => /handler|truncated|unwind_info/i.test(issue)));
});
void test("parseExceptionDirectory does not decode x64 unwind records for unsupported machines", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format spec, .pdata section:
  // the exception directory layout is machine-specific, so an x86 image must not decode AMD64 pdata semantics.
  writeRuntimeFunction(dv, exOff, 0x1000, 0x1010, 0x2000);
  bytes[0x2000] = 0x09;
  const parsed = await parseExceptionFixture(
    bytes,
    "exception-x86.bin",
    exOff,
    12,
    rvaToOff,
    IMAGE_FILE_MACHINE_I386
  );
  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 0);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 0);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("machine")));
});
void test("parseExceptionDirectory does not invent handler RVAs from chained unwind records", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const exOff = 0x80;
  const unwindInfoRva = 0x2000;
  const chainedUnwindInfoRva = 0x3000;
  const dv = new DataView(bytes.buffer);
  writeRuntimeFunction(dv, exOff, 0x1000, 0x1010, unwindInfoRva);
  // Microsoft x64 exception-handling docs:
  // if UNW_FLAG_CHAININFO is set, EHANDLER/UHANDLER must be clear and the trailing payload is a chained record.
  bytes[0x200] = 0x29; // version 1 | UNW_FLAG_EHANDLER | UNW_FLAG_CHAININFO
  // The chained begin/end RVAs are incidental here; the test only cares that the payload is treated as CHAININFO.
  dv.setUint32(0x204, 0x1111, true); // chained FunctionStart
  dv.setUint32(0x208, 0x1122, true); // chained FunctionEnd
  dv.setUint32(0x20c, chainedUnwindInfoRva, true); // chained UnwindInfoAddress
  bytes[0x240] = 0x01; // secondary unwind info version 1, no flags
  const mappedRvaToOff = (rva: number): number | null => {
    if (rva === exOff) return exOff;
    if (rva >= 0x1000 && rva < 0x1010) return 0x100 + (rva - 0x1000);
    if (rva === unwindInfoRva) return 0x200;
    if (rva === chainedUnwindInfoRva) return 0x240;
    return null;
  };
  const parsed = await parseExceptionFixture(
    bytes,
    "exception-chaininfo-handler-conflict.bin",
    exOff,
    12,
    mappedRvaToOff
  );
  assert.ok(parsed);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 0);
  assert.deepEqual(parsed.handlerRvas, []);
  assert.strictEqual(parsed.chainedUnwindInfoCount, 1);
  assert.ok(parsed.issues.some(issue => /chaininfo|ehandler|uhandler/i.test(issue)));
});
