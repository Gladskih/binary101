"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDirectory } from "../../analyzers/pe/exception.js";
import { MockFile } from "../helpers/mock-file.js";

const rvaToOff = (rva: number): number => rva;

const coverageAdd = (_label: string, _start: number, _size: number): void => {};

void test("parseExceptionDirectory parses pdata entries and unwind info stats", async () => {
  const bytes = new Uint8Array(0x3000).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(exOff + 0, 0x1000, true);
  dv.setUint32(exOff + 4, 0x1010, true);
  dv.setUint32(exOff + 8, 0x2000, true);
  dv.setUint32(exOff + 12, 0x1100, true);
  dv.setUint32(exOff + 16, 0x1120, true);
  dv.setUint32(exOff + 20, 0x2010, true);

  bytes[0x2000] = 0x09;
  dv.setUint32(0x2000 + 4, 0x1500, true);
  bytes[0x2010] = 0x21;

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: 24 }],
    rvaToOff,
    coverageAdd
  );

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

void test("parseExceptionDirectory does not cap large pdata directories at 1024 entries", async () => {
  const entryCount = 1025;
  const exOff = 0x100;
  const unwindInfoRva = 0x4000;
  const bytes = new Uint8Array(0x6000).fill(0);
  bytes[unwindInfoRva] = 0x09;
  const dv = new DataView(bytes.buffer);
  for (let index = 0; index < entryCount; index += 1) {
    const begin = 0x1000 + index * 0x10;
    dv.setUint32(exOff + index * 12 + 0, begin, true);
    dv.setUint32(exOff + index * 12 + 4, begin + 0x10, true);
    dv.setUint32(exOff + index * 12 + 8, unwindInfoRva, true);
  }

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-big.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: entryCount * 12 }],
    rvaToOff,
    coverageAdd
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, entryCount);
  assert.strictEqual(parsed.beginRvas.length, entryCount);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 1);
});

void test("parseExceptionDirectory reports misaligned directory sizes", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(exOff + 0, 0x10, true);
  dv.setUint32(exOff + 4, 0x20, true);
  dv.setUint32(exOff + 8, 0, true);

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-misaligned.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: 13 }],
    rvaToOff,
    coverageAdd
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 1);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("not a multiple")));
});

void test("parseExceptionDirectory reports truncation when the directory spills past EOF", async () => {
  const exOff = 0x80;
  const bytes = new Uint8Array(exOff + 12).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(exOff + 0, 0x10, true);
  dv.setUint32(exOff + 4, 0x20, true);
  dv.setUint32(exOff + 8, 0, true);

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-truncated.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: 24 }],
    rvaToOff,
    coverageAdd
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 1);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("truncated")));
});

void test("parseExceptionDirectory returns empty stats when no complete entry is available", async () => {
  const exOff = 0x80;
  const bytes = new Uint8Array(exOff + 6).fill(0);
  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-too-small.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: 12 }],
    rvaToOff,
    coverageAdd
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 0);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("truncated")));
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("does not contain")));
});

void test("parseExceptionDirectory reports unreadable UNWIND_INFO blocks", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(exOff + 0, 0x10, true);
  dv.setUint32(exOff + 4, 0x20, true);
  dv.setUint32(exOff + 8, 0x300, true);

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-unwind-missing.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: 12 }],
    rvaToOff,
    coverageAdd
  );

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
  dv.setUint32(exOff + 0, 0x10, true);
  dv.setUint32(exOff + 4, 0x20, true);
  dv.setUint32(exOff + 8, unwindInfoRva, true);

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-unwind-version.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: 12 }],
    rvaToOff,
    coverageAdd
  );

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
  dv.setUint32(exOff + 0, 0x10, true);
  dv.setUint32(exOff + 4, 0x20, true);
  dv.setUint32(exOff + 8, 0, true);
  dv.setUint32(exOff + 12, 0x30, true);
  dv.setUint32(exOff + 16, 0x20, true);
  dv.setUint32(exOff + 20, 0, true);

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-invalid-range.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: 24 }],
    rvaToOff,
    coverageAdd
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 2);
  assert.strictEqual(parsed.invalidEntryCount, 1);
});

void test("parseExceptionDirectory does not decode x64 unwind records for unsupported machines", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(exOff + 0, 0x1000, true);
  dv.setUint32(exOff + 4, 0x1010, true);
  dv.setUint32(exOff + 8, 0x2000, true);
  bytes[0x2000] = 0x09;

  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-x86.bin"),
    [{ name: "EXCEPTION", rva: exOff, size: 12 }],
    rvaToOff,
    coverageAdd,
    0x014c
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 0);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 0);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("machine")));
});
