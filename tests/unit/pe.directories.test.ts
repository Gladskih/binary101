"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseClrDirectory } from "../../analyzers/pe/clr.js";
import { parseSecurityDirectory } from "../../analyzers/pe/security.js";
import { parseBaseRelocations } from "../../analyzers/pe/reloc.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const rvaToOff = (rva: number): number => rva;

type CoverageEntry = { label: string; start: number; size: number };

const collectCoverage = (): {
  regions: CoverageEntry[];
  add: (label: string, start: number, size: number) => void;
} => {
  const regions: CoverageEntry[] = [];
  const add = (label: string, start: number, size: number) => regions.push({ label, start, size });
  return { regions, add };
};

type ClrParseResult = {
  MajorRuntimeVersion?: number;
  meta?: { version?: string; streams: unknown[] };
} | null;

void test("parseClrDirectory parses metadata header and streams", async () => {
  const fileBytes = new Uint8Array(0x400).fill(0);
  const clrOffset = 0x100;
  const metaOffset = 0x200;
  const metaSize = 0x80;
  const clrView = new DataView(fileBytes.buffer);
  clrView.setUint32(clrOffset + 0, 0x48, true);
  clrView.setUint16(clrOffset + 4, 4, true);
  clrView.setUint16(clrOffset + 6, 0, true);
  clrView.setUint32(clrOffset + 8, metaOffset, true);
  clrView.setUint32(clrOffset + 12, metaSize, true);
  clrView.setUint32(clrOffset + 16, 0x01, true);
  clrView.setUint32(clrOffset + 20, 0x06000001, true);

  const metaView = new DataView(fileBytes.buffer, metaOffset, metaSize);
  let p = 0;
  metaView.setUint32(p, 0x424a5342, true); p += 4;
  metaView.setUint16(p, 1, true); p += 2;
  metaView.setUint16(p, 1, true); p += 2;
  metaView.setUint32(p, 0, true); p += 4;
  const verStr = encoder.encode("v4.0.30319");
  metaView.setUint32(p, verStr.length, true); p += 4;
  fileBytes.set(verStr, metaOffset + p);
  p = (p + verStr.length + 3) & ~3;
  metaView.setUint16(p, 0, true); p += 2;
  metaView.setUint16(p, 2, true); p += 2;
  metaView.setUint32(p, 0x20, true); p += 4;
  metaView.setUint32(p, 0x100, true); p += 4;
  fileBytes.set(encoder.encode("#~\0"), metaOffset + p);
  p = (p + 4 + 3) & ~3;
  metaView.setUint32(p, 0x120, true); p += 4;
  metaView.setUint32(p, 0x80, true); p += 4;
  fileBytes.set(encoder.encode("#Strings\0"), metaOffset + p);

  const dirs = [{ name: "CLR_RUNTIME", rva: clrOffset, size: 0x60 }];
  const { regions, add } = collectCoverage();
  const clr: ClrParseResult = await parseClrDirectory(new MockFile(fileBytes, "clr.bin"), dirs, rvaToOff, add);
  const definedClr = expectDefined(clr);
  const meta = expectDefined(definedClr.meta);
  assert.strictEqual(definedClr.MajorRuntimeVersion, 4);
  assert.strictEqual(meta.version, "v4.0.30319");
  assert.strictEqual(meta.streams.length, 2);
  assert.ok(regions.some(r => r.label.includes("CLR (.NET) header")));
});

void test("parseSecurityDirectory walks WIN_CERTIFICATE entries", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const secOff = 0x100;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(secOff + 0, 12, true);
  dv.setUint16(secOff + 4, 0x0200, true);
  dv.setUint16(secOff + 6, 0x0002, true);
  const second = secOff + 16;
  dv.setUint32(second + 0, 16, true);
  dv.setUint16(second + 4, 0x0200, true);
  dv.setUint16(second + 6, 0x0002, true);

  const dirs = [{ name: "SECURITY", rva: secOff, size: 40 }];
  const { regions, add } = collectCoverage();
  const parsed = await parseSecurityDirectory(new MockFile(bytes, "sec.bin"), dirs, add);
  const sec = expectDefined(parsed);
  const firstCert = expectDefined(sec.certs[0]);
  assert.strictEqual(sec.count, 2);
  assert.strictEqual(sec.certs.length, 2);
  assert.strictEqual(firstCert.certificateType, 0x0002);
  assert.strictEqual(firstCert.typeName.includes("PKCS#7"), true);
  assert.ok(firstCert.authenticode);
  assert.ok(regions.some(r => r.label.includes("SECURITY")));
});

void test("parseBaseRelocations counts entries and stops on invalid blocks", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const relOff = 0x40;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(relOff + 0, 0x1000, true);
  dv.setUint32(relOff + 4, 0x10, true);
  const invalidBlock = relOff + 0x10;
  dv.setUint32(invalidBlock + 0, 0, true);
  dv.setUint32(invalidBlock + 4, 0x08, true);
  const dirs = [{ name: "BASERELOC", rva: relOff, size: 0x20 }];
  const { regions, add } = collectCoverage();
  const parsed = await parseBaseRelocations(new MockFile(bytes, "reloc.bin"), dirs, rvaToOff, add);
  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
  assert.strictEqual(parsed.totalEntries, 4);
  assert.ok(regions.some(r => r.label.includes("BASERELOC")));
});

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

  bytes[0x2000] = 0x09; // UNWIND_INFO: version=1, flags=EHANDLER
  dv.setUint32(0x2000 + 4, 0x1500, true); // ExceptionHandler RVA
  bytes[0x2010] = 0x21; // UNWIND_INFO: version=1, flags=CHAININFO

  const dirs = [{ name: "EXCEPTION", rva: exOff, size: 24 }];
  const { regions, add } = collectCoverage();
  const parsed = await parseExceptionDirectory(new MockFile(bytes, "exception.bin"), dirs, rvaToOff, add);

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 2);
  assert.deepEqual(parsed.beginRvas, [0x1000, 0x1100]);
  assert.strictEqual(parsed.uniqueUnwindInfoCount, 2);
  assert.strictEqual(parsed.handlerUnwindInfoCount, 1);
  assert.strictEqual(parsed.chainedUnwindInfoCount, 1);
  assert.strictEqual(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.handlerRvas, [0x1500]);
  assert.deepEqual(parsed.issues, []);
  assert.ok(regions.some(r => r.label.includes("EXCEPTION")));
});

void test("parseExceptionDirectory does not cap large pdata directories at 1024 entries", async () => {
  const entryCount = 1025;
  const exOff = 0x100;
  const unwindInfoRva = 0x4000;
  const bytes = new Uint8Array(0x6000).fill(0);
  bytes[unwindInfoRva] = 0x09; // UNWIND_INFO: version=1, flags=EHANDLER
  const dv = new DataView(bytes.buffer);
  for (let index = 0; index < entryCount; index += 1) {
    const begin = 0x1000 + index * 0x10;
    dv.setUint32(exOff + index * 12 + 0, begin, true);
    dv.setUint32(exOff + index * 12 + 4, begin + 0x10, true);
    dv.setUint32(exOff + index * 12 + 8, unwindInfoRva, true);
  }

  const dirs = [{ name: "EXCEPTION", rva: exOff, size: entryCount * 12 }];
  const { add } = collectCoverage();
  const parsed = await parseExceptionDirectory(new MockFile(bytes, "exception-big.bin"), dirs, rvaToOff, add);

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

  const dirs = [{ name: "EXCEPTION", rva: exOff, size: 13 }];
  const { add } = collectCoverage();
  const parsed = await parseExceptionDirectory(new MockFile(bytes, "exception-misaligned.bin"), dirs, rvaToOff, add);

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

  const dirs = [{ name: "EXCEPTION", rva: exOff, size: 24 }];
  const { add } = collectCoverage();
  const parsed = await parseExceptionDirectory(new MockFile(bytes, "exception-truncated.bin"), dirs, rvaToOff, add);

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 1);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("truncated")));
});

void test("parseExceptionDirectory returns empty stats when no complete entry is available", async () => {
  const exOff = 0x80;
  const bytes = new Uint8Array(exOff + 6).fill(0);
  const dirs = [{ name: "EXCEPTION", rva: exOff, size: 12 }];
  const { add } = collectCoverage();
  const parsed = await parseExceptionDirectory(
    new MockFile(bytes, "exception-too-small.bin"),
    dirs,
    rvaToOff,
    add
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

  const dirs = [{ name: "EXCEPTION", rva: exOff, size: 12 }];
  const { add } = collectCoverage();
  const parsed = await parseExceptionDirectory(new MockFile(bytes, "exception-unwind-missing.bin"), dirs, rvaToOff, add);

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
  bytes[unwindInfoRva] = 0x00; // UNWIND_INFO: version=0 (unexpected), flags=0
  const dv = new DataView(bytes.buffer);
  dv.setUint32(exOff + 0, 0x10, true);
  dv.setUint32(exOff + 4, 0x20, true);
  dv.setUint32(exOff + 8, unwindInfoRva, true);

  const dirs = [{ name: "EXCEPTION", rva: exOff, size: 12 }];
  const { add } = collectCoverage();
  const parsed = await parseExceptionDirectory(new MockFile(bytes, "exception-unwind-version.bin"), dirs, rvaToOff, add);

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
  dv.setUint32(exOff + 16, 0x20, true); // Begin >= End -> invalid
  dv.setUint32(exOff + 20, 0, true);

  const dirs = [{ name: "EXCEPTION", rva: exOff, size: 24 }];
  const { add } = collectCoverage();
  const parsed = await parseExceptionDirectory(new MockFile(bytes, "exception-invalid-range.bin"), dirs, rvaToOff, add);

  assert.ok(parsed);
  assert.strictEqual(parsed.functionCount, 2);
  assert.strictEqual(parsed.invalidEntryCount, 1);
});
