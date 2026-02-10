"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseClrDirectory } from "../../analyzers/pe/clr.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const rvaToOff = (rva: number): number => rva;

type CoverageEntry = { label: string; start: number; size: number };

const collectCoverage = (): {
  regions: CoverageEntry[];
  add: (label: string, start: number, size: number) => void;
} => {
  const regions: CoverageEntry[] = [];
  const add = (label: string, start: number, size: number) => {
    regions.push({ label, start, size });
  };
  return { regions, add };
};

void test("parseClrDirectory parses metadata header and streams", async () => {
  const encoder = new TextEncoder();
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
  let cursor = 0;
  metaView.setUint32(cursor, 0x424a5342, true);
  cursor += 4;
  metaView.setUint16(cursor, 1, true);
  cursor += 2;
  metaView.setUint16(cursor, 1, true);
  cursor += 2;
  metaView.setUint32(cursor, 0, true);
  cursor += 4;
  const versionBytes = encoder.encode("v4.0.30319");
  metaView.setUint32(cursor, versionBytes.length, true);
  cursor += 4;
  fileBytes.set(versionBytes, metaOffset + cursor);
  cursor = (cursor + versionBytes.length + 3) & ~3;
  metaView.setUint16(cursor, 0, true);
  cursor += 2;
  metaView.setUint16(cursor, 2, true);
  cursor += 2;

  metaView.setUint32(cursor, 0x20, true);
  cursor += 4;
  metaView.setUint32(cursor, 0x100, true);
  cursor += 4;
  fileBytes.set(encoder.encode("#~\0"), metaOffset + cursor);
  cursor = (cursor + 4 + 3) & ~3;

  metaView.setUint32(cursor, 0x120, true);
  cursor += 4;
  metaView.setUint32(cursor, 0x80, true);
  cursor += 4;
  const nameBytes = encoder.encode("#Strings\0");
  fileBytes.set(nameBytes, metaOffset + cursor);

  const dirs = [{ name: "CLR_RUNTIME", rva: clrOffset, size: 0x60 }];
  const { regions, add } = collectCoverage();
  const clr = await parseClrDirectory(
    new MockFile(fileBytes, "clr.bin"),
    dirs,
    rvaToOff,
    add
  );

  const definedClr = expectDefined(clr);
  const meta = expectDefined(definedClr.meta);

  assert.strictEqual(definedClr.MajorRuntimeVersion, 4);
  assert.strictEqual(meta.version, "v4.0.30319");
  assert.strictEqual(meta.streams.length, 2);
  assert.ok(regions.some(r => r.label.includes("CLR (.NET) header")));
});

void test("parseClrDirectory parses full IMAGE_COR20_HEADER directory fields", async () => {
  const bytes = new Uint8Array(0x600).fill(0);
  const clrOffset = 0x100;
  const metaOffset = 0x200;
  const dv = new DataView(bytes.buffer);

  dv.setUint32(clrOffset + 0x00, 0x48, true);
  dv.setUint16(clrOffset + 0x04, 4, true);
  dv.setUint16(clrOffset + 0x06, 0, true);
  dv.setUint32(clrOffset + 0x08, metaOffset, true);
  dv.setUint32(clrOffset + 0x0c, 0x80, true);
  dv.setUint32(clrOffset + 0x10, 0, true);
  dv.setUint32(clrOffset + 0x14, 0x06000001, true);

  dv.setUint32(clrOffset + 0x18, 0x300, true);
  dv.setUint32(clrOffset + 0x1c, 0x40, true);
  dv.setUint32(clrOffset + 0x20, 0x340, true);
  dv.setUint32(clrOffset + 0x24, 0x20, true);
  dv.setUint32(clrOffset + 0x28, 0x360, true);
  dv.setUint32(clrOffset + 0x2c, 0x10, true);
  dv.setUint32(clrOffset + 0x30, 0x380, true);
  dv.setUint32(clrOffset + 0x34, 0x10, true);
  dv.setUint32(clrOffset + 0x38, 0x3a0, true);
  dv.setUint32(clrOffset + 0x3c, 0x08, true);
  dv.setUint32(clrOffset + 0x40, 0x3a8, true);
  dv.setUint32(clrOffset + 0x44, 0x18, true);

  const dirs = [{ name: "CLR_RUNTIME", rva: clrOffset, size: 0x48 }];
  const { add } = collectCoverage();
  const clr = await parseClrDirectory(new MockFile(bytes, "clr-full.bin"), dirs, rvaToOff, add);
  const definedClr = expectDefined(clr);

  assert.strictEqual(definedClr.ResourcesRVA, 0x300);
  assert.strictEqual(definedClr.ResourcesSize, 0x40);
  assert.strictEqual(definedClr.StrongNameSignatureRVA, 0x340);
  assert.strictEqual(definedClr.StrongNameSignatureSize, 0x20);
  assert.strictEqual(definedClr.CodeManagerTableRVA, 0x360);
  assert.strictEqual(definedClr.CodeManagerTableSize, 0x10);
  assert.strictEqual(definedClr.VTableFixupsRVA, 0x380);
  assert.strictEqual(definedClr.VTableFixupsSize, 0x10);
  assert.strictEqual(definedClr.ExportAddressTableJumpsRVA, 0x3a0);
  assert.strictEqual(definedClr.ExportAddressTableJumpsSize, 0x08);
  assert.strictEqual(definedClr.ManagedNativeHeaderRVA, 0x3a8);
  assert.strictEqual(definedClr.ManagedNativeHeaderSize, 0x18);
});

void test("parseClrDirectory parses VTableFixups entries", async () => {
  const bytes = new Uint8Array(0x500).fill(0);
  const clrOffset = 0x100;
  const vtOff = 0x200;
  const dv = new DataView(bytes.buffer);

  dv.setUint32(clrOffset + 0x00, 0x48, true);
  dv.setUint16(clrOffset + 0x04, 4, true);
  dv.setUint16(clrOffset + 0x06, 0, true);
  dv.setUint32(clrOffset + 0x08, 0, true);
  dv.setUint32(clrOffset + 0x0c, 0, true);
  dv.setUint32(clrOffset + 0x10, 0, true);
  dv.setUint32(clrOffset + 0x14, 0, true);

  dv.setUint32(clrOffset + 0x30, vtOff, true);
  dv.setUint32(clrOffset + 0x34, 0x10, true);

  dv.setUint32(vtOff + 0x00, 0x1111, true);
  dv.setUint16(vtOff + 0x04, 2, true);
  dv.setUint16(vtOff + 0x06, 0x01, true);
  dv.setUint32(vtOff + 0x08, 0x2222, true);
  dv.setUint16(vtOff + 0x0c, 1, true);
  dv.setUint16(vtOff + 0x0e, 0x04, true);

  const dirs = [{ name: "CLR_RUNTIME", rva: clrOffset, size: 0x48 }];
  const { add } = collectCoverage();
  const clr = await parseClrDirectory(new MockFile(bytes, "clr-vt.bin"), dirs, rvaToOff, add);
  const definedClr = expectDefined(clr);

  const entries = expectDefined(definedClr.vtableFixups);
  assert.strictEqual(entries.length, 2);
  assert.deepStrictEqual(entries[0], { RVA: 0x1111, Count: 2, Type: 0x01 });
  assert.deepStrictEqual(entries[1], { RVA: 0x2222, Count: 1, Type: 0x04 });
});

void test("parseClrDirectory returns issues when the CLR directory is truncated", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const clrOffset = 0x100;
  const dv = new DataView(bytes.buffer);

  dv.setUint32(clrOffset + 0x00, 0x48, true);
  dv.setUint16(clrOffset + 0x04, 4, true);
  dv.setUint16(clrOffset + 0x06, 0, true);
  dv.setUint32(clrOffset + 0x08, 0, true);
  dv.setUint32(clrOffset + 0x0c, 0, true);
  dv.setUint32(clrOffset + 0x10, 0, true);
  dv.setUint32(clrOffset + 0x14, 0, true);

  const dirs = [{ name: "CLR_RUNTIME", rva: clrOffset, size: 0x18 }];
  const { add } = collectCoverage();
  const clr = await parseClrDirectory(
    new MockFile(bytes, "clr-truncated.bin"),
    dirs,
    rvaToOff,
    add
  );
  const definedClr = expectDefined(clr);
  const issues = expectDefined(definedClr.issues);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("truncated")));
});

void test("parseClrDirectory returns partial header info even when the directory is smaller than minimum", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  const clrOffset = 0x40;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(clrOffset + 0x00, 0x48, true);
  dv.setUint16(clrOffset + 0x04, 2, true);
  dv.setUint16(clrOffset + 0x06, 5, true);
  const dirs = [{ name: "CLR_RUNTIME", rva: clrOffset, size: 0x10 }];
  const { add } = collectCoverage();
  const clr = await parseClrDirectory(new MockFile(bytes, "clr-too-small.bin"), dirs, rvaToOff, add);
  const definedClr = expectDefined(clr);
  assert.strictEqual(definedClr.MajorRuntimeVersion, 2);
  assert.ok(expectDefined(definedClr.issues).some(issue => issue.toLowerCase().includes("minimum")));
});

void test("parseClrDirectory reports metadata RVAs that cannot be mapped", async () => {
  const bytes = new Uint8Array(0x300).fill(0);
  const clrOffset = 0x100;
  const metaRva = 0x200;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(clrOffset + 0x00, 0x48, true);
  dv.setUint16(clrOffset + 0x04, 2, true);
  dv.setUint16(clrOffset + 0x06, 5, true);
  dv.setUint32(clrOffset + 0x08, metaRva, true);
  dv.setUint32(clrOffset + 0x0c, 0x80, true);
  const dirs = [{ name: "CLR_RUNTIME", rva: clrOffset, size: 0x48 }];
  const { add } = collectCoverage();
  const mapWithHole = (rva: number): number | null => (rva === metaRva ? null : rva);
  const clr = await parseClrDirectory(new MockFile(bytes, "clr-meta-hole.bin"), dirs, mapWithHole, add);
  assert.ok(expectDefined(expectDefined(clr).issues).some(issue => issue.toLowerCase().includes("metadata rva")));
});

