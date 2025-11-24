"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseClrDirectory, parseSecurityDirectory } from "../../dist/analyzers/pe/clr-security.js";
import { parseBaseRelocations } from "../../dist/analyzers/pe/reloc.js";
import { parseExceptionDirectory } from "../../dist/analyzers/pe/exception.js";
import { MockFile } from "../helpers/mock-file.mjs";

const encoder = new TextEncoder();
const rvaToOff = rva => rva;

const collectCoverage = () => {
  const regions = [];
  const add = (label, start, size) => regions.push({ label, start, size });
  return { regions, add };
};

test("parseClrDirectory parses metadata header and streams", async () => {
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

  const meta = new DataView(fileBytes.buffer, metaOffset, metaSize);
  let p = 0;
  meta.setUint32(p, 0x424a5342, true); p += 4;
  meta.setUint16(p, 1, true); p += 2;
  meta.setUint16(p, 1, true); p += 2;
  meta.setUint32(p, 0, true); p += 4;
  const verStr = encoder.encode("v4.0.30319");
  meta.setUint32(p, verStr.length, true); p += 4;
  fileBytes.set(verStr, metaOffset + p);
  p = (p + verStr.length + 3) & ~3;
  meta.setUint16(p, 0, true); p += 2;
  meta.setUint16(p, 2, true); p += 2;
  meta.setUint32(p, 0x20, true); p += 4;
  meta.setUint32(p, 0x100, true); p += 4;
  fileBytes.set(encoder.encode("#~\0"), metaOffset + p);
  p = (p + 4 + 3) & ~3;
  meta.setUint32(p, 0x120, true); p += 4;
  meta.setUint32(p, 0x80, true); p += 4;
  fileBytes.set(encoder.encode("#Strings\0"), metaOffset + p);

  const dirs = [{ name: "CLR_RUNTIME", rva: clrOffset, size: 0x60 }];
  const { regions, add } = collectCoverage();
  const clr = await parseClrDirectory(new MockFile(fileBytes, "clr.bin"), dirs, rvaToOff, add);
  assert.ok(clr);
  assert.strictEqual(clr.MajorRuntimeVersion, 4);
  assert.strictEqual(clr.meta.version, "v4.0.30319");
  assert.strictEqual(clr.meta.streams.length, 2);
  assert.ok(regions.some(r => r.label.includes("CLR (.NET) header")));
});

test("parseSecurityDirectory walks WIN_CERTIFICATE entries", async () => {
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
  assert.ok(parsed);
  assert.strictEqual(parsed.count, 2);
  assert.strictEqual(parsed.certs.length, 2);
  assert.ok(regions.some(r => r.label.includes("SECURITY")));
});

test("parseBaseRelocations counts entries and stops on invalid blocks", async () => {
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

test("parseExceptionDirectory samples pdata entries", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const exOff = 0x80;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(exOff + 0, 0x10, true);
  dv.setUint32(exOff + 4, 0x20, true);
  dv.setUint32(exOff + 8, 0x30, true);
  dv.setUint32(exOff + 12, 0x40, true);
  dv.setUint32(exOff + 16, 0x50, true);
  dv.setUint32(exOff + 20, 0x60, true);
  const dirs = [{ name: "EXCEPTION", rva: exOff, size: 24 }];
  const { regions, add } = collectCoverage();
  const parsed = await parseExceptionDirectory(new MockFile(bytes, "exception.bin"), dirs, rvaToOff, add);
  assert.ok(parsed);
  assert.strictEqual(parsed.count, 2);
  assert.strictEqual(parsed.sample.length, 2);
  assert.ok(regions.some(r => r.label.includes("EXCEPTION")));
});
