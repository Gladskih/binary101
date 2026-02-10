"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCor20Issues, readCor20Header } from "../../analyzers/pe/clr-cor20-header.js";

void test("readCor20Header reads IMAGE_COR20_HEADER fields from a full header view", () => {
  const bytes = new Uint8Array(0x48).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0x00, 0x48, true);
  dv.setUint16(0x04, 2, true);
  dv.setUint16(0x06, 5, true);
  dv.setUint32(0x08, 0x1111, true);
  dv.setUint32(0x0c, 0x2222, true);
  dv.setUint32(0x10, 0x3333, true);
  dv.setUint32(0x14, 0x4444, true);
  dv.setUint32(0x18, 0x5555, true);
  dv.setUint32(0x1c, 0x6666, true);
  dv.setUint32(0x20, 0x7777, true);
  dv.setUint32(0x24, 0x8888, true);
  dv.setUint32(0x28, 0x9999, true);
  dv.setUint32(0x2c, 0xaaaa, true);
  dv.setUint32(0x30, 0xbbbb, true);
  dv.setUint32(0x34, 0xcccc, true);
  dv.setUint32(0x38, 0xdddd, true);
  dv.setUint32(0x3c, 0xeeee, true);
  dv.setUint32(0x40, 0xffff0000, true);
  dv.setUint32(0x44, 0x12345678, true);
  const parsed = readCor20Header(new DataView(bytes.buffer));
  assert.strictEqual(parsed.cb, 0x48);
  assert.strictEqual(parsed.MajorRuntimeVersion, 2);
  assert.strictEqual(parsed.MinorRuntimeVersion, 5);
  assert.strictEqual(parsed.MetaDataRVA, 0x1111);
  assert.strictEqual(parsed.MetaDataSize, 0x2222);
  assert.strictEqual(parsed.Flags, 0x3333);
  assert.strictEqual(parsed.EntryPointToken, 0x4444);
  assert.strictEqual(parsed.ResourcesRVA, 0x5555);
  assert.strictEqual(parsed.ResourcesSize, 0x6666);
  assert.strictEqual(parsed.StrongNameSignatureRVA, 0x7777);
  assert.strictEqual(parsed.StrongNameSignatureSize, 0x8888);
  assert.strictEqual(parsed.CodeManagerTableRVA, 0x9999);
  assert.strictEqual(parsed.CodeManagerTableSize, 0xaaaa);
  assert.strictEqual(parsed.VTableFixupsRVA, 0xbbbb);
  assert.strictEqual(parsed.VTableFixupsSize, 0xcccc);
  assert.strictEqual(parsed.ExportAddressTableJumpsRVA, 0xdddd);
  assert.strictEqual(parsed.ExportAddressTableJumpsSize, 0xeeee);
  assert.strictEqual(parsed.ManagedNativeHeaderRVA, 0xffff0000);
  assert.strictEqual(parsed.ManagedNativeHeaderSize, 0x12345678);
});

void test("buildCor20Issues reports declared sizes smaller than the minimum COR20 header", () => {
  const issues = buildCor20Issues(0x10, 0x10);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("minimum")));
});
