"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGuardRf } from "../../../../../analyzers/pe/dynamic-relocations/guard-rf.js";

void test("Guard RF prologue decodes header bytes and relocation sites", () => {
  const view = new DataView(new ArrayBuffer(15));
  view.setUint8(0, 2);
  view.setUint8(1, 0x90);
  view.setUint8(2, 0xcc);
  view.setUint32(3, 0x2000, true);
  view.setUint32(7, 12, true);
  view.setUint16(11, 0x123, true);
  view.setUint16(13, 0x456, true);
  const warnings: string[] = [];

  const parsed = parseGuardRf(view, 1n, 0, 3, 3, 15, warnings);

  assert.deepEqual(parsed, { kind: "prologue", prologueBytes: [0x90, 0xcc],
    sites: [{ rva: 0x2123, type: 0 }, { rva: 0x2456, type: 0 }] });
  assert.deepEqual(warnings, []);
});

void test("Guard RF epilogue decodes descriptors and bitmap", () => {
  const view = new DataView(new ArrayBuffer(21));
  view.setUint32(0, 3, true);
  view.setUint8(4, 5);
  view.setUint8(5, 2);
  view.setUint16(6, 2, true);
  view.setUint8(8, 0xaa);
  view.setUint8(9, 0xbb);
  view.setUint8(10, 0xcc);
  view.setUint8(11, 0xdd);
  view.setUint8(12, 0x05);
  view.setUint32(13, 0x3000, true);
  view.setUint32(17, 8, true);
  const warnings: string[] = [];

  const parsed = parseGuardRf(view, 2n, 0, 13, 13, 21, warnings);

  assert.deepEqual(parsed, { kind: "epilogue", epilogueCount: 3,
    epilogueByteCount: 5, branchDescriptorElementSize: 2,
    branchDescriptors: [[0xaa, 0xbb], [0xcc, 0xdd]], branchDescriptorBitmap: [0x05],
    sites: [] });
  assert.deepEqual(warnings, []);
});

void test("Guard RF retains valid blocks before a truncated block", () => {
  const view = new DataView(new ArrayBuffer(22));
  view.setUint32(0, 0x1000, true);
  view.setUint32(4, 10, true);
  view.setUint16(8, 0x234, true);
  view.setUint32(10, 0x2000, true);
  view.setUint32(14, 20, true);
  const warnings: string[] = [];

  const parsed = parseGuardRf(view, 1n, 0, 0, 0, 22, warnings);

  assert.deepEqual(parsed?.sites, [{ rva: 0x1234, type: 0 }]);
  assert.ok(warnings.some(warning => warning.includes("block size")));
});

void test("Guard RF reports truncated header without reading past it", () => {
  const warnings: string[] = [];

  const parsed = parseGuardRf(new DataView(new Uint8Array([4, 0x90]).buffer),
    1n, 0, 2, 2, 2, warnings);

  assert.equal(parsed, null);
  assert.ok(warnings.some(warning => warning.includes("prologue bytes")));
});

void test("Guard RF rejects descriptor lengths outside the V2 header", () => {
  const view = new DataView(new ArrayBuffer(8));
  view.setUint8(5, 4);
  view.setUint16(6, 2, true);
  const warnings: string[] = [];

  assert.equal(parseGuardRf(view, 2n, 0, 8, 8, 8, warnings), null);
  assert.ok(warnings.some(warning => warning.includes("branch descriptors")));
});

void test("Guard RF rejects invalid spans and unsupported symbols", () => {
  const view = new DataView(new ArrayBuffer(8));
  const warnings: string[] = [];

  assert.equal(parseGuardRf(view, 1n, -1, 0, 0, 8, warnings), null);
  assert.equal(parseGuardRf(view, 99n, 0, 0, 0, 8, warnings), null);
  assert.ok(warnings.some(warning => warning.includes("bounds")));
  assert.ok(warnings.some(warning => warning.includes("unsupported symbol")));
});
