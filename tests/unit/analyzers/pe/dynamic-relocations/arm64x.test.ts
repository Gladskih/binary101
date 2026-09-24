"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseArm64xFixups } from "../../../../../analyzers/pe/dynamic-relocations/arm64x.js";

void test("ARM64X decodes zero fill, value and signed delta records", () => {
  const view = new DataView(new ArrayBuffer(24));
  view.setUint32(0, 0x2000, true);
  view.setUint32(4, 24, true);
  view.setUint16(8, 0x8800, true); // Zero fill of four bytes at offset 0x800.
  view.setUint16(10, 0x5004, true); // Value of two bytes at page offset 4.
  view.setUint16(12, 0xbeef, true);
  view.setUint16(14, 0x6008, true); // Negative delta, scaled by four.
  view.setUint16(16, 3, true);
  view.setUint16(18, 0xa00c, true); // Positive delta, scaled by eight.
  view.setUint16(20, 2, true);
  view.setUint16(22, 0x400e, true); // Zero fill of two bytes.
  const warnings: string[] = [];

  const fixups = parseArm64xFixups(view, 0, 24, warnings);

  assert.deepEqual(fixups, [
    { kind: "zeroFill", rva: 0x2800, size: 4 },
    { kind: "value", rva: 0x2004, size: 2, value: 0xbeefn },
    { kind: "delta", rva: 0x2008, delta: -12 },
    { kind: "delta", rva: 0x200c, delta: 16 },
    { kind: "zeroFill", rva: 0x200e, size: 2 }
  ]);
  assert.deepEqual(warnings, []);
});

void test("ARM64X stops at a truncated value and keeps prior fixups", () => {
  const view = new DataView(new ArrayBuffer(12));
  view.setUint32(0, 0x1000, true);
  view.setUint32(4, 12, true);
  view.setUint16(8, 0x100, true);
  view.setUint16(10, 0xd008, true); // Eight-byte value without bytes.
  const warnings: string[] = [];

  const fixups = parseArm64xFixups(view, 0, 12, warnings);

  assert.deepEqual(fixups, [{ kind: "zeroFill", rva: 0x1100, size: 1 }]);
  assert.ok(warnings.some(warning => warning.includes("truncated")));
});

void test("ARM64X rejects malformed blocks and records warnings", () => {
  const view = new DataView(new ArrayBuffer(8));
  view.setUint32(0, 0x123, true);
  view.setUint32(4, 8, true);
  const warnings: string[] = [];

  assert.deepEqual(parseArm64xFixups(view, 0, 8, warnings), []);
  assert.ok(warnings.some(warning => warning.includes("page RVA")));
});

void test("ARM64X decodes eight-byte values without losing precision", () => {
  const view = new DataView(new ArrayBuffer(20));
  view.setUint32(0, 0x4000, true);
  view.setUint32(4, 20, true);
  view.setUint16(8, 0xd008, true); // Eight-byte value at aligned offset 8.
  view.setBigUint64(10, 0xfedcba9876543210n, true);
  const warnings: string[] = [];

  assert.deepEqual(parseArm64xFixups(view, 0, 20, warnings),
    [{ kind: "value", rva: 0x4008, size: 8, value: 0xfedcba9876543210n }]);
  assert.deepEqual(warnings, []);
});

void test("ARM64X rejects unsupported record types and unsafe spans", () => {
  const view = new DataView(new ArrayBuffer(12));
  view.setUint32(0, 0x1000, true);
  view.setUint32(4, 12, true);
  view.setUint16(8, 0x3004, true); // Reserved type 3.
  const warnings: string[] = [];

  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings), []);
  assert.deepEqual(parseArm64xFixups(view, -1, 12, warnings), []);
  assert.ok(warnings.some(warning => warning.includes("invalid fixup record")));
  assert.ok(warnings.some(warning => warning.includes("bounds")));
});

void test("ARM64X reports an incomplete block header", () => {
  const warnings: string[] = [];

  assert.deepEqual(parseArm64xFixups(new DataView(new ArrayBuffer(4)), 0, 4, warnings), []);
  assert.ok(warnings.some(warning => warning.includes("truncated block header")));
});

void test("ARM64X rejects an invalid block size and unaligned fixup RVA", () => {
  const view = new DataView(new ArrayBuffer(12));
  view.setUint32(0, 0x1000, true);
  view.setUint32(4, 8, true);
  const warnings: string[] = [];
  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings), []);
  assert.ok(warnings.some(warning => warning.includes("block size")));

  view.setUint32(4, 12, true);
  view.setUint16(8, 0x4101, true); // Two-byte zero fill at odd RVA.
  warnings.length = 0;
  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings), []);
  assert.ok(warnings.some(warning => warning.includes("unaligned fixup RVA")));
});

void test("ARM64X rejects an unaligned delta and a truncated delta", () => {
  const view = new DataView(new ArrayBuffer(12));
  view.setUint32(0, 0x1000, true);
  view.setUint32(4, 12, true);
  view.setUint16(8, 0x2002, true); // DELTA writes a 4-byte word.
  view.setUint16(10, 1, true);
  const warnings: string[] = [];

  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings), []);
  assert.ok(warnings.some(warning => warning.includes("unaligned fixup RVA")));

  view.setUint16(8, 0x100, true);
  view.setUint16(10, 0x2000, true);
  warnings.length = 0;
  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings),
    [{ kind: "zeroFill", rva: 0x1100, size: 1 }]);
  assert.ok(warnings.some(warning => warning.includes("truncated fixup value")));
});

void test("ARM64X rejects zero terminators and zero-width value fixups", () => {
  const view = new DataView(new ArrayBuffer(12));
  view.setUint32(0, 0x1000, true);
  view.setUint32(4, 12, true);
  const warnings: string[] = [];

  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings), []);
  assert.ok(warnings.some(warning => warning.includes("terminator")));

  view.setUint16(8, 0x1000, true); // VALUE with reserved size argument zero.
  warnings.length = 0;
  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings), []);
  assert.ok(warnings.some(warning => warning.includes("invalid fixup")));
});

void test("ARM64X validates all block size constraints", () => {
  const view = new DataView(new ArrayBuffer(12));
  view.setUint32(0, 0x1000, true);
  const warnings: string[] = [];

  view.setUint32(4, 10, true);
  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings), []);
  view.setUint32(4, 16, true);
  assert.deepEqual(parseArm64xFixups(view, 0, 12, warnings), []);

  assert.equal(warnings.filter(warning => warning.includes("block size")).length, 2);
});

void test("ARM64X validates all payload bounds", () => {
  const view = new DataView(new ArrayBuffer(8));
  const warnings: string[] = [];

  assert.deepEqual(parseArm64xFixups(view, 0, 9, warnings), []);
  assert.deepEqual(parseArm64xFixups(view, 4, 3, warnings), []);
  assert.deepEqual(parseArm64xFixups(view, 0.5, 8, warnings), []);
  assert.deepEqual(parseArm64xFixups(view, 0, -1, warnings), []);

  assert.equal(warnings.length, 4);
});
