"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectELF, detectMachO } from "../../analyzers/format-detectors.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("detectELF returns formatted label for 64-bit little-endian executables", () => {
  const bytes = new Uint8Array(0x20).fill(0);
  bytes.set([0x7f, 0x45, 0x4c, 0x46], 0);
  bytes[4] = 2;
  bytes[5] = 1;
  const dv = dvFrom(bytes);
  dv.setUint16(0x10, 2, true);
  dv.setUint16(0x12, 0x3e, true);
  const label = detectELF(dv);
  assert.strictEqual(label, "ELF 64-bit LSB executable, x86-64");
});

void test("detectMachO differentiates 32-bit, 64-bit and fat", () => {
  assert.strictEqual(detectMachO(dvFrom([0xfe, 0xed, 0xfa, 0xce])), "Mach-O 32-bit");
  assert.strictEqual(detectMachO(dvFrom([0xfe, 0xed, 0xfa, 0xcf])), "Mach-O 64-bit");
  assert.strictEqual(detectMachO(dvFrom([0xca, 0xfe, 0xba, 0xbe])), "Mach-O universal (Fat)");
  assert.strictEqual(detectMachO(dvFrom([0x00, 0x01, 0x02, 0x03])), null);
});
