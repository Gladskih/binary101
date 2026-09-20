"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeElf } from "../../../../analyzers/elf/probe.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("probeElf labels ET_EXEC explicitly and keeps ET_DYN generic", () => {
  const bytes = new Uint8Array(0x20).fill(0);
  bytes.set([0x7f, 0x45, 0x4c, 0x46], 0);
  bytes[4] = 2;
  bytes[5] = 1;
  const dv = dvFrom(bytes);
  dv.setUint16(0x10, 2, true);
  dv.setUint16(0x12, 0x3e, true);
  assert.strictEqual(probeElf(dv), "ELF 64-bit LSB executable, x86-64");
  // gABI ELF Header, e_type: ET_DYN=3 does not distinguish a shared library from PIE.
  // https://gabi.xinuos.com/elf/02-eheader.html
  dv.setUint16(0x10, 3, true);
  assert.strictEqual(probeElf(dv), "ELF 64-bit LSB, x86-64");
  // ET_REL=1 and ET_NONE=0 keep their existing, unambiguous descriptions.
  dv.setUint16(0x10, 1, true);
  assert.strictEqual(probeElf(dv), "ELF 64-bit LSB relocatable, x86-64");
  dv.setUint16(0x10, 0, true);
  assert.strictEqual(probeElf(dv), "ELF 64-bit LSB type=0, x86-64");
});
