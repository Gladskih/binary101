"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeElf } from "../../analyzers/elf/probe.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("probeElf returns formatted label for 64-bit little-endian executables", () => {
  const bytes = new Uint8Array(0x20).fill(0);
  bytes.set([0x7f, 0x45, 0x4c, 0x46], 0);
  bytes[4] = 2;
  bytes[5] = 1;
  const dv = dvFrom(bytes);
  dv.setUint16(0x10, 2, true);
  dv.setUint16(0x12, 0x3e, true);
  assert.strictEqual(probeElf(dv), "ELF 64-bit LSB executable, x86-64");
});
