"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readGuardCFFunctionTableRvas } from "../../analyzers/pe/debug-loadcfg.js";
import { MockFile } from "../helpers/mock-file.js";

void test("readGuardCFFunctionTableRvas reads RVAs from the CFG function table", async () => {
  const imageBase = 0x400000;
  const tableRva = 0x80;
  const tableVa = imageBase + tableRva;

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableRva + 0, 0x1000, true);
  dv.setUint32(tableRva + 4, 0, true);
  dv.setUint32(tableRva + 8, 0x1100, true);
  dv.setUint32(tableRva + 12, 1, true);

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "guardcf.bin"),
    rva => rva,
    imageBase,
    tableVa,
    2
  );
  assert.deepEqual(rvas, [0x1000, 0x1100]);
});

void test("readGuardCFFunctionTableRvas returns empty list for invalid or unmapped tables", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const file = new MockFile(bytes, "guardcf-invalid.bin");

  assert.deepEqual(
    await readGuardCFFunctionTableRvas(file, rva => rva, 0x2000, 0x1000, 1),
    []
  );
  assert.deepEqual(
    await readGuardCFFunctionTableRvas(file, () => null, 0, 0x80, 1),
    []
  );
});

void test("readGuardCFFunctionTableRvas truncates reads when the table spills past EOF", async () => {
  const bytes = new Uint8Array(0x88).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0x80 + 0, 0x1000, true);
  dv.setUint32(0x80 + 4, 0, true);

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "guardcf-truncated.bin"),
    rva => rva,
    0,
    0x80,
    3
  );
  assert.deepEqual(rvas, [0x1000]);
});

