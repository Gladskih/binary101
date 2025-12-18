"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readSafeSehHandlerTableRvas } from "../../analyzers/pe/load-config.js";
import { MockFile } from "../helpers/mock-file.js";

void test("readSafeSehHandlerTableRvas reads RVAs from a SafeSEH table storing handler VAs", async () => {
  const imageBase = 0x400000;
  const tableRva = 0x80;
  const tableVa = imageBase + tableRva;

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableRva + 0, imageBase + 0x1000, true);
  dv.setUint32(tableRva + 4, imageBase + 0x1100, true);

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-va.bin"),
    rva => rva,
    imageBase,
    tableVa,
    2
  );
  assert.deepEqual(rvas, [0x1000, 0x1100]);
});

void test("readSafeSehHandlerTableRvas reads RVAs from a SafeSEH table storing handler RVAs", async () => {
  const imageBase = 0x400000;
  const tableRva = 0x80;
  const tableVa = imageBase + tableRva;

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableRva + 0, 0x1000, true);
  dv.setUint32(tableRva + 4, 0x1100, true);

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-rva.bin"),
    rva => rva,
    imageBase,
    tableVa,
    2
  );
  assert.deepEqual(rvas, [0x1000, 0x1100]);
});

void test("readSafeSehHandlerTableRvas returns empty list for invalid or unmapped tables", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const file = new MockFile(bytes, "safeseh-invalid.bin");

  assert.deepEqual(await readSafeSehHandlerTableRvas(file, rva => rva, 0x400000, 0x1000, 1), []);
  assert.deepEqual(await readSafeSehHandlerTableRvas(file, () => null, 0, 0x80, 1), []);
});

void test("readSafeSehHandlerTableRvas truncates reads when the table spills past EOF", async () => {
  const bytes = new Uint8Array(0x84).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0x80, 0x1000, true);

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-truncated.bin"),
    rva => rva,
    0,
    0x80,
    3
  );
  assert.deepEqual(rvas, [0x1000]);
});
