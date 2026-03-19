"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readSafeSehHandlerTableRvas } from "../../analyzers/pe/load-config-tables.js";
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

void test("readSafeSehHandlerTableRvas preserves handler RVAs that are numerically above ImageBase", async () => {
  const imageBase = 0x400000;
  const tableRva = 0x80;
  const tableVa = imageBase + tableRva;

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  // The SafeSEH table entries are RVAs, not VAs. Large images can legitimately have handler RVAs above ImageBase.
  dv.setUint32(tableRva + 0, 0x500000, true);

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-high-rva.bin"),
    rva => rva,
    imageBase,
    tableVa,
    1
  );

  assert.deepEqual(rvas, [0x500000]);
});

void test("readSafeSehHandlerTableRvas does not rewrite valid RVAs that happen to be near ImageBase", async () => {
  const imageBase = 0x400000;
  const tableRva = Uint32Array.BYTES_PER_ELEMENT;
  const tableVa = imageBase + tableRva;

  const bytes = new Uint8Array(tableRva + Uint32Array.BYTES_PER_ELEMENT).fill(0);
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format, Load Configuration Directory:
  // SEHandlerTable points to a table of RVAs, not VAs.
  dv.setUint32(tableRva, 0x450000, true); // Only 0x50000 above ImageBase, so VA-subtraction heuristics corrupt it.

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-near-imagebase-rva.bin"),
    rva => rva,
    imageBase,
    tableVa,
    1
  );

  assert.deepEqual(rvas, [0x450000]);
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
