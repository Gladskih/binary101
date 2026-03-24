"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readSafeSehHandlerTableRvas } from "../../analyzers/pe/load-config-tables.js";
import { MockFile } from "../helpers/mock-file.js";

// Microsoft PE format documents 0x00400000 as the default ImageBase for Windows NT/2000/XP/95/98/Me EXE images.
const PE32_DEFAULT_IMAGE_BASE = 0x400000n;
// Small RVA used to place synthetic LOAD_CONFIG tables near the image start without overlapping test data.
const LOAD_CONFIG_TEST_TABLE_RVA = 0x80;

void test("readSafeSehHandlerTableRvas reads RVAs from a SafeSEH table storing handler RVAs", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x1000, true);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x1100, true);

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-rva.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2
  );
  assert.deepEqual(rvas, [0x1000, 0x1100]);
});

void test("readSafeSehHandlerTableRvas preserves handler RVAs that are numerically above ImageBase", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  // The SafeSEH table entries are RVAs, not VAs. Large images can legitimately have handler RVAs above ImageBase.
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x500000, true);

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-high-rva.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    1
  );

  assert.deepEqual(rvas, [0x500000]);
});

void test("readSafeSehHandlerTableRvas does not rewrite valid RVAs that happen to be near ImageBase", async () => {
  const imageBase = PE32_DEFAULT_IMAGE_BASE;
  const tableRva = Uint32Array.BYTES_PER_ELEMENT;
  const tableVa = imageBase + BigInt(tableRva);

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

void test("readSafeSehHandlerTableRvas keeps RVAs for low but legal image bases", async () => {
  // Microsoft PE format requires ImageBase to be a multiple of 64 K; 0x00010000 is the documented
  // Windows CE EXE default and exercises the old RVA-vs-VA confusion near the image start.
  const lowImageBase = 0x10000n;
  const tableVa = lowImageBase + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  // IMAGE_LOAD_CONFIG_DIRECTORY{32,64}.SEHandlerTable points to a table of RVAs, not VAs.
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x11000, true);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x12000, true);

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-low-imagebase-rva.bin"),
    rva => rva,
    lowImageBase,
    tableVa,
    2
  );

  assert.deepEqual(rvas, [0x11000, 0x12000]);
});

void test("readSafeSehHandlerTableRvas returns empty list for invalid or unmapped tables", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const file = new MockFile(bytes, "safeseh-invalid.bin");
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  assert.deepEqual(await readSafeSehHandlerTableRvas(file, rva => rva, PE32_DEFAULT_IMAGE_BASE, 0x1000n, 1), []);
  assert.deepEqual(await readSafeSehHandlerTableRvas(file, () => null, PE32_DEFAULT_IMAGE_BASE, tableVa, 1), []);
});

void test("readSafeSehHandlerTableRvas truncates reads when the table spills past EOF", async () => {
  const bytes = new Uint8Array(LOAD_CONFIG_TEST_TABLE_RVA + Uint32Array.BYTES_PER_ELEMENT).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x1000, true);
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  const rvas = await readSafeSehHandlerTableRvas(
    new MockFile(bytes, "safeseh-truncated.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    3
  );
  assert.deepEqual(rvas, [0x1000]);
});
