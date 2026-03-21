"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readGuardCFFunctionTableRvas } from "../../analyzers/pe/load-config-tables.js";
import { MockFile } from "../helpers/mock-file.js";

// Microsoft PE format documents 0x00400000 as the default ImageBase for Windows NT/2000/XP/95/98/Me EXE images.
const PE32_DEFAULT_IMAGE_BASE = 0x400000;
// Small RVA used to place synthetic LOAD_CONFIG tables near the image start without overlapping test data.
const LOAD_CONFIG_TEST_TABLE_RVA = 0x80;

// Microsoft PE format, GuardFlags:
// IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK uses bits 31-28 to encode the number of extra bytes per GFIDS entry.
// A stored nibble value of 1 therefore means a 5-byte entry (4-byte RVA + 1 metadata byte).
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE = 0x10000000;

void test("readGuardCFFunctionTableRvas reads RVAs from the CFG function table", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + LOAD_CONFIG_TEST_TABLE_RVA;

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x1000, true);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x1100, true);

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "guardcf.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2
  );
  assert.deepEqual(rvas, [0x1000, 0x1100]);
});

void test("readGuardCFFunctionTableRvas supports 5-byte GFIDS entries when GuardFlags encodes a stride", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + LOAD_CONFIG_TEST_TABLE_RVA;
  const guardFlags = IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE;

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x1000, true);
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x7f); // metadata byte (ignored)
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 5, 0x1100, true);
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 9, 0x01); // metadata byte (ignored)

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "guardcf-5b.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2,
    guardFlags
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
    await readGuardCFFunctionTableRvas(file, () => null, 0, LOAD_CONFIG_TEST_TABLE_RVA, 1),
    []
  );
});

void test("readGuardCFFunctionTableRvas truncates reads when the table spills past EOF", async () => {
  const bytes = new Uint8Array(LOAD_CONFIG_TEST_TABLE_RVA + Uint32Array.BYTES_PER_ELEMENT).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x1000, true);

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "guardcf-truncated.bin"),
    rva => rva,
    0,
    LOAD_CONFIG_TEST_TABLE_RVA,
    3
  );
  assert.deepEqual(rvas, [0x1000]);
});
