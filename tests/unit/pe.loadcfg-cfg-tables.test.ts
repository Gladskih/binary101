"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readGuardCFFunctionTableRvas,
  readGuardAddressTakenIatEntryTableRvas,
  readGuardEhContinuationTableRvas,
  readGuardLongJumpTargetTableRvas
} from "../../analyzers/pe/load-config-tables.js";
import { MockFile } from "../helpers/mock-file.js";

// Microsoft PE format documents 0x00400000 as the default ImageBase for Windows NT/2000/XP/95/98/Me EXE images.
const PE32_DEFAULT_IMAGE_BASE = 0x400000;
// Small RVA used to place synthetic LOAD_CONFIG tables near the image start without overlapping test data.
const LOAD_CONFIG_TEST_TABLE_RVA = 0x80;

// Microsoft PE format, GuardFlags:
// IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK uses bits 31-28 to encode the number of extra bytes per GFIDS entry.
// A stored nibble value of 1 therefore means a 5-byte entry (4-byte RVA + 1 metadata byte).
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE = 0x10000000;

void test("readGuardEhContinuationTableRvas reads RVAs and truncates at EOF", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + LOAD_CONFIG_TEST_TABLE_RVA;

  const bytes = new Uint8Array(0x88).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x1000, true);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x1100, true);

  assert.deepEqual(
    await readGuardEhContinuationTableRvas(
      new MockFile(bytes, "eh.bin"),
      rva => rva,
      PE32_DEFAULT_IMAGE_BASE,
      tableVa,
      3
    ),
    [0x1000, 0x1100]
  );
});

void test("readGuardEhContinuationTableRvas supports 5-byte entries when GuardFlags encodes a stride", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + LOAD_CONFIG_TEST_TABLE_RVA;
  const guardFlags = IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE;

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, 0x1000, true);
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x00);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 5, 0x1100, true);
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 9, 0x00);

  assert.deepEqual(
    await readGuardEhContinuationTableRvas(
      new MockFile(bytes, "eh-5b.bin"),
      rva => rva,
      PE32_DEFAULT_IMAGE_BASE,
      tableVa,
      2,
      guardFlags
    ),
    [0x1000, 0x1100]
  );
});

void test("Guard longjmp/address-taken IAT CFG tables return empty list for unmapped offsets", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + LOAD_CONFIG_TEST_TABLE_RVA;
  const bytes = new Uint8Array(0x100).fill(0);
  const file = new MockFile(bytes, "unmapped.bin");

  assert.deepEqual(
    await readGuardLongJumpTargetTableRvas(file, () => null, PE32_DEFAULT_IMAGE_BASE, tableVa, 1),
    []
  );
  assert.deepEqual(
    await readGuardAddressTakenIatEntryTableRvas(file, () => null, PE32_DEFAULT_IMAGE_BASE, tableVa, 1),
    []
  );
});

void test("readGuardCFFunctionTableRvas stops when later entries no longer map through rvaToOff", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + LOAD_CONFIG_TEST_TABLE_RVA;
  const bytes = new Uint8Array(8).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x1111, true);
  dv.setUint32(4, 0x2222, true);

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "cfg-gap.bin"),
    // Only the first table RVA is mapped; the second logical entry should not be read from a flat raw span.
    rva => (rva === LOAD_CONFIG_TEST_TABLE_RVA ? 0 : null),
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2
  );

  assert.deepEqual(rvas, [0x1111]);
});
