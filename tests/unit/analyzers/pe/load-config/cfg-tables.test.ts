"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readGuardCFFunctionTable,
  readGuardCFFunctionTableRvas,
  readGuardAddressTakenIatEntryTableRvas,
  readGuardEhContinuationTableRvas,
  readGuardLongJumpTargetTable,
  readGuardLongJumpTargetTableRvas
} from "../../../../../analyzers/pe/load-config/tables.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Microsoft PE format documents 0x00400000 as the default ImageBase for Windows NT/2000/XP/95/98/Me EXE images.
const PE32_DEFAULT_IMAGE_BASE = 0x400000n;
// Small RVA used to place synthetic LOAD_CONFIG tables near the image start without overlapping test data.
const LOAD_CONFIG_TEST_TABLE_RVA = 0x80;
// Synthetic CFG targets are 16-byte aligned because these tables identify valid control-flow targets.
const FIRST_CFG_TARGET_RVA = 0x1000;
const SECOND_CFG_TARGET_RVA = 0x1100;

// Microsoft PE format, GuardFlags:
// IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK uses bits 31-28 to encode the number of extra bytes per GFIDS entry.
// A stored nibble value of 1 therefore means a 5-byte entry (4-byte RVA + 1 metadata byte).
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE = 0x10000000;

void test("readGuardEhContinuationTableRvas reads RVAs and truncates at EOF", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  const bytes = new Uint8Array(0x88).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, FIRST_CFG_TARGET_RVA, true);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 4, SECOND_CFG_TARGET_RVA, true);

  assert.deepEqual(
    await readGuardEhContinuationTableRvas(
      new MockFile(bytes, "eh.bin"),
      rva => rva,
      PE32_DEFAULT_IMAGE_BASE,
      tableVa,
      3
    ),
    [FIRST_CFG_TARGET_RVA, SECOND_CFG_TARGET_RVA]
  );
});

void test("readGuardEhContinuationTableRvas supports 5-byte entries when GuardFlags encodes a stride", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, FIRST_CFG_TARGET_RVA, true);
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x00);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 5, SECOND_CFG_TARGET_RVA, true);
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 9, 0x00);

  assert.deepEqual(
    await readGuardEhContinuationTableRvas(
      new MockFile(bytes, "eh-5b.bin"),
      rva => rva,
      PE32_DEFAULT_IMAGE_BASE,
      tableVa,
      2,
      IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE
    ),
    [FIRST_CFG_TARGET_RVA, SECOND_CFG_TARGET_RVA]
  );
});

void test("readGuardCFFunctionTable decodes all documented GFIDS metadata flags", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);
  const bytes = new Uint8Array(0x200).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, FIRST_CFG_TARGET_RVA, true);
  // Windows SDK winnt.h: bits 0-3 name the four current GFIDS entry flags.
  view.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x0f);

  const table = await readGuardCFFunctionTable(
    new MockFile(bytes, "gfids-flags.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    1,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE
  );

  assert.deepEqual(table.entries[0]?.gfidsFlags, [
    "FID_SUPPRESSED",
    "EXPORT_SUPPRESSED",
    "FID_LANGEXCPTHANDLER",
    "FID_XFG"
  ]);
});

void test("readGuardLongJumpTargetTable marks truncated structured tables", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);
  const bytes = new Uint8Array(LOAD_CONFIG_TEST_TABLE_RVA + Uint32Array.BYTES_PER_ELEMENT).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, FIRST_CFG_TARGET_RVA, true);

  const table = await readGuardLongJumpTargetTable(
    new MockFile(bytes, "longjmp-truncated.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2
  );

  assert.equal(table.truncated, true);
  assert.equal(table.entries.length, 1);
  assert.ok(table.warnings?.some(warning => warning.includes("entry 1")));
});

void test("Guard longjmp/address-taken IAT CFG tables return empty list for unmapped offsets", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);
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
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);
  const bytes = new Uint8Array(8).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x1111, true); // Distinct sentinel target for the only mapped table entry.
  dv.setUint32(4, 0x2222, true); // Distinct sentinel target that must not be read through a gap.

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "cfg-gap.bin"),
    // Only the first four-byte entry is mapped; the second must not be read from a flat raw span.
    rva => (rva >= LOAD_CONFIG_TEST_TABLE_RVA && rva < LOAD_CONFIG_TEST_TABLE_RVA + 4
      ? rva - LOAD_CONFIG_TEST_TABLE_RVA
      : null),
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2
  );

  assert.deepEqual(rvas, [0x1111]);
});

void test("readGuardCFFunctionTableRvas follows an entry across noncontiguous raw sections", async () => {
  const bytes = new Uint8Array(0x20);
  // Microsoft PE metadata defines the leading GFIDS field as one four-byte RVA.
  bytes.set([0x78, 0x56], 0);
  bytes.set([0x34, 0x12], 0x10);
  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "cfg-section-split.bin"),
    rva => rva < LOAD_CONFIG_TEST_TABLE_RVA + 2
      ? rva - LOAD_CONFIG_TEST_TABLE_RVA
      : 0x10 + rva - LOAD_CONFIG_TEST_TABLE_RVA - 2,
    PE32_DEFAULT_IMAGE_BASE,
    PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA),
    1
  );
  assert.deepEqual(rvas, [0x12345678]);
});
