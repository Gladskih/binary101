"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readGuardCFFunctionTable,
  readGuardCFFunctionTableRvas
} from "../../../../../analyzers/pe/load-config/tables.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Microsoft PE format documents 0x00400000 as the default ImageBase for Windows NT/2000/XP/95/98/Me EXE images.
const PE32_DEFAULT_IMAGE_BASE = 0x400000n;
// Small RVA used to place synthetic LOAD_CONFIG tables near the image start without overlapping test data.
const LOAD_CONFIG_TEST_TABLE_RVA = 0x80;
// Synthetic CFG targets are 16-byte aligned because GFIDS entries normally identify function starts.
const FIRST_CFG_TARGET_RVA = 0x1000;
const SECOND_CFG_TARGET_RVA = 0x1100;

// Microsoft PE format, GuardFlags:
// IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK uses bits 31-28 to encode the number of extra bytes per GFIDS entry.
// A stored nibble value of 1 therefore means a 5-byte entry (4-byte RVA + 1 metadata byte).
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE = 0x10000000;

void test("readGuardCFFunctionTableRvas reads RVAs from the CFG function table", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, FIRST_CFG_TARGET_RVA, true);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 4, SECOND_CFG_TARGET_RVA, true);

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "guardcf.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2
  );
  assert.deepEqual(rvas, [FIRST_CFG_TARGET_RVA, SECOND_CFG_TARGET_RVA]);
});

void test("readGuardCFFunctionTableRvas supports 5-byte GFIDS entries when GuardFlags encodes a stride", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, FIRST_CFG_TARGET_RVA, true);
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x7f); // Non-zero metadata byte; RVA-only reader ignores it.
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 5, SECOND_CFG_TARGET_RVA, true);
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 9, 0x01); // Non-zero metadata byte; RVA-only reader ignores it.

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "guardcf-5b.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE
  );
  assert.deepEqual(rvas, [FIRST_CFG_TARGET_RVA, SECOND_CFG_TARGET_RVA]);
});

void test("readGuardCFFunctionTable preserves metadata bytes and decodes GFIDS flags", async () => {
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, FIRST_CFG_TARGET_RVA, true);
  // Microsoft CFG metadata documents bit 0 as FID_SUPPRESSED and bit 1 as EXPORT_SUPPRESSED.
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 4, 0x03);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA + 5, SECOND_CFG_TARGET_RVA, true);
  // Windows SDK defines bit 2 as FID_LANGEXCPTHANDLER; only bit 7 stays unknown.
  dv.setUint8(LOAD_CONFIG_TEST_TABLE_RVA + 9, 0x84);

  const table = await readGuardCFFunctionTable(
    new MockFile(bytes, "gfids.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    2,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_5_BYTE_STRIDE
  );
  assert.equal(table.entrySize, 5);
  assert.deepEqual(table.entries.map(entry => entry.rva), [FIRST_CFG_TARGET_RVA, SECOND_CFG_TARGET_RVA]);
  assert.deepEqual(table.entries[0]?.metadataBytes, [0x03]);
  assert.deepEqual(table.entries[0]?.gfidsFlags, ["FID_SUPPRESSED", "EXPORT_SUPPRESSED"]);
  assert.deepEqual(table.entries[1]?.gfidsFlags, ["FID_LANGEXCPTHANDLER"]);
  assert.equal(table.entries[1]?.unknownGfidsFlagBits, 0x80);
});

void test("readGuardCFFunctionTableRvas returns empty list for invalid or unmapped tables", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const file = new MockFile(bytes, "guardcf-invalid.bin");
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  assert.deepEqual(
    await readGuardCFFunctionTableRvas(file, rva => rva, 0x2000n, 0x1000n, 1),
    []
  );
  assert.deepEqual(
    await readGuardCFFunctionTableRvas(file, () => null, PE32_DEFAULT_IMAGE_BASE, tableVa, 1),
    []
  );
});

void test("readGuardCFFunctionTableRvas truncates reads when the table spills past EOF", async () => {
  const bytes = new Uint8Array(LOAD_CONFIG_TEST_TABLE_RVA + Uint32Array.BYTES_PER_ELEMENT).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(LOAD_CONFIG_TEST_TABLE_RVA, FIRST_CFG_TARGET_RVA, true);
  const tableVa = PE32_DEFAULT_IMAGE_BASE + BigInt(LOAD_CONFIG_TEST_TABLE_RVA);

  const rvas = await readGuardCFFunctionTableRvas(
    new MockFile(bytes, "guardcf-truncated.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    tableVa,
    3
  );
  assert.deepEqual(rvas, [FIRST_CFG_TARGET_RVA]);
});

void test("readGuardCFFunctionTable reports an invalid VA as a truncated structured table", async () => {
  const table = await readGuardCFFunctionTable(
    new MockFile(new Uint8Array(0x200), "bad-va.bin"),
    rva => rva,
    PE32_DEFAULT_IMAGE_BASE,
    0x1000n,
    1
  );
  assert.equal(table.truncated, true);
  assert.equal(table.entries.length, 0);
  assert.ok(table.warnings?.some(warning => warning.includes("not a valid VA")));
});
