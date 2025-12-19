"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readGuardAddressTakenIatEntryTableRvas,
  readGuardEhContinuationTableRvas,
  readGuardLongJumpTargetTableRvas,
} from "../../analyzers/pe/load-config-tables.js";
import { readLoadConfigPointerRva } from "../../analyzers/pe/load-config.js";
import { MockFile } from "../helpers/mock-file.js";

void test("readLoadConfigPointerRva converts VA to RVA and rejects invalid values", () => {
  assert.equal(readLoadConfigPointerRva(0x400000, 0x401234), 0x1234);
  assert.equal(readLoadConfigPointerRva(0x400000, 0), null);
  assert.equal(readLoadConfigPointerRva(-1, 0x401234), null);
});

void test("readGuardEhContinuationTableRvas reads RVAs and truncates at EOF", async () => {
  const imageBase = 0x400000;
  const tableRva = 0x80;
  const tableVa = imageBase + tableRva;

  const bytes = new Uint8Array(0x88).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableRva + 0, 0x1000, true);
  dv.setUint32(tableRva + 4, 0x1100, true);

  assert.deepEqual(
    await readGuardEhContinuationTableRvas(new MockFile(bytes, "eh.bin"), rva => rva, imageBase, tableVa, 3),
    [0x1000, 0x1100]
  );
});

void test("readGuardEhContinuationTableRvas supports 5-byte entries when GuardFlags encodes a stride", async () => {
  const imageBase = 0x400000;
  const tableRva = 0x80;
  const tableVa = imageBase + tableRva;
  const guardFlags = 0x10000000;

  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableRva + 0, 0x1000, true);
  dv.setUint8(tableRva + 4, 0x00);
  dv.setUint32(tableRva + 5, 0x1100, true);
  dv.setUint8(tableRva + 9, 0x00);

  assert.deepEqual(
    await readGuardEhContinuationTableRvas(new MockFile(bytes, "eh-5b.bin"), rva => rva, imageBase, tableVa, 2, guardFlags),
    [0x1000, 0x1100]
  );
});

void test("Guard longjmp/address-taken IAT CFG tables return empty list for unmapped offsets", async () => {
  const imageBase = 0x400000;
  const tableRva = 0x80;
  const tableVa = imageBase + tableRva;
  const bytes = new Uint8Array(0x100).fill(0);
  const file = new MockFile(bytes, "unmapped.bin");

  assert.deepEqual(await readGuardLongJumpTargetTableRvas(file, () => null, imageBase, tableVa, 1), []);
  assert.deepEqual(await readGuardAddressTakenIatEntryTableRvas(file, () => null, imageBase, tableVa, 1), []);
});
