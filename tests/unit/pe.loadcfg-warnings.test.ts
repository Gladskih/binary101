"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseLoadConfigDirectory32,
  parseLoadConfigDirectory64
} from "../../analyzers/pe/load-config.js";
import { collectLoadConfigWarnings } from "../../analyzers/pe/load-config-warnings.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("collectLoadConfigWarnings reports tables that do not fit in file/image bounds", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  const lcRva = 0x80;

  dv.setUint32(lcRva + 0x00, 0xc0, true); // Size
  dv.setUint32(lcRva + 0x50, 0x1f4, true); // GuardCFFunctionTable
  dv.setUint32(lcRva + 0x54, 4, true); // GuardCFFunctionCount

  const file = new MockFile(bytes, "loadcfg-warn.bin");
  const lc = expectDefined(
    await parseLoadConfigDirectory32(
      file,
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0xc0 }],
      value => value,
      () => {}
    )
  );

  assert.equal(lc.GuardCFFunctionCount, 4);
  const warnings = collectLoadConfigWarnings(file.size, value => value, 0x400000n, 0x200, lc);
  assert.ok(warnings.some(w => w.includes("GuardCFFunctionTable")));
});

void test("collectLoadConfigWarnings reports tables that start outside SizeOfImage even when raw bytes exist", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const dv = new DataView(bytes.buffer);
  const lcRva = 0x80;
  const imageBase = 0x400000n;

  dv.setUint32(lcRva + 0x00, 0xc0, true);
  // GuardCFFunctionTable is a VA. This points at RVA 0x300, which is outside SizeOfImage=0x200 below
  // while still mapping to raw bytes in the file.
  dv.setUint32(lcRva + 0x50, Number(imageBase + 0x300n), true);
  dv.setUint32(lcRva + 0x54, 1, true);

  const lc = expectDefined(
    await parseLoadConfigDirectory32(
      new MockFile(bytes, "loadcfg-sizeofimage.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0xc0 }],
      value => value,
      () => {}
    )
  );

  const warnings = collectLoadConfigWarnings(bytes.length, value => value, imageBase, 0x200, lc);
  assert.ok(warnings.some(w => /GuardCFFunctionTable/.test(w) && /SizeOfImage/.test(w)));
});

void test("collectLoadConfigWarnings rejects raw RVAs in documented VA table-pointer fields", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  const lcRva = 0x80;

  dv.setUint32(lcRva + 0x00, 0xc0, true);
  // PE format documents GuardCFFunctionTable as a VA to a table of RVAs, not a raw RVA itself.
  dv.setUint32(lcRva + 0x50, 0x40, true);
  dv.setUint32(lcRva + 0x54, 1, true);

  const lc = expectDefined(
    await parseLoadConfigDirectory32(
      new MockFile(bytes, "loadcfg-raw-rva-pointer.bin"),
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0xc0 }],
      value => value,
      () => {}
    )
  );

  const warnings = collectLoadConfigWarnings(
    bytes.length,
    value => value,
    0x400000n,
    bytes.length,
    lc
  );
  assert.ok(warnings.some(w => /GuardCFFunctionTable/.test(w) && /not a valid VA/.test(w)));
});

void test("collectLoadConfigWarnings rejects raw RVAs in documented VA pointer fields", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  const lcRva = 0x20;

  dv.setUint32(lcRva + 0x00, 0x148, true);
  // PE format documents VolatileMetadataPointer as a VA, so a raw RVA below ImageBase is malformed.
  dv.setBigUint64(lcRva + 0x100, 0x120n, true);

  const file = new MockFile(bytes, "loadcfg-raw-rva-volatile.bin");
  const lc = expectDefined(
    await parseLoadConfigDirectory64(
      file,
      [{ name: "LOAD_CONFIG", rva: lcRva, size: 0x148 }],
      value => value,
      () => {}
    )
  );

  const warnings = collectLoadConfigWarnings(
    file.size,
    value => value,
    0x400000n,
    file.size,
    lc
  );
  assert.ok(warnings.some(w => /VolatileMetadataPointer/.test(w) && /not a valid VA/.test(w)));
});
