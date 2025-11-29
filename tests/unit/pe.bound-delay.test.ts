"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBoundImports, parseDelayImports } from "../../analyzers/pe/bound-delay.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();

void test("parseDelayImports reads delay descriptors, names, and ordinals", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);

  const base = 64;
  // Delay import entry at offset 64.
  const dllNameOff = 300;
  const intOff = 200;
  const hintNameOff = 0x10;
  dv.setUint32(base + 0, 1, true); // Attributes (RVA)
  dv.setUint32(base + 4, dllNameOff, true);
  dv.setUint32(base + 12, 0, true); // IAT RVA
  dv.setUint32(base + 16, intOff, true); // INT RVA
  dv.setUint32(base + 20, 0, true); // bound IAT
  dv.setUint32(base + 24, 0, true); // unload info
  dv.setUint32(base + 28, 0x12345678, true); // timestamp

  // Import name table: named then ordinal then terminator.
  dv.setUint32(intOff + 0, hintNameOff, true);
  dv.setUint32(intOff + 4, 0x80000002, true);
  dv.setUint32(intOff + 8, 0, true);

  // Hint/name entry.
  dv.setUint16(hintNameOff, 0x1234, true);
  encoder.encodeInto("Func\0", new Uint8Array(bytes.buffer, hintNameOff + 2));

  // DLL name.
  encoder.encodeInto("kernel32.dll\0", new Uint8Array(bytes.buffer, dllNameOff));

  const file = new MockFile(bytes, "delay-imports.bin");
  const addCoverageRegions = [];
  const result = await parseDelayImports(
    file,
    [{ name: "DELAY_IMPORT", rva: base, size: 32 }],
    value => value,
    (label, start, size) => addCoverageRegions.push({ label, start, size }),
    false,
    0
  );

  const definedResult = expectDefined(result);
  assert.equal(addCoverageRegions.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.name, "kernel32.dll");
  assert.equal(entry.TimeDateStamp, 0x12345678);
  assert.equal(entry.functions.length, 2);
  assert.deepEqual(entry.functions[0], { hint: 0x1234, name: "Func" });
  assert.deepEqual(entry.functions[1], { ordinal: 2 });
});

void test("parseDelayImports stops on truncated thunk table without throwing", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const base = 16;
  dv.setUint32(base + 0, 1, true); // Attributes (RVA)
  dv.setUint32(base + 16, 0x70, true); // INT RVA points near end
  // Only 4 bytes of INT available, less than 8 needed for 64-bit thunk.
  dv.setUint32(0x70, 0x12345678, true);

  const result = await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: base, size: 32 }],
    value => value,
    () => {},
    true,
    0
  );
  const definedResult = expectDefined(result);
  assert.ok(definedResult.entries.length >= 0);
});

void test("parseBoundImports extracts bound import names", async () => {
  const base = 400;
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  // Entry 0
  dv.setUint32(base + 0, 0x01020304, true);
  dv.setUint16(base + 4, 32, true); // name at base+32
  dv.setUint16(base + 6, 0, true);
  // Terminator entry of zeros follows automatically.
  encoder.encodeInto("USER32.dll\0", new Uint8Array(bytes.buffer, base + 32));

  const file = new MockFile(bytes, "bound-imports.bin");
  const result = await parseBoundImports(
    file,
    [{ name: "BOUND_IMPORT", rva: base, size: 64 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.name, "USER32.dll");
  assert.equal(entry.TimeDateStamp, 0x01020304);
});
