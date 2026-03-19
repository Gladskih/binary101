"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBoundImports, parseDelayImports } from "../../analyzers/pe/bound-delay.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const writeDelayImportDllName = (bytes: Uint8Array, view: DataView, descriptorOffset: number, nameRva: number): void => {
  view.setUint32(descriptorOffset + 4, nameRva, true);
  encoder.encodeInto("delay.dll\0", new Uint8Array(bytes.buffer, nameRva));
};

void test("parseDelayImports reads delay descriptors, names, and ordinals", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);

  const base = 64;
  // Delay import entry at offset 64.
  const dllNameOff = 300;
  const intOff = 200;
  const hintNameOff = 0x10;
  dv.setUint32(base + 0, 0, true); // PE/COFF delay-import descriptors store RVAs and this field must be 0.
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

void test("parseDelayImports warns when 32-bit thunk table truncates mid-entry", async () => {
  const bytes = new Uint8Array(0x54).fill(0);
  const dv = new DataView(bytes.buffer);
  const base = 0x10;
  const dllNameRva = 0x30;
  dv.setUint32(base + 0, 0, true);
  writeDelayImportDllName(bytes, dv, base, dllNameRva);
  dv.setUint32(base + 16, 0x50, true); // INT RVA points near end
  // First thunk is ordinal and fits; second thunk would be out of file.
  dv.setUint32(0x50, 0x80000002, true);

  const result = await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: base, size: 32 }],
    value => value,
    () => {},
    false,
    0
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  assert.ok(definedResult.warning?.toLowerCase().includes("thunk table truncated"));
});

void test("parseDelayImports tolerates truncated INT in 64-bit path", async () => {
  const bytes = new Uint8Array(0x54).fill(0); // only 4 bytes available after 0x50
  const dv = new DataView(bytes.buffer);
  const base = 0x10;
  const dllNameRva = 0x30;
  dv.setUint32(base + 0, 0, true);
  writeDelayImportDllName(bytes, dv, base, dllNameRva);
  dv.setUint32(base + 16, 0x50, true); // INT RVA points near end
  // Only 4 bytes available for a 64-bit thunk.
  dv.setUint32(0x50, 0xdeadbeef, true);

  const result = await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: base, size: 32 }],
    value => value,
    () => {},
    true,
    0
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.functions.length, 0);
  assert.ok(definedResult.warning?.toLowerCase().includes("thunk table truncated"));
});

void test("parseDelayImports handles an empty INT in the 32-bit path", async () => {
  const bytes = new Uint8Array(96).fill(0);
  const dv = new DataView(bytes.buffer);
  const base = 0x10;
  const dllNameRva = 0x30;
  dv.setUint32(base + 0, 0, true);
  writeDelayImportDllName(bytes, dv, base, dllNameRva);
  dv.setUint32(base + 16, 0x50, true); // INT RVA near end
  dv.setUint32(0x50, 0, true);

  const result = await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: base, size: 32 }],
    value => value,
    () => {},
    false,
    0
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.functions.length, 0);
  assert.equal(definedResult.warning, undefined);
});

void test("parseDelayImports handles truncated hint/name strings", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const base = 0x20;
  const dllNameRva = 0x40;
  dv.setUint32(base + 0, 0, true);
  writeDelayImportDllName(bytes, dv, base, dllNameRva);
  dv.setUint32(base + 16, 0x60, true); // INT RVA
  // INT entry points to hint/name near end of file; string is not null-terminated within buffer.
  dv.setUint32(0x60, 0x78, true);
  dv.setUint16(0x78, 0x7f7f, true);
  // Fill rest with non-zero bytes to avoid early NUL.
  bytes.fill(0x41, 0x7a);

  const result = await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: base, size: 32 }],
    value => value,
    () => {},
    false,
    0
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  const entryFn = expectDefined(definedResult.entries[0]);
  assert.ok(entryFn.functions.length >= 1);
  const firstFn = expectDefined(entryFn.functions[0]);
  assert.ok(typeof firstFn.name === "string");
  assert.ok(definedResult.warning?.toLowerCase().includes("name string truncated"));
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

void test("parseBoundImports stops on truncated descriptor", async () => {
  const base = 16;
  const bytes = new Uint8Array(18).fill(0); // less than one full descriptor
  const result = await parseBoundImports(
    new MockFile(bytes),
    [{ name: "BOUND_IMPORT", rva: base, size: 8 }],
    value => value,
    () => {}
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 0);
  assert.ok(definedResult.warning?.toLowerCase().includes("truncated"));
});

void test("parseBoundImports handles name offset outside directory", async () => {
  const base = 32;
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(base + 0, 0x11111111, true);
  dv.setUint16(base + 4, 0x80, true); // offset beyond directory size
  dv.setUint16(base + 6, 0, true);

  const result = await parseBoundImports(
    new MockFile(bytes),
    [{ name: "BOUND_IMPORT", rva: base, size: 16 }],
    value => value,
    () => {}
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 1);
  assert.equal(definedResult.entries[0]?.name, "");
  assert.ok(definedResult.warning?.toLowerCase().includes("name offset"));
});

void test("parseBoundImports skips over forwarder refs before the next descriptor", async () => {
  const base = 0x40;
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(base + 0, 0x11111111, true);
  dv.setUint16(base + 4, 0x30, true);
  dv.setUint16(base + 6, 1, true);

  dv.setUint32(base + 8, 0x22222222, true);
  dv.setUint16(base + 12, 0x40, true);
  dv.setUint16(base + 14, 0, true);

  dv.setUint32(base + 16, 0x33333333, true);
  dv.setUint16(base + 20, 0x50, true);
  dv.setUint16(base + 22, 0, true);

  encoder.encodeInto("KERNEL32.dll\0", new Uint8Array(bytes.buffer, base + 0x30));
  encoder.encodeInto("NTDLL.dll\0", new Uint8Array(bytes.buffer, base + 0x40));
  encoder.encodeInto("USER32.dll\0", new Uint8Array(bytes.buffer, base + 0x50));

  const result = await parseBoundImports(
    new MockFile(bytes),
    [{ name: "BOUND_IMPORT", rva: base, size: 96 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.deepEqual(
    definedResult.entries.map(entry => entry.name),
    ["KERNEL32.dll", "USER32.dll"]
  );
});

void test("parseDelayImports treats descriptor fields as RVA when Attributes is zero", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);

  const base = 0x40;
  const dllNameRva = 0x120;
  const intRva = 0x160;
  const hintNameRva = 0x1a0;

  dv.setUint32(base + 0, 0, true);
  dv.setUint32(base + 4, dllNameRva, true);
  dv.setUint32(base + 16, intRva, true);

  dv.setUint32(intRva + 0, hintNameRva, true);
  dv.setUint32(intRva + 4, 0, true);

  dv.setUint16(hintNameRva, 0x10, true);
  encoder.encodeInto("Func\0", new Uint8Array(bytes.buffer, hintNameRva + 2));
  encoder.encodeInto("kernel32.dll\0", new Uint8Array(bytes.buffer, dllNameRva));

  const result = await parseDelayImports(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: base, size: 32 }],
    value => value,
    () => {},
    false,
    0x400000
  );

  const definedResult = expectDefined(result);
  const entry = expectDefined(definedResult.entries[0]);
  assert.deepEqual(entry.functions, [{ hint: 0x10, name: "Func" }]);
});
