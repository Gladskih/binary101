"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseImportDirectory32,
  parseImportDirectory64
} from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
void test("parseImportDirectory reads import descriptors with names and ordinals", async () => {
  const bytes = new Uint8Array(1024).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 500;

  dv.setUint32(impBase + 0, 600, true);
  dv.setUint32(impBase + 12, 620, true);
  dv.setUint32(impBase + 16, 0, true);
  encoder.encodeInto("SHELL32.dll\0", new Uint8Array(bytes.buffer, 620));
  dv.setUint32(600, 700, true);
  dv.setUint32(604, 0x80000003, true);
  dv.setUint32(608, 0, true);
  dv.setUint16(700, 0x55aa, true);
  encoder.encodeInto("ImportX\0", new Uint8Array(bytes.buffer, 702));

  const { entries: imports } = await parseImportDirectory32(
    new MockFile(bytes, "imports.bin"),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value,
    () => {}
  );

  assert.equal(imports.length, 1);
  const firstImport = expectDefined(imports[0]);
  assert.equal(firstImport.dll, "SHELL32.dll");
  assert.equal(firstImport.functions.length, 2);
  assert.deepEqual(firstImport.functions[0], { hint: 0x55aa, name: "ImportX" });
  assert.deepEqual(firstImport.functions[1], { ordinal: 3 });
});

void test("parseImportDirectory reports warning on truncated thunk table", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x20;
  dv.setUint32(impBase + 12, 0x60, true);
  // The import lookup table starts four bytes before EOF, so a PE32+ thunk entry is physically truncated.
  // PE/COFF import thunk entries are 8 bytes in PE32+.
  dv.setUint32(impBase + 16, 0x7c, true);
  dv.setUint16(0x60, 0);
  dv.setUint32(0x7c, 0x12345678, true);

  const { entries, warning } = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value,
    () => {}
  );

  assert.ok(entries.length >= 0);
  assert.ok(warning && /truncated/i.test(warning));
});

void test("parseImportDirectory warns on unmapped name RVA", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x10;
  dv.setUint32(impBase + 12, 0x200, true);
  dv.setUint32(impBase + 16, 0, true);

  const { warning } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => (value < bytes.length ? value : null),
    () => {}
  );

  assert.ok(warning && /name rva/i.test(warning));
});

void test("parseImportDirectory warns when an import-by-name thunk points to an unmapped Hint/Name entry", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x10;
  const dllNameRva = 0x40;
  const thunkRva = 0x60;
  dv.setUint32(impBase + 0, thunkRva, true);
  dv.setUint32(impBase + 12, dllNameRva, true);
  encoder.encodeInto("KERNEL32.dll\0", new Uint8Array(bytes.buffer, dllNameRva));
  dv.setUint32(thunkRva, 0x200, true);
  dv.setUint32(thunkRva + 4, 0, true);

  const { entries, warning } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => (value < bytes.length ? value : null),
    () => {}
  );

  assert.deepEqual(entries[0]?.functions, [{ name: "<bad RVA>" }]);
  assert.ok(warning && /hint|name|rva/i.test(warning));
});

void test("parseImportDirectory warns when a mapped DLL name offset falls past EOF", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x10;
  dv.setUint32(impBase + 12, 0x40, true);

  const { warning } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    // The mapper accepts the descriptor itself but pushes the DLL name 0x200 bytes past a 128-byte file.
    value => (value === impBase ? impBase : value === 0 ? null : value + 0x200),
    () => {}
  );

  assert.ok(warning && /name rva/i.test(warning));
});

void test("parseImportDirectory warns on unmapped thunk RVA (x86)", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x10;
  dv.setUint32(impBase + 12, 0x40, true);
  dv.setUint32(impBase + 16, 0x200, true);
  encoder.encodeInto("KERNEL32.dll\0", new Uint8Array(bytes.buffer, 0x40));

  const { entries, warning } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => (value < bytes.length ? value : null),
    () => {}
  );

  assert.ok(entries.length >= 0);
  assert.ok(warning && /thunk rva/i.test(warning));
});

void test("parseImportDirectory aggregates multiple warnings", async () => {
  const bytes = new Uint8Array(64).fill(0);
  const impBase = 0x10;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(impBase + 12, 0x200, true);
  dv.setUint32(impBase + 16, 0x300, true);

  const { warning } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 16 }],
    value => (value < bytes.length ? value : null),
    () => {}
  );

  assert.ok(warning);
  assert.ok(/name rva/i.test(warning));
  assert.ok(/thunk rva/i.test(warning));
});

void test("parseImportDirectory does not decode a descriptor past the declared directory size", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x20;

  dv.setUint32(impBase + 0, 0x60, true);
  dv.setUint32(impBase + 12, 0x40, true);
  encoder.encodeInto("KERNEL32.dll\0", new Uint8Array(bytes.buffer, 0x40));
  dv.setUint32(0x60, 0x70, true);
  dv.setUint32(0x64, 0, true);
  dv.setUint16(0x70, 0x1234, true);
  encoder.encodeInto("Sleep\0", new Uint8Array(bytes.buffer, 0x72));

  const { entries, warning } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 16 }],
    value => value,
    () => {}
  );

  assert.equal(entries.length, 0);
  assert.ok(warning && /truncated|descriptor/i.test(warning));
});

void test("parseImportDirectory supports 64-bit imports path", async () => {
  const bytes = new Uint8Array(512).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x40;
  dv.setUint32(impBase + 0, 0, true);
  dv.setUint32(impBase + 12, 0x80, true);
  dv.setUint32(impBase + 16, 0x120, true);
  encoder.encodeInto("ADVAPI32.dll\0", new Uint8Array(bytes.buffer, 0x80));
  dv.setBigUint64(0x120 + 0, 0x180n, true);
  dv.setBigUint64(0x120 + 8, 0x8000000000000005n, true);
  dv.setBigUint64(0x120 + 16, 0n, true);
  dv.setUint16(0x180, 0x0077, true);
  encoder.encodeInto("RegOpenKey\0", new Uint8Array(bytes.buffer, 0x182));

  const { entries: imports } = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value,
    () => {}
  );

  assert.equal(imports.length, 1);
  const firstImport = expectDefined(imports[0]);
  assert.equal(firstImport.functions.length, 2);
  assert.deepEqual(firstImport.functions[0], { hint: 0x77, name: "RegOpenKey" });
  assert.deepEqual(firstImport.functions[1], { ordinal: 5 });
});

void test("parseImportDirectory warns when ordinal import thunks set reserved bits", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x20;
  dv.setUint32(impBase + 12, 0x40, true);
  dv.setUint32(impBase + 16, 0x80, true);
  encoder.encodeInto("KERNEL32.dll\0", new Uint8Array(bytes.buffer, 0x40));
  // PE/COFF import lookup table: when the ordinal flag is set in PE32, bits 30-15 must be zero.
  dv.setUint32(0x80, 0xffff0002, true);
  dv.setUint32(0x84, 0, true);

  const { warning } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value,
    () => {}
  );

  assert.ok(warning && /ordinal/i.test(warning));
});
