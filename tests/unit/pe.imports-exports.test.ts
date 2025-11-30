"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExportDirectory } from "../../analyzers/pe/exports.js";
import { parseImportDirectory } from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();

void test("parseExportDirectory extracts names and forwarders", async () => {
  const bytes = new Uint8Array(1024).fill(0);
  const dv = new DataView(bytes.buffer);
  const baseExp = 128;

  // Export directory header.
  dv.setUint32(baseExp + 0, 1, true); // Characteristics
  dv.setUint32(baseExp + 4, 0x11223344, true); // TimeDateStamp
  dv.setUint16(baseExp + 8, 1, true); // MajorVersion
  dv.setUint16(baseExp + 10, 0, true); // MinorVersion
  const nameRva = 300;
  dv.setUint32(baseExp + 12, nameRva, true);
  dv.setUint32(baseExp + 16, 1, true); // Base
  dv.setUint32(baseExp + 20, 2, true); // NumberOfFunctions
  dv.setUint32(baseExp + 24, 1, true); // NumberOfNames
  dv.setUint32(baseExp + 28, 400, true); // AddressOfFunctions
  dv.setUint32(baseExp + 32, 420, true); // AddressOfNames
  dv.setUint32(baseExp + 36, 430, true); // AddressOfNameOrdinals

  encoder.encodeInto("demo.dll\0", new Uint8Array(bytes.buffer, nameRva));

  // EAT (AddressOfFunctions)
  dv.setUint32(400 + 0, 0x7000, true); // normal RVA
  const forwarderRva = baseExp + 64;
  dv.setUint32(400 + 4, forwarderRva, true); // forwarder RVA inside directory

  // Name/ordinal tables
  dv.setUint32(420, 440, true); // RVA of "FuncB"
  dv.setUint16(430, 1, true); // maps to second function (ord = Base + 1)
  encoder.encodeInto("FuncB\0", new Uint8Array(bytes.buffer, 440));

  // Forwarder string
  encoder.encodeInto("KERNEL32.Forward\0", new Uint8Array(bytes.buffer, forwarderRva));

  const file = new MockFile(bytes, "exports.bin");
  const result = await parseExportDirectory(
    file,
    [{ name: "EXPORT", rva: baseExp, size: 96 }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  assert.equal(definedResult.dllName, "demo.dll");
  assert.equal(definedResult.entries.length, 2);
  const secondEntry = expectDefined(definedResult.entries[1]);
  assert.equal(secondEntry.forwarder, "KERNEL32.Forward");
  assert.equal(secondEntry.name, "FuncB");
});

void test("parseImportDirectory reads import descriptors with names and ordinals", async () => {
  const bytes = new Uint8Array(1024).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 500;

  // Descriptor at impBase
  dv.setUint32(impBase + 0, 600, true); // OriginalFirstThunk
  dv.setUint32(impBase + 12, 620, true); // Name RVA
  dv.setUint32(impBase + 16, 0, true); // FirstThunk (unused)
  // Terminator descriptor left as zeros after size 40.

  encoder.encodeInto("SHELL32.dll\0", new Uint8Array(bytes.buffer, 620));

  // INT table at 600: named then ordinal then zero.
  dv.setUint32(600, 700, true);
  dv.setUint32(604, 0x80000003, true);
  dv.setUint32(608, 0, true);

  // Hint/name structure at 700.
  dv.setUint16(700, 0x55aa, true);
  encoder.encodeInto("ImportX\0", new Uint8Array(bytes.buffer, 702));

  const file = new MockFile(bytes, "imports.bin");
  const { entries: imports } = await parseImportDirectory(
    file,
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value,
    () => {},
    false
  );

  assert.equal(imports.length, 1);
  const firstImport = expectDefined(imports[0]);
  assert.equal(firstImport.dll, "SHELL32.dll");
  assert.equal(firstImport.functions.length, 2);
  assert.deepEqual(firstImport.functions[0], { hint: 0x55aa, name: "ImportX" });
  assert.deepEqual(firstImport.functions[1], { ordinal: 3 });
});

void test("parseExportDirectory stops at available function table size", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const expRva = 0x20;
  dv.setUint32(expRva + 20, 10, true); // NumberOfFunctions huge
  dv.setUint32(expRva + 28, 0x60, true); // AddressOfFunctions
  // Only one function entry fits in the buffer.
  dv.setUint32(0x60, 0x1234, true);

  const file = new MockFile(bytes, "exports-trunc.bin");
  const result = await parseExportDirectory(
    file,
    [{ name: "EXPORT", rva: expRva, size: 40 }],
    value => value,
    () => {}
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 8); // limited by available bytes (32 / 4)
  const firstEntry = expectDefined(definedResult.entries[0]);
  assert.equal(firstEntry.rva, 0x1234);
  assert.equal(definedResult.entries[7]?.rva, 0);
});

void test("parseExportDirectory truncates entries when EAT is shorter than NumberOfFunctions", async () => {
  const bytes = new Uint8Array(0x48).fill(0); // 72 bytes
  const dv = new DataView(bytes.buffer);
  const expRva = 0x10;
  dv.setUint32(expRva + 20, 10, true); // NumberOfFunctions claims 10
  dv.setUint32(expRva + 28, 0x40, true); // AddressOfFunctions near buffer end
  // Only two dwords fit at 0x40..0x47.
  dv.setUint32(0x40, 0x1111, true);
  dv.setUint32(0x44, 0x2222, true);

  const result = await parseExportDirectory(
    new MockFile(bytes, "exports-eat-trunc.bin"),
    [{ name: "EXPORT", rva: expRva, size: 64 }],
    value => value,
    () => {}
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 2);
  assert.equal(definedResult.entries[0]?.rva, 0x1111);
  assert.equal(definedResult.entries[1]?.rva, 0x2222);
});

void test("parseExportDirectory ignores names beyond available name/ordinal tables", async () => {
  const bytes = new Uint8Array(0xe0).fill(0); // 224 bytes
  const dv = new DataView(bytes.buffer);
  const expRva = 0x20;
  dv.setUint32(expRva + 16, 1, true); // OrdinalBase
  dv.setUint32(expRva + 20, 2, true); // NumberOfFunctions
  dv.setUint32(expRva + 24, 3, true); // NumberOfNames claims 3
  dv.setUint32(expRva + 28, 0x80, true); // AddressOfFunctions
  dv.setUint32(expRva + 32, 0xd4, true); // AddressOfNames (only two entries fit)
  dv.setUint32(expRva + 36, 0xdc, true); // AddressOfNameOrdinals (only two entries fit)
  // Function RVAs
  dv.setUint32(0x80, 0x1000, true);
  dv.setUint32(0x84, 0x2000, true);
  // Name pointer table (only 8 bytes available for two entries)
  dv.setUint32(0xd4, 0xc0, true);
  dv.setUint32(0xd8, 0x00, true);
  // Ordinal table (only 4 bytes available for two entries)
  dv.setUint16(0xdc, 0, true); // maps to first function
  dv.setUint16(0xde, 1, true); // maps (empty) second name to second function
  // Name string
  encoder.encodeInto("OnlyName\0", new Uint8Array(bytes.buffer, 0xc0));

  const result = await parseExportDirectory(
    new MockFile(bytes, "exports-names-trunc.bin"),
    [{ name: "EXPORT", rva: expRva, size: 80 }],
    value => value,
    () => {}
  );
  const definedResult = expectDefined(result);
  assert.equal(definedResult.entries.length, 2);
  assert.equal(definedResult.entries[0]?.name, "OnlyName");
  assert.ok(definedResult.entries[1]?.name === null || definedResult.entries[1]?.name === "");
});

void test("parseImportDirectory reports warning on truncated thunk table", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x20;
  dv.setUint32(impBase + 12, 0x60, true); // name RVA
  dv.setUint32(impBase + 16, 0x70, true); // FirstThunk RVA
  dv.setUint16(0x60, 0); // empty name
  // Only 4 bytes available for a 64-bit thunk, forcing truncation.
  dv.setUint32(0x70, 0x12345678, true);

  const { entries, warning } = await parseImportDirectory(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value,
    () => {},
    true
  );
  assert.ok(entries.length >= 0);
  assert.ok(warning && /truncated/i.test(warning));
});

void test("parseImportDirectory warns on unmapped name RVA", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x10;
  dv.setUint32(impBase + 12, 0x200, true); // Name RVA outside file
  dv.setUint32(impBase + 16, 0, true); // FirstThunk

  const { warning } = await parseImportDirectory(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => (value < bytes.length ? value : null),
    () => {},
    false
  );
  assert.ok(warning && /name rva/i.test(warning));
});

void test("parseImportDirectory warns on unmapped thunk RVA (x86)", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  const impBase = 0x10;
  dv.setUint32(impBase + 12, 0x40, true); // Name RVA valid
  dv.setUint32(impBase + 16, 0x200, true); // FirstThunk outside file
  encoder.encodeInto("KERNEL32.dll\0", new Uint8Array(bytes.buffer, 0x40));

  const { entries, warning } = await parseImportDirectory(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => (value < bytes.length ? value : null),
    () => {},
    false
  );
  assert.ok(entries.length >= 0);
  assert.ok(warning && /thunk rva/i.test(warning));
});

void test("parseImportDirectory aggregates multiple warnings", async () => {
  const bytes = new Uint8Array(64).fill(0);
  const impBase = 0x10;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(impBase + 12, 0x200, true); // bad name RVA
  dv.setUint32(impBase + 16, 0x300, true); // bad thunk RVA
  // Also truncate descriptor by limiting size.

  const { warning } = await parseImportDirectory(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: 16 }],
    value => (value < bytes.length ? value : null),
    () => {},
    false
  );
  assert.ok(warning);
  assert.ok(/name rva/i.test(warning));
  assert.ok(/thunk rva/i.test(warning));
});
