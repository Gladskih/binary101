"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExportDirectory } from "../../analyzers/pe/exports.js";
import { parseImportDirectory } from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";

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

  assert.ok(result);
  assert.equal(result.dllName, "demo.dll");
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[1].forwarder, "KERNEL32.Forward");
  assert.equal(result.entries[1].name, "FuncB");
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
  const imports = await parseImportDirectory(
    file,
    [{ name: "IMPORT", rva: impBase, size: 40 }],
    value => value,
    () => {},
    false
  );

  assert.equal(imports.length, 1);
  assert.equal(imports[0].dll, "SHELL32.dll");
  assert.equal(imports[0].functions.length, 2);
  assert.deepEqual(imports[0].functions[0], { hint: 0x55aa, name: "ImportX" });
  assert.deepEqual(imports[0].functions[1], { ordinal: 3 });
});