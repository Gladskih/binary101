"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseImportDirectory32, parseImportDirectory64 } from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  IMAGE_IMPORT_BY_NAME_HINT_SIZE,
  IMAGE_IMPORT_DESCRIPTOR_SIZE,
  IMPORT_DIRECTORY_SIZE,
  IMAGE_THUNK_DATA32_SIZE,
  IMAGE_THUNK_DATA64_SIZE,
  createHintValue,
  createImportLayout,
  createOrdinalThunk32,
  createOrdinalThunk64,
  createUnmappedRva,
  cStringSize,
  imageImportByNameSize,
  placeAtEnd,
  writeImportByName,
  writeImportDescriptor,
  writeImportName,
  writeThunkTable32,
  writeThunkTable64
} from "./pe.import-layout.js";

void test("parseImportDirectory reads import descriptors with names and ordinals", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 3);
  const dllNameRva = layout.reserve(cStringSize("SHELL32.dll"));
  const hintNameRva = layout.reserve(imageImportByNameSize("ImportX"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const importHint = createHintValue(cStringSize("ImportX"), cStringSize("SHELL32.dll"));

  writeImportDescriptor(view, descriptorOffset, {
    originalFirstThunk: thunkTableRva,
    dllNameRva
  });
  writeThunkTable32(view, thunkTableRva, [hintNameRva, createOrdinalThunk32(3), 0]);
  writeImportName(bytes, dllNameRva, "SHELL32.dll");
  writeImportByName(bytes, view, hintNameRva, importHint, "ImportX");

  const result = await parseImportDirectory32(
    new MockFile(bytes, "imports.bin"),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.equal(result.warning, undefined);
  assert.equal(result.entries.length, 1);
  const entry = expectDefined(result.entries[0]);
  assert.equal(entry.dll, "SHELL32.dll");
  assert.deepEqual(entry.functions, [{ hint: importHint, name: "ImportX" }, { ordinal: 3 }]);
});

void test(
  "parseImportDirectory warns when an import-by-name thunk points to an unmapped Hint/Name entry",
  async () => {
    const layout = createImportLayout();
    const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
    const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
    const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
    const bytes = new Uint8Array(layout.size()).fill(0);
    const view = new DataView(bytes.buffer);
    const missingHintNameRva = createUnmappedRva(bytes);

    writeImportDescriptor(view, descriptorOffset, {
      originalFirstThunk: thunkTableRva,
      dllNameRva
    });
    writeImportName(bytes, dllNameRva, "KERNEL32.dll");
    writeThunkTable32(view, thunkTableRva, [missingHintNameRva, 0]);

    const result = await parseImportDirectory32(
      new MockFile(bytes),
      [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
      value => (value < bytes.length ? value : null),
      () => {}
    );

    assert.deepEqual(result.entries[0]?.functions, [{ name: "<bad RVA>" }]);
    assert.ok(result.warning?.match(/hint|name|rva/i));
  }
);

void test("parseImportDirectory does not decode a descriptor past the declared directory size", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const hintNameRva = layout.reserve(imageImportByNameSize("Sleep"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  writeImportDescriptor(view, descriptorOffset, {
    originalFirstThunk: thunkTableRva,
    dllNameRva
  });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  writeThunkTable32(view, thunkTableRva, [hintNameRva, 0]);
  writeImportByName(bytes, view, hintNameRva, 0, "Sleep");

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{
      name: "IMPORT",
      rva: descriptorOffset,
      size: IMAGE_IMPORT_DESCRIPTOR_SIZE - IMAGE_THUNK_DATA32_SIZE
    }],
    value => value,
    () => {}
  );

  assert.equal(result.entries.length, 0);
  assert.ok(result.warning?.match(/truncated|descriptor/i));
});

void test("parseImportDirectory supports the 64-bit imports path", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("ADVAPI32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA64_SIZE * 3);
  const hintNameRva = layout.reserve(imageImportByNameSize("RegOpenKey"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const importHint = 0;
  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "ADVAPI32.dll");
  writeThunkTable64(view, thunkTableRva, [BigInt(hintNameRva), createOrdinalThunk64(5), 0n]);
  writeImportByName(bytes, view, hintNameRva, importHint, "RegOpenKey");

  const result = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.equal(result.warning, undefined);
  assert.equal(result.entries.length, 1);
  const entry = expectDefined(result.entries[0]);
  assert.deepEqual(entry.functions, [{ hint: importHint, name: "RegOpenKey" }, { ordinal: 5 }]);
});

void test("parseImportDirectory warns when PE32 ordinal thunks set reserved bits", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  // PE/COFF Import Lookup Table: any non-zero payload in reserved bits 30-15 is invalid.
  writeThunkTable32(view, thunkTableRva, [createOrdinalThunk32(2, 1), 0]);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.ok(result.warning?.match(/ordinal/i));
});

void test("parseImportDirectory warns when the Hint/Name table is truncated", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const bytes = new Uint8Array(layout.size() + 1).fill(0);
  const view = new DataView(bytes.buffer);
  const hintNameRva = placeAtEnd(bytes, 1); // Only one byte of the 2-byte hint fits in the file.
  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  writeThunkTable32(view, thunkTableRva, [hintNameRva, 0]);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.deepEqual(result.entries[0]?.functions, [{ name: "" }]);
  assert.ok(result.warning?.match(/truncated/i));
});

void test("parseImportDirectory warns when DLL names run to EOF without terminators", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllName = "FirstDLL";
  const bytes = new Uint8Array(layout.size() + dllName.length).fill(0);
  const view = new DataView(bytes.buffer);
  const dllNameRva = placeAtEnd(bytes, dllName.length);
  writeImportDescriptor(view, descriptorOffset, { dllNameRva });
  writeImportName(bytes, dllNameRva, dllName, false);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.equal(result.entries[0]?.dll, "FirstDLL");
  assert.ok(result.warning?.includes("DLL name string truncated"));
});

void test("parseImportDirectory warns when import names run to EOF without terminators", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const dllNameRva = layout.reserve(cStringSize("SECOND.dll"));
  const importName = "A".repeat(46);
  const bytes = new Uint8Array(
    layout.size() + IMAGE_IMPORT_BY_NAME_HINT_SIZE + importName.length
  ).fill(0);
  const view = new DataView(bytes.buffer);
  const hintNameRva = placeAtEnd(bytes, IMAGE_IMPORT_BY_NAME_HINT_SIZE + importName.length);
  const importHint = 0;
  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "SECOND.dll");
  writeThunkTable32(view, thunkTableRva, [hintNameRva, 0]);
  writeImportByName(bytes, view, hintNameRva, importHint, importName, false);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.deepEqual(result.entries[0]?.functions, [{ hint: importHint, name: importName }]);
  assert.ok(result.warning?.includes("Import name string truncated"));
});

void test("parseImportDirectory warns when a PE32 thunk table is physically truncated", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const bytes = new Uint8Array(layout.size() + 2).fill(0);
  const view = new DataView(bytes.buffer);
  const thunkTableRva = placeAtEnd(bytes, 2); // Only half of the 4-byte PE32 thunk fits.
  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  view.setUint16(thunkTableRva, 1, true);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.equal(result.entries[0]?.functions.length, 0);
  assert.ok(result.warning?.match(/truncated/i));
});

void test("parseImportDirectory warns when PE32+ ordinal thunks set reserved bits", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("ADVAPI32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA64_SIZE * 2);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "ADVAPI32.dll");
  // PE/COFF Import Lookup Table: any non-zero payload in reserved bits 62-15 is invalid.
  writeThunkTable64(view, thunkTableRva, [createOrdinalThunk64(2, 1n), 0n]);

  const result = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.deepEqual(result.entries[0]?.functions, [{ ordinal: 2 }]);
  assert.ok(result.warning?.match(/reserved/i));
});
