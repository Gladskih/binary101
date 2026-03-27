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
  createImportLayout,
  cStringSize,
  createLimitedImportSliceFile,
  placeAtEnd,
  writeImportByName,
  writeImportDescriptor,
  writeImportName,
  writeThunkTable32
} from "./pe.import-layout.js";

void test("parseImportDirectory reads DLL names beyond one incremental string-read chunk", async () => {
  const longDllName = `${"K".repeat(70)}.dll`;
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize(longDllName));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva });
  writeImportName(bytes, dllNameRva, longDllName);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value
  );

  assert.equal(result.entries[0]?.dll, longDllName);
  assert.equal(result.warning, undefined);
});

void test("parseImportDirectory returns no entries when the IMPORT directory starts at EOF", async () => {
  const bytes = new Uint8Array(IMPORT_DIRECTORY_SIZE * 2).fill(0);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: bytes.length, size: IMPORT_DIRECTORY_SIZE }],
    value => value
  );

  assert.deepEqual(result.entries, []);
});

void test("parseImportDirectory keeps returning no entries when the IMPORT directory starts at EOF", async () => {
  const bytes = new Uint8Array(64).fill(0);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: bytes.length, size: IMPORT_DIRECTORY_SIZE }],
    value => value
  );

  assert.deepEqual(result.entries, []);
});

void test("parseImportDirectory keeps scanning after nameless live descriptors", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE * 3);
  const dllNameRva = layout.reserve(cStringSize("LATE.dll"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const laterDescriptorOffset = descriptorOffset + IMAGE_IMPORT_DESCRIPTOR_SIZE * 2;

  // Microsoft PE format, Import Directory Table: non-zero TimeDateStamp/ForwarderChain keep a descriptor live.
  writeImportDescriptor(view, descriptorOffset, { timeDateStamp: 1 });
  writeImportDescriptor(view, descriptorOffset + IMAGE_IMPORT_DESCRIPTOR_SIZE, {
    forwarderChain: 1
  });
  writeImportDescriptor(view, laterDescriptorOffset, { dllNameRva });
  writeImportName(bytes, dllNameRva, "LATE.dll");

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE * 2 }],
    value => value
  );

  assert.deepEqual(result.entries.map(entry => entry.dll), ["LATE.dll"]);
  assert.ok(result.warning?.includes("Import descriptor is missing the DLL name RVA."));
});

void test("parseImportDirectory reports truncated 64-bit thunk tables", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("delay64.dll"));
  const bytes = new Uint8Array(layout.size() + (IMAGE_THUNK_DATA64_SIZE / 2)).fill(0);
  const view = new DataView(bytes.buffer);
  const thunkTableRva = placeAtEnd(bytes, IMAGE_THUNK_DATA64_SIZE / 2);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "delay64.dll");
  view.setUint32(thunkTableRva, 1, true);

  const result = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value
  );

  assert.ok(result.warning?.match(/truncated/i));
});

void test("parseImportDirectory warns when the Hint/Name table is truncated after the hint", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const bytes = new Uint8Array(layout.size() + IMAGE_IMPORT_BY_NAME_HINT_SIZE).fill(0);
  const hintNameRva = placeAtEnd(bytes, IMAGE_IMPORT_BY_NAME_HINT_SIZE);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  writeThunkTable32(view, thunkTableRva, [hintNameRva]);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value
  );

  assert.deepEqual(result.entries[0]?.functions, [{ hint: 0, name: "" }]);
  assert.ok(result.warning?.toLowerCase().includes("truncated"));
});

void test("parseImportDirectory reads bounded import strings without over-reading slices", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("SECOND.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const importName = "A".repeat(46);
  const bytes = new Uint8Array(
    layout.size() + IMAGE_IMPORT_BY_NAME_HINT_SIZE + importName.length
  ).fill(0);
  const hintNameRva = placeAtEnd(bytes, IMAGE_IMPORT_BY_NAME_HINT_SIZE + importName.length);
  const importHint = 0;
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "SECOND.dll");
  writeThunkTable32(view, thunkTableRva, [hintNameRva, 0]);
  writeImportByName(bytes, view, hintNameRva, importHint, importName, false);

  const result = await parseImportDirectory32(
    createLimitedImportSliceFile(bytes, 8, "imports-bounded.bin"),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value
  );

  const entry = expectDefined(result.entries[0]);
  assert.deepEqual(entry.functions, [{ hint: importHint, name: importName }]);
  assert.ok(result.warning?.includes("Import name string truncated"));
});
