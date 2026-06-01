"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseImportDirectory32 } from "../../analyzers/pe/imports/index.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  IMAGE_IMPORT_DESCRIPTOR_SIZE,
  IMAGE_THUNK_DATA32_SIZE,
  IMPORT_DIRECTORY_SIZE,
  cStringSize,
  createImportLayout,
  createOrdinalThunk32,
  writeImportDescriptor,
  writeImportName,
  writeThunkTable32
} from "./pe.import-layout.js";

void test("parseImportDirectory warns when the descriptor table lacks a null terminator", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  writeImportDescriptor(view, descriptorOffset, {
    dllNameRva,
    firstThunk: thunkTableRva
  });
  writeThunkTable32(view, thunkTableRva, [0]);
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMAGE_IMPORT_DESCRIPTOR_SIZE }],
    value => value
  );

  assert.ok(result.warning?.includes("not terminated by an all-zero descriptor"));
});

void test("parseImportDirectory warns when a thunk table lacks a null terminator", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  writeImportDescriptor(view, descriptorOffset, {
    dllNameRva,
    firstThunk: thunkTableRva
  });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  writeThunkTable32(view, thunkTableRva, [createOrdinalThunk32(7)]);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value
  );

  assert.ok(result.warning?.includes("Import thunk table is not terminated by a null entry"));
});
