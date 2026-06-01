"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDelayImports32 } from "../../analyzers/pe/imports/delay.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  IMAGE_DELAYLOAD_DESCRIPTOR_SIZE,
  IMAGE_THUNK_DATA32_SIZE,
  createDelayImportLayout,
  writeDelayImportDescriptor,
  writeDelayImportName,
  writeThunkTable32
} from "./pe.delay-import-layout.js";

void test("parseDelayImports warns when the descriptor table lacks a null terminator", async () => {
  const layout = createDelayImportLayout(0x40);
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const dllNameRva = layout.reserve("delay.dll".length + 1);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  writeDelayImportDescriptor(view, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeThunkTable32(view, thunkTableRva, [0]);
  writeDelayImportName(bytes, dllNameRva, "delay.dll");

  const result = await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value
  );

  assert.ok(result?.warning?.includes("not terminated by an all-zero descriptor"));
});

void test("parseDelayImports warns when a thunk table lacks a null terminator", async () => {
  const layout = createDelayImportLayout(0x40);
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2);
  const dllNameRva = layout.reserve("delay.dll".length + 1);
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  writeDelayImportDescriptor(view, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, "delay.dll");
  writeThunkTable32(view, thunkTableRva, [0x80000002]);

  const result = await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2 }],
    value => value
  );

  assert.ok(result?.warning?.includes("Delay-load thunk table is not terminated by a null entry"));
});
