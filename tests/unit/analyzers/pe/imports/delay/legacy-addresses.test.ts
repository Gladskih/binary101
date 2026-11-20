"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDelayImports32 } from "../../../../../../analyzers/pe/imports/delay.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";
import {
  IMAGE_DELAYLOAD_DESCRIPTOR_SIZE,
  IMAGE_THUNK_DATA32_SIZE,
  createDelayImportLayout,
  imageImportByNameSize,
  writeDelayImportDescriptor,
  writeDelayImportName,
  writeImportByName,
  writeThunkTable32
} from "../../delay-import-layout.js";

void test("parseDelayImports resolves legacy descriptor and hint/name VAs", async () => {
  const layout = createDelayImportLayout(0x40);
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2);
  const dllNameRva = layout.reserve("kernel32.dll".length + 1);
  const intRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 3);
  const hintNameRva = layout.reserve(imageImportByNameSize("Func"));
  const iatRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 3);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  const imageBase = 0x400000;
  // Microsoft PE format: a clear RvaBased bit denotes the original VA layout.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#attributes
  writeDelayImportDescriptor(dv, descriptorOffset, {
    attributes: 0,
    dllNameRva: imageBase + dllNameRva,
    importNameTableRva: imageBase + intRva
  });
  dv.setUint32(descriptorOffset + 12, imageBase + iatRva, true);
  writeThunkTable32(dv, intRva, [imageBase + hintNameRva, 0x80000002, 0]);
  writeImportByName(bytes, dv, hintNameRva, 0x10, "Func");
  writeDelayImportName(bytes, dllNameRva, "kernel32.dll");

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2 }],
    value => value < bytes.length ? value : null,
    { sizeOfImage: bytes.length, imageBase: BigInt(imageBase) }
  ));

  const entry = expectDefined(result.entries[0]);
  assert.equal(result.warning, undefined);
  assert.equal(entry.name, "kernel32.dll");
  assert.equal(entry.ImportNameTableRVA, intRva);
  assert.equal(entry.ImportAddressTableRVA, iatRva);
  assert.deepEqual(entry.functions, [{ hint: 0x10, name: "Func" }, { ordinal: 2 }]);
});

void test("parseDelayImports warns when a legacy VA is below the image base", async () => {
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2);
  const dllNameRva = layout.reserve("kernel32.dll".length + 1);
  const bytes = new Uint8Array(layout.size());
  const imageBase = 0x400000;
  writeDelayImportDescriptor(new DataView(bytes.buffer), descriptorOffset, {
    attributes: 0,
    dllNameRva,
    importNameTableRva: 0
  });
  writeDelayImportName(bytes, dllNameRva, "kernel32.dll");

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2 }],
    value => value < bytes.length ? value : null,
    { sizeOfImage: bytes.length, imageBase: BigInt(imageBase) }
  ));

  assert.equal(result.entries[0]?.name, "");
  assert.match(result.warning ?? "", /Delay import VA .* cannot be resolved/);
});
