"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDelayImports32, parseDelayImports64 } from "../../analyzers/pe/delay-imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  IMAGE_DELAYLOAD_DESCRIPTOR_SIZE,
  IMAGE_THUNK_DATA32_SIZE,
  IMAGE_THUNK_DATA64_SIZE,
  cStringSize,
  createDelayImportLayout,
  imageImportByNameSize,
  writeDelayImportDescriptor,
  writeDelayImportName,
  writeImportByName,
  writeThunkTable32,
  writeThunkTable64
} from "./pe.delay-import-layout.js";

void test("parseDelayImports warns when the Delay Import Name Table cannot be mapped", async () => {
  const dllName = "delay.dll";
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const intRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: intRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);
  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => (value === intRva ? null : value)
  ));
  assert.ok(result.warning?.toLowerCase().includes("name"));
});

void test("parseDelayImports reports an unmappable directory base instead of silently returning null", async () => {
  const result = await parseDelayImports32(
    new MockFile(new Uint8Array(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE).fill(0)),
    [{ name: "DELAY_IMPORT", rva: 1, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    () => null
  );

  assert.ok(result);
  assert.deepEqual(result?.entries, []);
  assert.ok(result?.warning?.toLowerCase().match(/map|offset|rva/));
});

void test("parseDelayImports warns when PE32+ name thunks set reserved bits", async () => {
  const dllName = "delay64.dll";
  const importName = "DelayFunc";
  const hint = 0x21;
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const intRva = layout.reserve(IMAGE_THUNK_DATA64_SIZE * 2);
  const hintNameRva = layout.reserve(imageImportByNameSize(importName));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: intRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);
  // Delay import INT entries use IMAGE_THUNK_DATA, so PE32+ name imports reserve bits 62-31.
  writeThunkTable64(dv, intRva, [0x0000000100000000n | BigInt(hintNameRva), 0n]);
  writeImportByName(bytes, dv, hintNameRva, hint, importName);
  const result = expectDefined(await parseDelayImports64(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value
  ));
  assert.ok(result.warning?.toLowerCase().includes("reserved"));
});

void test("parseDelayImports warns when the DLL name stops mapping before its null terminator", async () => {
  const dllName = "AB";
  const rvaLayout = createDelayImportLayout();
  const fileLayout = createDelayImportLayout(0);
  const descriptorRva = rvaLayout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = rvaLayout.reserve(cStringSize(dllName));
  const descriptorOffset = fileLayout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameOffset = fileLayout.reserve(cStringSize(dllName));
  const bytes = new Uint8Array(fileLayout.size()).fill(0);
  const dv = new DataView(bytes.buffer);

  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: 0
  });
  writeDelayImportName(bytes, dllNameOffset, dllName);

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= descriptorRva && rva < descriptorRva + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
      return rva - descriptorRva;
    }
    if (rva === dllNameRva) return dllNameOffset;
    if (rva === dllNameRva + 1) return dllNameOffset + 1;
    return null;
  };

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorRva, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    sparseRvaToOff
  ));

  assert.equal(result.entries[0]?.name, dllName);
  assert.ok(result.warning?.toLowerCase().match(/truncated|name/));
});

void test("parseDelayImports warns when an import-by-name string stops mapping before its null terminator", async () => {
  const dllName = "delay.dll";
  const importName = "AB";
  const hint = dllName.length + importName.length;
  const rvaLayout = createDelayImportLayout();
  const fileLayout = createDelayImportLayout(0);
  const descriptorRva = rvaLayout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = rvaLayout.reserve(cStringSize(dllName));
  const intRva = rvaLayout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const hintNameRva = rvaLayout.reserve(imageImportByNameSize(importName));
  const descriptorOffset = fileLayout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameOffset = fileLayout.reserve(cStringSize(dllName));
  const thunkOffset = fileLayout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const hintNameOffset = fileLayout.reserve(imageImportByNameSize(importName));
  const bytes = new Uint8Array(fileLayout.size()).fill(0);
  const dv = new DataView(bytes.buffer);

  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: intRva
  });
  writeDelayImportName(bytes, dllNameOffset, dllName);
  writeThunkTable32(dv, thunkOffset, [hintNameRva, 0]);
  writeImportByName(bytes, dv, hintNameOffset, hint, importName);

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= descriptorRva && rva < descriptorRva + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
      return rva - descriptorRva;
    }
    if (rva >= dllNameRva && rva < dllNameRva + cStringSize(dllName)) {
      return dllNameOffset + (rva - dllNameRva);
    }
    if (rva >= intRva && rva < intRva + IMAGE_THUNK_DATA32_SIZE * 2) {
      return thunkOffset + (rva - intRva);
    }
    if (rva === hintNameRva || rva === hintNameRva + 2 || rva === hintNameRva + 3) {
      // Hint bytes map, and only the first two name bytes map. The trailing NUL does not.
      return hintNameOffset + (rva - hintNameRva);
    }
    return null;
  };

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorRva, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    sparseRvaToOff
  ));

  assert.deepEqual(result.entries[0]?.functions, [{ hint, name: importName }]);
  assert.ok(result.warning?.toLowerCase().match(/truncated|name/));
});
