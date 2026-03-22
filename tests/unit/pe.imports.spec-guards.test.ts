"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseImportDirectory32, parseImportDirectory64 } from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  IMAGE_IMPORT_BY_NAME_HINT_SIZE,
  IMAGE_IMPORT_DESCRIPTOR_SIZE,
  IMAGE_ORDINAL_FLAG64,
  IMAGE_THUNK_DATA32_SIZE,
  IMAGE_THUNK_DATA64_SIZE,
  IMPORT_DIRECTORY_SIZE,
  createHintValue,
  createNameThunk64,
  createImportLayout,
  createLimitedImportSliceFile,
  cStringSize,
  imageImportByNameSize,
  placeAtEnd,
  writeImportByName,
  writeImportDescriptor,
  writeImportName,
  writeThunkTable32,
  writeThunkTable64
} from "./pe.import-layout.js";

void test("parseImportDirectory warns when PE32+ name thunks set high reserved bits", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("ADVAPI32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA64_SIZE * 2);
  const hintNameRva = layout.reserve(imageImportByNameSize("RegOpenKey"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const importHint = 0;

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "ADVAPI32.dll");
  // Microsoft PE format, Import Lookup Table: bits 62-31 are reserved for PE32+ name thunks.
  writeThunkTable64(view, thunkTableRva, [createNameThunk64(hintNameRva, 1n), 0n]);
  writeImportByName(bytes, view, hintNameRva, importHint, "RegOpenKey");

  const result = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  const entry = expectDefined(result.entries[0]);
  assert.deepEqual(entry.functions[0], { hint: importHint, name: "RegOpenKey" });
  assert.ok(result.warning?.match(/reserved bits/i));
});

void test("parseImportDirectory warns when an import name runs to EOF without a terminator", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("ADVAPI32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA64_SIZE * 2);
  const importName = "RegOpenKey";
  const bytes = new Uint8Array(
    layout.size() + IMAGE_IMPORT_BY_NAME_HINT_SIZE + importName.length
  ).fill(0);
  const hintNameRva = placeAtEnd(bytes, IMAGE_IMPORT_BY_NAME_HINT_SIZE + importName.length);
  const view = new DataView(bytes.buffer);
  const importHint = 0;

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "ADVAPI32.dll");
  writeThunkTable64(view, thunkTableRva, [BigInt(hintNameRva), 0n]);
  writeImportByName(bytes, view, hintNameRva, importHint, importName, false);

  const result = await parseImportDirectory64(
    createLimitedImportSliceFile(bytes, 8, "imports-eof-name.bin"),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  const entry = expectDefined(result.entries[0]);
  assert.deepEqual(entry.functions[0], { hint: importHint, name: importName });
  assert.ok(result.warning?.toLowerCase().includes("truncated"));
});

void test("parseImportDirectory clamps the descriptor walk to the declared import directory size", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE * 3);
  const firstDllNameRva = layout.reserve(cStringSize("first.dll"));
  const secondDllNameRva = layout.reserve(cStringSize("second.dll"));
  const firstThunkRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const secondThunkRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva: firstDllNameRva, firstThunk: firstThunkRva });
  writeImportDescriptor(view, descriptorOffset + IMAGE_IMPORT_DESCRIPTOR_SIZE, {
    dllNameRva: secondDllNameRva,
    firstThunk: secondThunkRva
  });
  writeImportName(bytes, firstDllNameRva, "first.dll");
  writeImportName(bytes, secondDllNameRva, "second.dll");
  writeThunkTable32(view, firstThunkRva, [0]);
  writeThunkTable32(view, secondThunkRva, [0]);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMAGE_IMPORT_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  assert.deepEqual(result.entries.map(entry => entry.dll), ["first.dll"]);
});

void test("parseImportDirectory drops a truncated live descriptor instead of inventing a partial import", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(
    IMAGE_IMPORT_DESCRIPTOR_SIZE - IMAGE_IMPORT_BY_NAME_HINT_SIZE
  );
  const dllNameRva = layout.reserve(cStringSize("TRUNC.dll"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva });
  writeImportName(bytes, dllNameRva, "TRUNC.dll");

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{
      name: "IMPORT",
      rva: descriptorOffset,
      size: IMAGE_IMPORT_DESCRIPTOR_SIZE - IMAGE_IMPORT_BY_NAME_HINT_SIZE
    }],
    value => value,
    () => {}
  );

  assert.deepEqual(result.entries, []);
  assert.ok(result.warning?.toLowerCase().includes("truncated"));
});

void test("parseImportDirectory keeps an empty import name when hint bytes reach EOF", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const bytes = new Uint8Array(layout.size() + IMAGE_IMPORT_BY_NAME_HINT_SIZE).fill(0);
  const view = new DataView(bytes.buffer);
  const hintNameRva = placeAtEnd(bytes, IMAGE_IMPORT_BY_NAME_HINT_SIZE);
  const importHint = createHintValue(
    IMAGE_IMPORT_BY_NAME_HINT_SIZE,
    cStringSize("KERNEL32.dll")
  );

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  writeThunkTable32(view, thunkTableRva, [hintNameRva, 0]);
  view.setUint16(hintNameRva, importHint, true);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  assert.deepEqual(result.entries[0]?.functions, [{ hint: importHint, name: "" }]);
  assert.equal(result.warning, undefined);
});

void test("parseImportDirectory walks the full null-terminated PE32+ thunk array without a fixed cap", async () => {
  // Import lookup tables are null-terminated IMAGE_THUNK_DATA arrays; the PE format does not define a 16384-entry cap.
  const importCount = 16385;
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const thunkTableRva = layout.reserve((importCount + 1) * IMAGE_THUNK_DATA64_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: thunkTableRva });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  writeThunkTable64(
    view,
    thunkTableRva,
    Array.from({ length: importCount }, (_, index) => IMAGE_ORDINAL_FLAG64 | BigInt(index + 1)).concat(0n)
  );

  const result = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  const entry = expectDefined(result.entries[0]);
  assert.equal(entry.functions.length, importCount);
  assert.deepEqual(entry.functions.at(-1), { ordinal: importCount });
});

void test(
  "parseImportDirectory does not treat a partially non-zero descriptor as the null terminator",
  async () => {
    const layout = createImportLayout();
    const descriptorOffset = layout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE * 5);
    const oftNameRva = layout.reserve(cStringSize("oft.dll"));
    const timeNameRva = layout.reserve(cStringSize("time.dll"));
    const forwardNameRva = layout.reserve(cStringSize("forward.dll"));
    const firstNameRva = layout.reserve(cStringSize("first.dll"));
    const oftThunkRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
    const firstThunkRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
    const bytes = new Uint8Array(layout.size()).fill(0);
    const view = new DataView(bytes.buffer);

    // Microsoft PE format, Import Directory Table: only the all-zero descriptor is the terminator.
    writeImportDescriptor(view, descriptorOffset, {
      originalFirstThunk: oftThunkRva,
      dllNameRva: oftNameRva,
      firstThunk: oftThunkRva
    });
    writeImportDescriptor(view, descriptorOffset + IMAGE_IMPORT_DESCRIPTOR_SIZE, {
      timeDateStamp: 1,
      dllNameRva: timeNameRva
    });
    writeImportDescriptor(view, descriptorOffset + IMAGE_IMPORT_DESCRIPTOR_SIZE * 2, {
      forwarderChain: 1,
      dllNameRva: forwardNameRva
    });
    writeImportDescriptor(view, descriptorOffset + IMAGE_IMPORT_DESCRIPTOR_SIZE * 3, {
      dllNameRva: firstNameRva,
      firstThunk: firstThunkRva
    });
    writeThunkTable32(view, oftThunkRva, [0]);
    writeThunkTable32(view, firstThunkRva, [0]);
    writeImportName(bytes, oftNameRva, "oft.dll");
    writeImportName(bytes, timeNameRva, "time.dll");
    writeImportName(bytes, forwardNameRva, "forward.dll");
    writeImportName(bytes, firstNameRva, "first.dll");

    const result = await parseImportDirectory32(
      new MockFile(bytes),
      [{ name: "IMPORT", rva: descriptorOffset, size: IMAGE_IMPORT_DESCRIPTOR_SIZE * 5 }],
      value => value,
      () => {}
    );

    assert.deepEqual(result.entries.map(entry => entry.dll), [
      "oft.dll",
      "time.dll",
      "forward.dll",
      "first.dll"
    ]);
  }
);

for (const [availableDirSize, fieldName] of [
  [1, "OriginalFirstThunk"],
  [4, "TimeDateStamp"],
  [8, "ForwarderChain"],
  [12, "name RVA"]
] as const) {
  void test(
    `parseImportDirectory names ${fieldName} when a descriptor ends before that field`,
    async () => {
      const bytes = new Uint8Array(IMPORT_DIRECTORY_SIZE + IMAGE_THUNK_DATA32_SIZE).fill(0);
      const descriptorOffset = IMAGE_THUNK_DATA32_SIZE;

      const result = await parseImportDirectory32(
        new MockFile(bytes),
        [{ name: "IMPORT", rva: descriptorOffset, size: availableDirSize }],
        value => value,
        () => {}
      );

      assert.ok(result.warning?.includes(fieldName));
    }
  );
}
