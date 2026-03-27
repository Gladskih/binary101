"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseImportDirectory32, parseImportDirectory64 } from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  IMAGE_IMPORT_DESCRIPTOR_SIZE,
  IMAGE_THUNK_DATA32_SIZE,
  IMPORT_DIRECTORY_SIZE,
  createImportLayout,
  createUnmappedRva,
  cStringSize,
  writeImportDescriptor,
  writeImportName,
} from "./pe.import-layout.js";

void test("parseImportDirectory warns when a mapped DLL name offset falls past EOF", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("mapped.dll"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const mappedPastEofOffset = createUnmappedRva(bytes);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva });

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => (value === dllNameRva ? mappedPastEofOffset : value)
  );

  assert.equal(result.entries[0]?.dll, "");
  assert.ok(result.warning?.match(/name rva/i));
});

void test("parseImportDirectory warns on unmapped name RVA", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const unmappedDllNameRva = createUnmappedRva(bytes);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva: unmappedDllNameRva });

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => (value < bytes.length ? value : null)
  );

  assert.ok(result.warning?.match(/name rva/i));
});

void test("parseImportDirectory warns when the root IMPORT directory does not map to file data", async () => {
  const bytes = new Uint8Array(IMPORT_DIRECTORY_SIZE).fill(0);

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: 0x1000, size: IMPORT_DIRECTORY_SIZE }],
    () => null
  );

  assert.deepEqual(result.entries, []);
  assert.ok(result.warning?.match(/import|directory|map|file data/i));
});

void test("parseImportDirectory warns on unmapped thunk RVA in PE32", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const missingThunkRva = createUnmappedRva(bytes);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: missingThunkRva });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => (value < bytes.length ? value : null)
  );

  assert.ok(result.warning?.match(/thunk rva/i));
});

void test("parseImportDirectory warns on unmapped thunk RVAs in PE32+", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("ADVAPI32.dll"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const missingThunkRva = createUnmappedRva(bytes);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva, firstThunk: missingThunkRva });
  writeImportName(bytes, dllNameRva, "ADVAPI32.dll");

  const result = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => (value < bytes.length ? value : null)
  );

  assert.ok(result.warning?.match(/thunk rva/i));
});

void test("parseImportDirectory aggregates multiple warnings with the expected separator", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);
  const unmappedDllNameRva = createUnmappedRva(bytes);
  const unmappedThunkRva = createUnmappedRva(bytes, IMAGE_THUNK_DATA32_SIZE);

  writeImportDescriptor(view, descriptorOffset, {
    dllNameRva: unmappedDllNameRva,
    firstThunk: unmappedThunkRva
  });

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMAGE_IMPORT_DESCRIPTOR_SIZE - 4 }],
    value => (value < bytes.length ? value : null)
  );

  assert.ok(result.warning?.includes(" | "));
  assert.ok(result.warning?.match(/name rva/i));
  assert.ok(result.warning?.match(/thunk rva/i));
});

void test("parseImportDirectory uses the IMPORT data directory even when other directories exist", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("USER32.dll"));
  const bytes = new Uint8Array(layout.size() + IMPORT_DIRECTORY_SIZE).fill(0);
  const view = new DataView(bytes.buffer);
  const exportDirectoryRva = IMAGE_IMPORT_DESCRIPTOR_SIZE + IMAGE_THUNK_DATA32_SIZE;

  writeImportDescriptor(view, descriptorOffset, { dllNameRva });
  writeImportName(bytes, dllNameRva, "USER32.dll");

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [
      { name: "EXPORT", rva: exportDirectoryRva, size: IMPORT_DIRECTORY_SIZE },
      { name: "IMPORT", rva: descriptorOffset, size: bytes.length - descriptorOffset }
    ],
    value => value
  );

  assert.equal(result.warning, undefined);
  assert.deepEqual(result.entries.map(entry => entry.dll), ["USER32.dll"]);
});

void test("parseImportDirectory accepts a mapped DLL name at file offset zero", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("ZERO.dll"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva });
  writeImportName(bytes, 0, "ZERO.dll");

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => (value >= dllNameRva && value < dllNameRva + cStringSize("ZERO.dll") ? value - dllNameRva : value)
  );

  assert.equal(result.entries[0]?.dll, "ZERO.dll");
  assert.equal(result.warning, undefined);
});

void test("parseImportDirectory rejects mapped DLL names that start exactly at EOF", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("EOF.dll"));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva });

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => (value === dllNameRva ? bytes.length : value)
  );

  assert.ok(result.warning?.match(/name rva/i));
});
