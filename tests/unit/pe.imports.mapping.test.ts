"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseImportDirectory32, parseImportDirectory64 } from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  IMAGE_IMPORT_DESCRIPTOR_SIZE,
  IMAGE_THUNK_DATA32_SIZE,
  IMPORT_DIRECTORY_SIZE,
  createImportLayout,
  createUnmappedRva,
  cStringSize,
  imageImportByNameSize,
  writeImportByName,
  writeImportDescriptor,
  writeImportName,
  writeThunkTable32
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
    value => (value === dllNameRva ? 0 : value)
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

void test("parseImportDirectory stops when later thunk slots no longer map through rvaToOff", async () => {
  const layout = createImportLayout();
  const descriptorOffset = layout.reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = layout.reserve(cStringSize("KERNEL32.dll"));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 3);
  const mappedHintNameRva = layout.reserve(imageImportByNameSize("OnlyMapped"));
  const unmappedHintNameRva = layout.reserve(imageImportByNameSize("UnmappedThunk"));
  const mappedEnd = mappedHintNameRva + imageImportByNameSize("OnlyMapped");
  const unmappedEnd = unmappedHintNameRva + imageImportByNameSize("UnmappedThunk");
  const bytes = new Uint8Array(layout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, {
    originalFirstThunk: thunkTableRva,
    dllNameRva
  });
  writeImportName(bytes, dllNameRva, "KERNEL32.dll");
  writeThunkTable32(view, thunkTableRva, [mappedHintNameRva, unmappedHintNameRva, 0]);
  writeImportByName(bytes, view, mappedHintNameRva, 0, "OnlyMapped");
  writeImportByName(bytes, view, unmappedHintNameRva, 0, "UnmappedThunk");

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva === descriptorOffset || rva === dllNameRva || rva === thunkTableRva) return rva;
    if (rva >= mappedHintNameRva && rva < mappedEnd) return rva;
    if (rva >= unmappedHintNameRva && rva < unmappedEnd) return rva;
    return null;
  };

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    sparseRvaToOff
  );

  const entry = expectDefined(result.entries[0]);
  assert.deepEqual(entry.functions, [{ hint: 0, name: "OnlyMapped" }]);
  assert.ok(result.warning?.match(/truncated|unmapped|thunk/i));
});

void test("parseImportDirectory resolves later descriptors through rvaToOff instead of assuming contiguous file bytes", async () => {
  const firstDllName = "first.dll";
  const secondDllName = "second.dll";
  const rvaLayout = createImportLayout();
  const fileLayout = createImportLayout(0);
  const firstDescriptorRva = rvaLayout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const secondDescriptorRva = rvaLayout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const firstDllNameRva = rvaLayout.reserve(cStringSize(firstDllName));
  const secondDllNameRva = rvaLayout.reserve(cStringSize(secondDllName));
  const firstDllNameEnd = firstDllNameRva + cStringSize(firstDllName);
  const secondDllNameEnd = secondDllNameRva + cStringSize(secondDllName);
  const firstDescriptorOffset = fileLayout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const firstDllNameOffset = fileLayout.reserve(cStringSize(firstDllName));
  const secondDescriptorOffset = fileLayout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const secondDllNameOffset = fileLayout.reserve(cStringSize(secondDllName));
  const bytes = new Uint8Array(fileLayout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, firstDescriptorOffset, { dllNameRva: firstDllNameRva });
  writeImportDescriptor(view, secondDescriptorOffset, { dllNameRva: secondDllNameRva });
  writeImportName(bytes, firstDllNameOffset, firstDllName);
  writeImportName(bytes, secondDllNameOffset, secondDllName);

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= firstDescriptorRva && rva < firstDescriptorRva + IMAGE_IMPORT_DESCRIPTOR_SIZE) {
      return rva - firstDescriptorRva;
    }
    if (rva >= secondDescriptorRva && rva < secondDescriptorRva + IMAGE_IMPORT_DESCRIPTOR_SIZE) {
      return secondDescriptorOffset + (rva - secondDescriptorRva);
    }
    if (rva >= firstDllNameRva && rva < firstDllNameEnd) {
      return firstDllNameOffset + (rva - firstDllNameRva);
    }
    if (rva >= secondDllNameRva && rva < secondDllNameEnd) {
      return secondDllNameOffset + (rva - secondDllNameRva);
    }
    return null;
  };

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: firstDescriptorRva, size: IMPORT_DIRECTORY_SIZE }],
    sparseRvaToOff
  );

  assert.deepEqual(result.entries.map(entry => entry.dll), [firstDllName, secondDllName]);
});

void test("parseImportDirectory warns when a DLL name stops mapping before its null terminator", async () => {
  const dllName = "AB";
  const rvaLayout = createImportLayout();
  const fileLayout = createImportLayout(0);
  const descriptorRva = rvaLayout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const dllNameRva = rvaLayout.reserve(cStringSize(dllName));
  const descriptorOffset = fileLayout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const dllNameOffset = fileLayout.reserve(cStringSize(dllName));
  const bytes = new Uint8Array(fileLayout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, { dllNameRva });
  writeImportName(bytes, dllNameOffset, dllName);

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= descriptorRva && rva < descriptorRva + IMAGE_IMPORT_DESCRIPTOR_SIZE) {
      return rva - descriptorRva;
    }
    if (rva === dllNameRva) return dllNameOffset;
    if (rva === dllNameRva + 1) return dllNameOffset + 1;
    return null;
  };

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorRva, size: IMAGE_IMPORT_DESCRIPTOR_SIZE }],
    sparseRvaToOff
  );

  assert.equal(result.entries[0]?.dll, dllName);
  assert.ok(result.warning?.match(/truncated|name/i));
});

void test("parseImportDirectory warns when an import-by-name string stops mapping before its null terminator", async () => {
  const dllName = "KERNEL32.dll";
  const importName = "AB";
  const rvaLayout = createImportLayout();
  const fileLayout = createImportLayout(0);
  const descriptorRva = rvaLayout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const dllNameRva = rvaLayout.reserve(cStringSize(dllName));
  const thunkRva = rvaLayout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const hintNameRva = rvaLayout.reserve(imageImportByNameSize(importName));
  const descriptorOffset = fileLayout.reserve(IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const dllNameOffset = fileLayout.reserve(cStringSize(dllName));
  const thunkOffset = fileLayout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const hintNameOffset = fileLayout.reserve(imageImportByNameSize(importName));
  const bytes = new Uint8Array(fileLayout.size()).fill(0);
  const view = new DataView(bytes.buffer);

  writeImportDescriptor(view, descriptorOffset, {
    originalFirstThunk: thunkRva,
    dllNameRva
  });
  writeImportName(bytes, dllNameOffset, dllName);
  writeThunkTable32(view, thunkOffset, [hintNameRva, 0]);
  writeImportByName(bytes, view, hintNameOffset, 0x33, importName);

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= descriptorRva && rva < descriptorRva + IMAGE_IMPORT_DESCRIPTOR_SIZE) {
      return rva - descriptorRva;
    }
    if (rva >= dllNameRva && rva < dllNameRva + cStringSize(dllName)) {
      return dllNameOffset + (rva - dllNameRva);
    }
    if (rva >= thunkRva && rva < thunkRva + IMAGE_THUNK_DATA32_SIZE * 2) {
      return thunkOffset + (rva - thunkRva);
    }
    if (rva === hintNameRva || rva === hintNameRva + 2 || rva === hintNameRva + 3) {
      // Hint bytes map, and only the first two name bytes map. The trailing NUL does not.
      return hintNameOffset + (rva - hintNameRva);
    }
    return null;
  };

  const result = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorRva, size: IMPORT_DIRECTORY_SIZE }],
    sparseRvaToOff
  );

  assert.deepEqual(result.entries[0]?.functions, [{ hint: 0x33, name: importName }]);
  assert.ok(result.warning?.match(/truncated|name/i));
});
