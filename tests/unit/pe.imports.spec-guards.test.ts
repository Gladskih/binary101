"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseImportDirectory32,
  parseImportDirectory64
} from "../../analyzers/pe/imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const IMAGE_IMPORT_DESCRIPTOR_SIZE = 20; // IMAGE_IMPORT_DESCRIPTOR
const IMPORT_DIRECTORY_SIZE = IMAGE_IMPORT_DESCRIPTOR_SIZE * 2; // One descriptor plus the required null terminator.
const IMAGE_THUNK_DATA32_SIZE = 4; // IMAGE_THUNK_DATA32
const IMAGE_THUNK_DATA64_SIZE = 8; // IMAGE_THUNK_DATA64
const IMAGE_IMPORT_BY_NAME_HINT_SIZE = 2; // Hint field before the import name string.
const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n; // IMAGE_ORDINAL_FLAG64

const createRvaLayout = (start = IMPORT_DIRECTORY_SIZE): ((size: number) => number) => {
  let next = start;
  return (size: number): number => {
    const offset = next;
    next += size;
    return offset;
  };
};

const cStringSize = (text: string): number => encoder.encode(`${text}\0`).length;
const imageImportByNameSize = (name: string): number =>
  IMAGE_IMPORT_BY_NAME_HINT_SIZE + cStringSize(name);

void test("parseImportDirectory warns when PE32+ name thunks set high reserved bits", async () => {
  const dllName = "ADVAPI32.dll";
  const importName = "RegOpenKey";
  const hint = 0x77;
  const reserve = createRvaLayout();
  const impBase = reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = reserve(cStringSize(dllName));
  const thunkRva = reserve(IMAGE_THUNK_DATA64_SIZE * 2);
  const hintNameRva = reserve(imageImportByNameSize(importName));
  const bytes = new Uint8Array(reserve(0)).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(impBase + 12, dllNameRva, true);
  dv.setUint32(impBase + 16, thunkRva, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));
  // Microsoft PE format, Import Lookup Table:
  // for PE32+, bits 62-31 must be zero when importing by name.
  dv.setBigUint64(thunkRva, 0x0000000100000000n | BigInt(hintNameRva), true); // Set reserved bit 32 and keep the name RVA.
  dv.setBigUint64(thunkRva + IMAGE_THUNK_DATA64_SIZE, 0n, true);
  dv.setUint16(hintNameRva, hint, true);
  encoder.encodeInto(
    `${importName}\0`,
    new Uint8Array(bytes.buffer, hintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE)
  );

  const { entries, warning } = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  const firstImport = expectDefined(entries[0]);
  assert.deepEqual(firstImport.functions[0], { hint, name: "RegOpenKey" });
  assert.ok(warning && /reserved bits/i.test(warning));
});

void test("parseImportDirectory stops when later thunk slots no longer map through rvaToOff", async () => {
  const dllName = "KERNEL32.dll";
  const mappedHint = 0x11;
  const mappedName = "OnlyMapped";
  const unmappedHint = 0x22;
  const unmappedName = "UnmappedThunk";
  const reserve = createRvaLayout();
  const impBase = reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = reserve(cStringSize(dllName));
  const thunkRva = reserve(IMAGE_THUNK_DATA32_SIZE * 3);
  const mappedHintNameRva = reserve(imageImportByNameSize(mappedName));
  const unmappedHintNameRva = reserve(imageImportByNameSize(unmappedName));
  const mappedHintNameEnd = mappedHintNameRva + imageImportByNameSize(mappedName);
  const unmappedHintNameEnd = unmappedHintNameRva + imageImportByNameSize(unmappedName);
  const bytes = new Uint8Array(reserve(0)).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(impBase + 0, thunkRva, true);
  dv.setUint32(impBase + 12, dllNameRva, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));
  dv.setUint32(thunkRva, mappedHintNameRva, true);
  dv.setUint32(thunkRva + IMAGE_THUNK_DATA32_SIZE, unmappedHintNameRva, true);
  dv.setUint32(thunkRva + IMAGE_THUNK_DATA32_SIZE * 2, 0, true);
  dv.setUint16(mappedHintNameRva, mappedHint, true);
  encoder.encodeInto(
    `${mappedName}\0`,
    new Uint8Array(bytes.buffer, mappedHintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE)
  );
  dv.setUint16(unmappedHintNameRva, unmappedHint, true);
  encoder.encodeInto(
    `${unmappedName}\0`,
    new Uint8Array(bytes.buffer, unmappedHintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE)
  );

  const sparseRvaToOff = (rva: number): number | null => {
    // Only the first thunk slot maps. A parser that assumes the table stays contiguous in file offsets will
    // incorrectly read the second thunk from raw bytes instead of respecting the RVA mapper for each entry.
    if (rva === impBase || rva === dllNameRva || rva === thunkRva) return rva;
    if (rva >= mappedHintNameRva && rva < mappedHintNameEnd) return rva;
    if (rva >= unmappedHintNameRva && rva < unmappedHintNameEnd) return rva;
    return null;
  };

  const { entries, warning } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: IMPORT_DIRECTORY_SIZE }],
    sparseRvaToOff,
    () => {}
  );

  const firstImport = expectDefined(entries[0]);
  assert.deepEqual(firstImport.functions, [{ hint: mappedHint, name: mappedName }]);
  assert.ok(warning && /truncated|unmapped|thunk/i.test(warning));
});

void test("parseImportDirectory walks the full null-terminated PE32+ thunk array without a fixed cap", async () => {
  // Import lookup/name tables are null-terminated IMAGE_THUNK_DATA arrays; the format does not define a 16384-entry cap.
  const importCount = 16385; // Deliberately 16384 + 1 to prove the parser must follow the null terminator instead of a loop cap.
  const dllName = "KERNEL32.dll";
  const reserve = createRvaLayout();
  const descriptorOffset = reserve(IMPORT_DIRECTORY_SIZE);
  const dllNameRva = reserve(cStringSize(dllName));
  const thunkRva = reserve((importCount + 1) * IMAGE_THUNK_DATA64_SIZE);
  const bytes = new Uint8Array(reserve(0)).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(descriptorOffset + 12, dllNameRva, true);
  dv.setUint32(descriptorOffset + 16, thunkRva, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));
  for (let index = 0; index < importCount; index += 1) {
    dv.setBigUint64(thunkRva + index * IMAGE_THUNK_DATA64_SIZE, IMAGE_ORDINAL_FLAG64 | BigInt(index + 1), true);
  }
  dv.setBigUint64(thunkRva + importCount * IMAGE_THUNK_DATA64_SIZE, 0n, true);

  const { entries } = await parseImportDirectory64(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: descriptorOffset, size: IMPORT_DIRECTORY_SIZE }],
    value => value,
    () => {}
  );

  const firstImport = expectDefined(entries[0]);
  assert.equal(firstImport.functions.length, importCount);
  assert.deepEqual(firstImport.functions.at(-1), { ordinal: importCount });
});

void test("parseImportDirectory does not treat a partially non-zero descriptor as the null terminator", async () => {
  const dllName = "KERNEL32.dll";
  const reserve = createRvaLayout();
  const impBase = reserve(IMPORT_DIRECTORY_SIZE + IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const dllNameRva = reserve(cStringSize(dllName));
  const thunkRva = reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const bytes = new Uint8Array(reserve(0)).fill(0);
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format, Import Directory Table:
  // the terminator is an empty descriptor filled with null values, not merely one with zero Name/Thunk RVAs.
  dv.setUint32(impBase + 4, 0x12345678, true); // Non-zero TimeDateStamp keeps this descriptor malformed, not null.
  dv.setUint32(impBase + IMAGE_IMPORT_DESCRIPTOR_SIZE + 12, dllNameRva, true);
  dv.setUint32(impBase + IMAGE_IMPORT_DESCRIPTOR_SIZE + 16, thunkRva, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));
  dv.setUint32(thunkRva, 0x80000002, true);
  dv.setUint32(thunkRva + IMAGE_THUNK_DATA32_SIZE, 0, true);

  const { entries } = await parseImportDirectory32(
    new MockFile(bytes),
    [{ name: "IMPORT", rva: impBase, size: IMPORT_DIRECTORY_SIZE + IMAGE_IMPORT_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  const firstImport = expectDefined(entries[0]);
  assert.equal(entries.length, 1);
  assert.equal(firstImport.dll, dllName);
  assert.deepEqual(firstImport.functions, [{ ordinal: 2 }]);
});
