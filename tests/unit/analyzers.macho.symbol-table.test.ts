"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSymtab } from "../../analyzers/macho/symbol-table.js";
import { wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";

// mach-o/nlist.h: N_EXT == 0x01.
const N_EXT_BIT = 0x01;
// mach-o/loader.h: MH_EXECUTE == 0x2.
const EXECUTABLE_FILETYPE = 0x2;
// mach-o/loader.h: MH_TWOLEVEL == 0x80.
const TWOLEVEL_NAMESPACE_FLAG = 0x80;
// mach-o/nlist.h: N_SECT == 0x0e.
const N_SECT = 0x0e;
// mach-o/nlist.h: sizeof(struct nlist_64) == 16.
const NLIST64_SIZE = 16;
// mach-o/nlist.h: sizeof(struct nlist) == 12.
const NLIST32_SIZE = 12;
const textEncoder = new TextEncoder();

void test("parseSymtab reports truncated symbol tables and invalid string indexes", async () => {
  const values = createMachOIncidentalValues();
  const symbolTableOffset = NLIST64_SIZE;
  const stringTableOffset = symbolTableOffset + NLIST64_SIZE;
  const stringBytes = textEncoder.encode(`\0${values.nextLabel("name")}`);
  const invalidStringIndex = stringBytes.length * 2;
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(symbolTableOffset, invalidStringIndex, true);
  bytes[symbolTableOffset + 4] = N_EXT_BIT;
  view.setBigUint64(symbolTableOffset + 8, 0n, true);
  bytes.set(stringBytes, stringTableOffset);
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-negative"),
    0,
    bytes.length,
    true,
    true,
    symbolTableOffset,
    2,
    stringTableOffset,
    stringBytes.length,
    EXECUTABLE_FILETYPE,
    TWOLEVEL_NAMESPACE_FLAG
  );
  assert.match(parsed.issues.join("\n"), /declares 2 symbols but only 1 entries fit/);
  assert.match(parsed.issues.join("\n"), new RegExp(`string index ${invalidStringIndex} is outside the string table`));
});

void test("parseSymtab reports string tables that extend past the image", async () => {
  const bytes = new Uint8Array(NLIST64_SIZE * 2);
  const stringTableOffset = bytes.length - 8;
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-short-strings"),
    0,
    bytes.length,
    true,
    true,
    0,
    0,
    stringTableOffset,
    16,
    EXECUTABLE_FILETYPE
  );
  assert.match(parsed.issues[0] || "", /String table extends beyond the Mach-O image/);
});

void test("parseSymtab parses 32-bit symbol entries", async () => {
  const values = createMachOIncidentalValues();
  const symbolName = values.nextLabel("symbol");
  const stringBytes = textEncoder.encode(`\0${symbolName}\0`);
  const stringTableOffset = NLIST32_SIZE;
  const symbolValue = values.nextUint32();
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  bytes[4] = N_EXT_BIT | N_SECT;
  bytes[5] = (values.nextUint8() & 0x07) + 1;
  view.setUint16(6, 0x0100, true);
  view.setUint32(8, symbolValue, true);
  bytes.set(stringBytes, stringTableOffset);

  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-32"),
    0,
    bytes.length,
    false,
    true,
    0,
    1,
    stringTableOffset,
    stringBytes.length,
    EXECUTABLE_FILETYPE,
    TWOLEVEL_NAMESPACE_FLAG
  );

  assert.equal(parsed.symbols.length, 1);
  assert.equal(parsed.symbols[0]?.name, symbolName);
  assert.equal(parsed.symbols[0]?.value, BigInt(symbolValue));
  assert.equal(parsed.symbols[0]?.libraryOrdinal, 1);
  assert.deepEqual(parsed.issues, []);
});

void test("parseSymtab resolves names without reading the full string table", async () => {
  const values = createMachOIncidentalValues();
  const symbolName = values.nextLabel("lazy");
  const stringBytes = textEncoder.encode(`\0${symbolName}\0`);
  const stringTableOffset = NLIST64_SIZE;
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  bytes[4] = N_EXT_BIT | N_SECT;
  bytes[5] = 1;
  view.setBigUint64(8, 0n, true);
  const tracked = createSliceTrackingFile(bytes, 0x100000, "symtab-lazy-strings");
  bytes.set(stringBytes, stringTableOffset);

  const parsed = await parseSymtab(
    tracked.file,
    0,
    tracked.file.size,
    true,
    true,
    0,
    1,
    stringTableOffset,
    0xfffe0,
    EXECUTABLE_FILETYPE,
    TWOLEVEL_NAMESPACE_FLAG
  );

  assert.equal(parsed.symbols[0]?.name, symbolName);
  assert.ok(Math.max(...tracked.requests) <= 64 * 1024);
});

void test("parseSymtab preserves SELF_LIBRARY_ORDINAL for defined external symbols", async () => {
  const values = createMachOIncidentalValues();
  const bytes = new Uint8Array(NLIST64_SIZE + 1);
  const view = new DataView(bytes.buffer);
  const stringTableOffset = NLIST64_SIZE;
  view.setUint32(0, 0, true);
  bytes[4] = N_EXT_BIT | N_SECT;
  bytes[5] = 1;
  view.setBigUint64(8, BigInt(values.nextUint16() + 0x1000), true);
  bytes[stringTableOffset] = 0;

  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-self-ordinal"),
    0,
    bytes.length,
    true,
    true,
    0,
    1,
    stringTableOffset,
    1,
    EXECUTABLE_FILETYPE,
    TWOLEVEL_NAMESPACE_FLAG
  );

  assert.equal(parsed.symbols[0]?.libraryOrdinal, 0);
  assert.deepEqual(parsed.issues, []);
});

void test("parseSymtab rejects non-zero string indexes when the string table is empty", async () => {
  const bytes = new Uint8Array(NLIST64_SIZE);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  bytes[4] = N_EXT_BIT | N_SECT;
  bytes[5] = 1;
  view.setBigUint64(8, 0n, true);

  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-empty-strings"),
    0,
    bytes.length,
    true,
    true,
    0,
    1,
    bytes.length,
    0,
    EXECUTABLE_FILETYPE
  );

  assert.match(parsed.issues.join("\n"), /string index 1 is outside the string table/i);
});

void test("parseSymtab does not treat MH_OBJECT n_desc flags as library ordinals", async () => {
  const values = createMachOIncidentalValues();
  const symbolName = values.nextLabel("object");
  const stringBytes = textEncoder.encode(`\0${symbolName}\0`);
  const stringTableOffset = NLIST64_SIZE;
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  bytes[4] = N_EXT_BIT | N_SECT;
  bytes[5] = 1;
  view.setUint16(6, 0x0100, true);
  view.setBigUint64(8, BigInt(values.nextUint16() + 0x1000), true);
  bytes.set(stringBytes, stringTableOffset);

  // mach-o/loader.h: MH_OBJECT == 0x1.
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-object-flags"),
    0,
    bytes.length,
    true,
    true,
    0,
    1,
    stringTableOffset,
    stringBytes.length,
    0x1
  );

  assert.equal(parsed.symbols[0]?.libraryOrdinal, null);
  assert.deepEqual(parsed.issues, []);
});

void test("parseSymtab ignores library ordinals when MH_TWOLEVEL is not set", async () => {
  const values = createMachOIncidentalValues();
  const symbolName = values.nextLabel("flat");
  const stringBytes = textEncoder.encode(`\0${symbolName}\0`);
  const stringTableOffset = NLIST64_SIZE;
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  bytes[4] = N_EXT_BIT | N_SECT;
  bytes[5] = 1;
  view.setUint16(6, 0x0100, true);
  view.setBigUint64(8, 0n, true);
  bytes.set(stringBytes, stringTableOffset);

  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-flat-namespace"),
    0,
    bytes.length,
    true,
    true,
    0,
    1,
    stringTableOffset,
    stringBytes.length,
    EXECUTABLE_FILETYPE,
    0
  );

  assert.equal(parsed.symbols[0]?.libraryOrdinal, null);
  assert.deepEqual(parsed.issues, []);
});
