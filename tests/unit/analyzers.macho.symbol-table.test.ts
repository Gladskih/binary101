"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSymtab } from "../../analyzers/macho/symbol-table.js";
import {
  BIG_ENDIAN_64_MAGIC,
  LITTLE_ENDIAN_32_MAGIC,
  LITTLE_ENDIAN_64_MAGIC,
  createSymtabHeader
} from "../fixtures/macho-header-test-helpers.js";
import { NLIST32_SIZE, NLIST64_SIZE, writeNlist32, writeNlist64 } from "../fixtures/macho-nlist-test-helpers.js";
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
const textEncoder = new TextEncoder();

void test("parseSymtab reports truncated symbol tables and invalid string indexes", async () => {
  const values = createMachOIncidentalValues();
  const symbolTableOffset = NLIST64_SIZE;
  const stringTableOffset = symbolTableOffset + NLIST64_SIZE;
  const stringBytes = textEncoder.encode(`\0${values.nextLabel("name")}`);
  const invalidStringIndex = stringBytes.length * 2;
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  writeNlist64(bytes, symbolTableOffset, {
    stringIndex: invalidStringIndex,
    type: N_EXT_BIT,
    sectionIndex: 0,
    description: 0,
    value: 0n
  });
  bytes.set(stringBytes, stringTableOffset);
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-negative"),
    0,
    bytes.length,
    createSymtabHeader(LITTLE_ENDIAN_64_MAGIC, EXECUTABLE_FILETYPE, TWOLEVEL_NAMESPACE_FLAG),
    symbolTableOffset,
    2,
    stringTableOffset,
    stringBytes.length
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
    createSymtabHeader(LITTLE_ENDIAN_64_MAGIC, EXECUTABLE_FILETYPE, 0),
    0,
    0,
    stringTableOffset,
    16
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
  writeNlist32(bytes, 0, {
    stringIndex: 1,
    type: N_EXT_BIT | N_SECT,
    sectionIndex: (values.nextUint8() & 0x07) + 1,
    // mach-o/nlist.h: the high byte of n_desc stores library ordinal 1 for
    // MH_TWOLEVEL images.
    description: 0x0100,
    value: symbolValue
  });
  bytes.set(stringBytes, stringTableOffset);
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-32"),
    0,
    bytes.length,
    createSymtabHeader(LITTLE_ENDIAN_32_MAGIC, EXECUTABLE_FILETYPE, TWOLEVEL_NAMESPACE_FLAG),
    0,
    1,
    stringTableOffset,
    stringBytes.length
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
  writeNlist64(bytes, 0, {
    stringIndex: 1,
    type: N_EXT_BIT | N_SECT,
    sectionIndex: 1,
    description: 0,
    value: 0n
  });
  const tracked = createSliceTrackingFile(bytes, 0x100000, "symtab-lazy-strings");
  bytes.set(stringBytes, stringTableOffset);
  const parsed = await parseSymtab(
    tracked.file,
    0,
    tracked.file.size,
    createSymtabHeader(LITTLE_ENDIAN_64_MAGIC, EXECUTABLE_FILETYPE, TWOLEVEL_NAMESPACE_FLAG),
    0,
    1,
    stringTableOffset,
    0xfffe0
  );
  assert.equal(parsed.symbols[0]?.name, symbolName);
  assert.ok(Math.max(...tracked.requests) <= 64 * 1024);
});

void test("parseSymtab warns when symbol names are not NUL-terminated within the string table", async () => {
  const symbolName = "name";
  const stringBytes = textEncoder.encode(symbolName);
  const stringTableOffset = NLIST64_SIZE;
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  writeNlist64(bytes, 0, {
    stringIndex: 0,
    type: N_EXT_BIT | N_SECT,
    sectionIndex: 1,
    description: 0,
    value: 0n
  });
  bytes.set(stringBytes, stringTableOffset);
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-unterminated-name"),
    0,
    bytes.length,
    createSymtabHeader(LITTLE_ENDIAN_64_MAGIC, EXECUTABLE_FILETYPE, TWOLEVEL_NAMESPACE_FLAG),
    0,
    1,
    stringTableOffset,
    stringBytes.length
  );
  assert.equal(parsed.symbols[0]?.name, symbolName);
  assert.match(parsed.issues.join("\n"), /symbol 0 name is not NUL-terminated within the string table/i);
});

void test("parseSymtab preserves SELF_LIBRARY_ORDINAL for defined external symbols", async () => {
  const values = createMachOIncidentalValues();
  const bytes = new Uint8Array(NLIST64_SIZE + 1);
  const stringTableOffset = NLIST64_SIZE;
  writeNlist64(bytes, 0, {
    stringIndex: 0,
    type: N_EXT_BIT | N_SECT,
    sectionIndex: 1,
    description: 0,
    value: BigInt(values.nextUint16() + 0x1000)
  });
  bytes[stringTableOffset] = 0;
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-self-ordinal"),
    0,
    bytes.length,
    createSymtabHeader(LITTLE_ENDIAN_64_MAGIC, EXECUTABLE_FILETYPE, TWOLEVEL_NAMESPACE_FLAG),
    0,
    1,
    stringTableOffset,
    1
  );
  assert.equal(parsed.symbols[0]?.libraryOrdinal, 0);
  assert.deepEqual(parsed.issues, []);
});

void test("parseSymtab rejects non-zero string indexes when the string table is empty", async () => {
  const bytes = new Uint8Array(NLIST64_SIZE);
  writeNlist64(bytes, 0, {
    stringIndex: 1,
    type: N_EXT_BIT | N_SECT,
    sectionIndex: 1,
    description: 0,
    value: 0n
  });
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-empty-strings"),
    0,
    bytes.length,
    createSymtabHeader(LITTLE_ENDIAN_64_MAGIC, EXECUTABLE_FILETYPE, 0),
    0,
    1,
    bytes.length,
    0
  );
  assert.match(parsed.issues.join("\n"), /string index 1 is outside the string table/i);
});

void test("parseSymtab does not treat MH_OBJECT n_desc flags as library ordinals", async () => {
  const values = createMachOIncidentalValues();
  const symbolName = values.nextLabel("object");
  const stringBytes = textEncoder.encode(`\0${symbolName}\0`);
  const stringTableOffset = NLIST64_SIZE;
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  writeNlist64(bytes, 0, {
    stringIndex: 1,
    type: N_EXT_BIT | N_SECT,
    sectionIndex: 1,
    // In MH_OBJECT files these same high-byte bits are object-file flags, not
    // two-level library ordinals.
    description: 0x0100,
    value: BigInt(values.nextUint16() + 0x1000)
  });
  bytes.set(stringBytes, stringTableOffset);
  // mach-o/loader.h: MH_OBJECT == 0x1.
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-object-flags"),
    0,
    bytes.length,
    createSymtabHeader(LITTLE_ENDIAN_64_MAGIC, 0x1, TWOLEVEL_NAMESPACE_FLAG),
    0,
    1,
    stringTableOffset,
    stringBytes.length
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
  writeNlist64(bytes, 0, {
    stringIndex: 1,
    type: N_EXT_BIT | N_SECT,
    sectionIndex: 1,
    // mach-o/nlist.h: without MH_TWOLEVEL, this high byte must not be treated
    // as a bound-library ordinal even though it numerically encodes 1.
    description: 0x0100,
    value: 0n
  });
  bytes.set(stringBytes, stringTableOffset);
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-flat-namespace"),
    0,
    bytes.length,
    createSymtabHeader(LITTLE_ENDIAN_64_MAGIC, EXECUTABLE_FILETYPE, 0),
    0,
    1,
    stringTableOffset,
    stringBytes.length
  );
  assert.equal(parsed.symbols[0]?.libraryOrdinal, null);
  assert.deepEqual(parsed.issues, []);
});

void test("parseSymtab parses big-endian 64-bit symbol entries", async () => {
  const values = createMachOIncidentalValues();
  const symbolName = values.nextLabel("big");
  const stringBytes = textEncoder.encode(`\0${symbolName}\0`);
  const stringTableOffset = NLIST64_SIZE;
  const symbolValue = 0x0102030405060708n;
  const bytes = new Uint8Array(stringTableOffset + stringBytes.length);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  view.setUint32(0, 1, false);
  bytes[4] = N_EXT_BIT | N_SECT;
  bytes[5] = 1;
  view.setUint16(6, 0x0200, false);
  view.setBigUint64(8, symbolValue, false);
  bytes.set(stringBytes, stringTableOffset);
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-big-endian-64"),
    0,
    bytes.length,
    createSymtabHeader(BIG_ENDIAN_64_MAGIC, EXECUTABLE_FILETYPE, TWOLEVEL_NAMESPACE_FLAG),
    0,
    1,
    stringTableOffset,
    stringBytes.length
  );
  assert.equal(parsed.symbols[0]?.name, symbolName);
  assert.equal(parsed.symbols[0]?.value, symbolValue);
  assert.equal(parsed.symbols[0]?.libraryOrdinal, 2);
  assert.deepEqual(parsed.issues, []);
});
