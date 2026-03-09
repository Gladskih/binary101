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

const writeNlist64 = (
  bytes: Uint8Array,
  entryOffset: number,
  options: {
    stringIndex: number;
    type: number;
    sectionIndex: number;
    description: number;
    value: bigint;
  }
): void => {
  // mach-o/nlist.h: nlist_64 stores n_strx/u32, n_type/u8, n_sect/u8,
  // n_desc/u16, n_value/u64 in that order.
  const view = new DataView(bytes.buffer, bytes.byteOffset + entryOffset, NLIST64_SIZE);
  view.setUint32(0, options.stringIndex, true);
  bytes[entryOffset + 4] = options.type;
  bytes[entryOffset + 5] = options.sectionIndex;
  view.setUint16(6, options.description, true);
  view.setBigUint64(8, options.value, true);
};

const writeNlist32 = (
  bytes: Uint8Array,
  entryOffset: number,
  options: {
    stringIndex: number;
    type: number;
    sectionIndex: number;
    description: number;
    value: number;
  }
): void => {
  // mach-o/nlist.h: nlist stores n_strx/u32, n_type/u8, n_sect/u8,
  // n_desc/u16, n_value/u32 in that order.
  const view = new DataView(bytes.buffer, bytes.byteOffset + entryOffset, NLIST32_SIZE);
  view.setUint32(0, options.stringIndex, true);
  bytes[entryOffset + 4] = options.type;
  bytes[entryOffset + 5] = options.sectionIndex;
  view.setUint16(6, options.description, true);
  view.setUint32(8, options.value, true);
};

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
