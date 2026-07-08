"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { miscProbes } from "../../../../../analyzers/probes/magic-misc.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);
const run = (bytes: ArrayLike<number>): string | null => miscProbes.map(p => p(dvFrom(bytes))).find(Boolean) || null;
// SQLite WAL-index docs define shm files as 32768-byte chunks and iVersion 3007000.
// https://sqlite.org/walformat.html#the_wal_index_file_format
const SQLITE_WAL_INDEX_TEST_CHUNK_SIZE = 32768;
const SQLITE_WAL_INDEX_TEST_VERSION = 3007000;
const sqliteWalIndexWithPaddingByte = (paddingOffset: number): Uint8Array => {
  const bytes = new Uint8Array(SQLITE_WAL_INDEX_TEST_CHUNK_SIZE);
  new DataView(bytes.buffer).setUint32(0, SQLITE_WAL_INDEX_TEST_VERSION, true);
  bytes[paddingOffset] = 1;
  return bytes;
};
const terminfoEntry = (magic: number, nameList = "vt100|DEC VT100"): Uint8Array => {
  const names = new TextEncoder().encode(`${nameList}\0`);
  const numberByteLength = magic === 0x021e ? 4 : 2;
  const booleanCount = 1;
  const numberCount = 1;
  const stringCount = 1;
  const stringTableSize = 4;
  const afterBooleans = 12 + names.length + booleanCount;
  const numbersOffset = afterBooleans + (afterBooleans % 2);
  const bytes = new Uint8Array(numbersOffset + numberCount * numberByteLength + stringCount * 2 + stringTableSize);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, magic, true);
  view.setUint16(2, names.length, true);
  view.setUint16(4, booleanCount, true);
  view.setUint16(6, numberCount, true);
  view.setUint16(8, stringCount, true);
  view.setUint16(10, stringTableSize, true);
  bytes.set(names, 12);
  return bytes;
};
const msDeltaPayload = (marker: string): Uint8Array => {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  // MSDelta PA30 notes: the first 4 bytes are a checksum word before the PA30 marker.
  // https://github.com/smilingthax/msdelta-pa30-format
  view.setUint32(0, 0xfff6c947, false);
  bytes.set([...marker].map(character => character.charCodeAt(0)), 4);
  return bytes;
};
const pythonBytecode = (flags: number): Uint8Array => {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  bytes[0] = 0xcb;
  bytes[1] = 0x0d;
  bytes[2] = 0x0d;
  bytes[3] = 0x0a;
  view.setUint32(4, flags, true);
  return bytes;
};

void test("detects documents, compound files and executables", () => {
  assert.strictEqual(run([0x25, 0x50, 0x44, 0x46, 0x2d]), "PDF document");
  const cfb = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  assert.strictEqual(run(cfb), "Microsoft Compound File (e.g. Office 97-2003, MSI)");
  const lnk = new Uint8Array(0x14);
  const dv = new DataView(lnk.buffer);
  dv.setUint32(0, 0x4c, true);
  dv.setUint32(4, 0x00021401, true);
  dv.setUint8(12, 0xc0);
  dv.setUint8(19, 0x46);
  assert.strictEqual(run(lnk), "Windows shortcut (.lnk)");
  assert.strictEqual(run([0x00, 0x61, 0x73, 0x6d]), "WebAssembly binary (WASM)");
});

void test("detects pdb, dex, djvu and help file signatures", () => {
  const pdbHeader = "Microsoft C/C++ MSF 7.00 Program Database";
  const pdb = new Uint8Array(pdbHeader.length + 1);
  pdb.set([...pdbHeader].map(ch => ch.charCodeAt(0)));
  assert.strictEqual(run(pdb), "Microsoft PDB debug symbols");
  const dex = [..."dex\n035\0"].map(ch => ch.charCodeAt(0));
  assert.strictEqual(run(dex), "Android DEX bytecode");
  const djvu = [..."AT&TFORM"].map(c => c.charCodeAt(0)).concat([0, 0, 0, 0], ..."DJVU".split("").map(c => c.charCodeAt(0)));
  assert.strictEqual(run(djvu), "DjVu document");
  assert.strictEqual(run([0x3f, 0x5f, 0x03, 0x00]), "Windows Help file (HLP)");
});

void test("detects compiled terminfo terminal capability entries", () => {
  assert.strictEqual(
    run(terminfoEntry(0x011a)),
    'Compiled terminfo entry "vt100" (terminal capability database)'
  );
  assert.strictEqual(
    run(terminfoEntry(0x021e, "tmux|tmux terminal multiplexer")),
    'Compiled terminfo entry "tmux" (terminal capability database)'
  );
});

void test("detects GNU gettext compiled message catalogs", () => {
  assert.strictEqual(
    run([0xde, 0x12, 0x04, 0x95]),
    "GNU gettext message catalog (MO translations)"
  );
  assert.strictEqual(
    run([0x95, 0x04, 0x12, 0xde]),
    "GNU gettext message catalog (MO translations)"
  );
});

void test("detects CPython bytecode cache files", () => {
  assert.strictEqual(
    run(pythonBytecode(0)),
    "Python bytecode cache (PYC compiled module)"
  );
  assert.strictEqual(
    run(pythonBytecode(3)),
    "Python bytecode cache (PYC compiled module)"
  );
});

void test("rejects malformed CPython bytecode cache headers", () => {
  assert.strictEqual(run(pythonBytecode(4)), null);
  assert.strictEqual(run(pythonBytecode(0).slice(0, 8)), null);
});

void test("rejects malformed compiled terminfo headers", () => {
  const missingNameTerminator = terminfoEntry(0x011a);
  missingNameTerminator[12 + "vt100|DEC VT100".length] = 0x41;
  assert.strictEqual(run(missingNameTerminator), null);
  const truncatedTables = terminfoEntry(0x021e).slice(0, 16);
  assert.strictEqual(run(truncatedTables), null);
});

void test("detects SQLite WAL-index shared-memory headers", () => {
  const littleEndian = new Uint8Array(SQLITE_WAL_INDEX_TEST_CHUNK_SIZE);
  const littleEndianView = new DataView(littleEndian.buffer);
  littleEndianView.setUint32(0, SQLITE_WAL_INDEX_TEST_VERSION, true);
  assert.strictEqual(run(littleEndian), "SQLite WAL-index shared-memory file");
  const bigEndian = new Uint8Array(SQLITE_WAL_INDEX_TEST_CHUNK_SIZE);
  const bigEndianView = new DataView(bigEndian.buffer);
  bigEndianView.setUint32(0, SQLITE_WAL_INDEX_TEST_VERSION, false);
  assert.strictEqual(run(bigEndian), "SQLite WAL-index shared-memory file");
});

void test("rejects malformed SQLite WAL-index shared-memory headers", () => {
  assert.strictEqual(run([]), null);
  // Correct chunk size and padding are not enough without the WAL-index iVersion.
  assert.strictEqual(run(new Uint8Array(SQLITE_WAL_INDEX_TEST_CHUNK_SIZE)), null);
  // WAL-index header bytes 4..7 are padding and must stay zero.
  assert.strictEqual(run(sqliteWalIndexWithPaddingByte(4)), null);
  assert.strictEqual(run(sqliteWalIndexWithPaddingByte(5)), null);
  assert.strictEqual(run(sqliteWalIndexWithPaddingByte(6)), null);
  assert.strictEqual(run(sqliteWalIndexWithPaddingByte(7)), null);
  const badSize = new Uint8Array(SQLITE_WAL_INDEX_TEST_CHUNK_SIZE + 1);
  new DataView(badSize.buffer).setUint32(0, SQLITE_WAL_INDEX_TEST_VERSION, true);
  assert.strictEqual(run(badSize), null);
});

void test("detects MSDelta Windows servicing patch payload markers", () => {
  assert.strictEqual(run(msDeltaPayload("PA30")), "MSDelta patch payload (PA30)");
  assert.strictEqual(run(msDeltaPayload("PA31")), "MSDelta patch payload (PA31)");
});

void test("rejects malformed MSDelta patch payload markers", () => {
  assert.strictEqual(run(msDeltaPayload("PA3").slice(0, 7)), null);
  assert.strictEqual(run(msDeltaPayload("PA31").reverse()), null);
  assert.strictEqual(run(msDeltaPayload("PA32")), null);
});

void test("returns null for unknown bytes", () => {
  assert.strictEqual(run([0x01, 0x02, 0x03, 0x04]), null);
});
