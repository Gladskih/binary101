"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSymtab } from "../../analyzers/macho/symbol-table.js";
import { wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

void test("parseSymtab reports truncated symbol tables and invalid string indexes", async () => {
  const bytes = new Uint8Array(0x24);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x10, 8, true);
  bytes[0x14] = 0x01;
  bytes[0x15] = 0;
  view.setUint16(0x16, 0, true);
  view.setBigUint64(0x18, 0n, true);
  bytes.set(new Uint8Array([0x00, 0x66, 0x6f, 0x6f]), 0x20);
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-negative"),
    0,
    bytes.length,
    true,
    true,
    0x10,
    2,
    0x20,
    4
  );
  assert.match(parsed.issues.join("\n"), /declares 2 symbols but only 1 entries fit/);
  assert.match(parsed.issues.join("\n"), /string index 8 is outside the string table/);
});

void test("parseSymtab reports string tables that extend past the image", async () => {
  const bytes = new Uint8Array(0x20);
  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-short-strings"),
    0,
    bytes.length,
    true,
    true,
    0,
    0,
    0x18,
    16
  );
  assert.match(parsed.issues[0] || "", /String table extends beyond the Mach-O image/);
});

void test("parseSymtab parses 32-bit symbol entries", async () => {
  const bytes = new Uint8Array(0x20);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  bytes[4] = 0x0f;
  bytes[5] = 2;
  view.setUint16(6, 0x0100, true);
  view.setUint32(8, 0x1234, true);
  bytes.set(new Uint8Array([0x00, 0x66, 0x6f, 0x6f, 0x00]), 0x0c);

  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-32"),
    0,
    bytes.length,
    false,
    true,
    0,
    1,
    0x0c,
    5
  );

  assert.equal(parsed.symbols.length, 1);
  assert.equal(parsed.symbols[0]?.name, "foo");
  assert.equal(parsed.symbols[0]?.value, 0x1234n);
  assert.equal(parsed.symbols[0]?.libraryOrdinal, 1);
  assert.deepEqual(parsed.issues, []);
});

void test("parseSymtab resolves names without reading the full string table", async () => {
  const bytes = new Uint8Array(0x25);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  bytes[4] = 0x0f;
  bytes[5] = 1;
  view.setUint16(6, 0, true);
  view.setBigUint64(8, 0n, true);
  bytes.set(new Uint8Array([0x00, 0x66, 0x6f, 0x6f, 0x00]), 0x20);
  const tracked = createSliceTrackingFile(bytes, 0x100000, "symtab-lazy-strings");

  const parsed = await parseSymtab(tracked.file, 0, tracked.file.size, true, true, 0, 1, 0x20, 0xfffe0);

  assert.equal(parsed.symbols[0]?.name, "foo");
  assert.ok(Math.max(...tracked.requests) <= 64 * 1024);
});

void test("parseSymtab preserves SELF_LIBRARY_ORDINAL for defined external symbols", async () => {
  const bytes = new Uint8Array(0x20);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0, true);
  bytes[4] = 0x0f;
  bytes[5] = 1;
  view.setUint16(6, 0, true);
  view.setBigUint64(8, 0x1234n, true);
  bytes[0x10] = 0;

  const parsed = await parseSymtab(
    wrapMachOBytes(bytes, "symtab-self-ordinal"),
    0,
    bytes.length,
    true,
    true,
    0,
    1,
    0x10,
    1
  );

  assert.equal(parsed.symbols[0]?.libraryOrdinal, 0);
  assert.deepEqual(parsed.issues, []);
});
