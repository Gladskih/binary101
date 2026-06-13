"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readResourceDirectoryEntries } from "../../analyzers/pe/resources/directory-entry-reader.js";
import type { ResourceSpanResolver } from "../../analyzers/pe/resources/relative-offsets.js";
import type { FileRangeReader } from "../../analyzers/file-range-reader.js";

// Microsoft PE/COFF, ".rsrc Section": IMAGE_RESOURCE_DIRECTORY is 16 bytes,
// IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
const DIRECTORY_BYTES = 16;
const ENTRY_BYTES = 8;
// Microsoft PE/COFF, "Resource Directory Entries": the high bit flags string names
// and subdirectory targets.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
const HIGH_BIT = 0x80000000;

const writeEntry = (
  bytes: Uint8Array,
  offset: number,
  nameField: number,
  targetField: number
): void => {
  new DataView(bytes.buffer).setUint32(offset, nameField, true);
  new DataView(bytes.buffer).setUint32(offset + 4, targetField, true);
};

const createReader = (bytes: Uint8Array): FileRangeReader & { readOffsets: number[] } => {
  const readOffsets: number[] = [];
  return {
    size: bytes.length,
    read: async (offset, size) => {
      readOffsets.push(offset);
      return new DataView(bytes.buffer, offset, Math.max(0, Math.min(size, bytes.length - offset)));
    },
    readBytes: async (offset, size) => new Uint8Array(bytes.buffer, offset, Math.min(size, bytes.length - offset)),
    readOffsets
  };
};

const createResolver = (
  resolveRelOffset: (rel: number, len: number) => number | null = rel => rel
): ResourceSpanResolver => ({
  describeRelOffsetFailure: rel => `failure:${rel.toString(16)}`,
  formatRelOffset: rel => `0x${rel.toString(16)}`,
  resolveRvaOffset: rva => rva,
  resolveRelOffset
});

void test("entry reader decodes a bulk-read table and records malformed entry warnings", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + 2 * ENTRY_BYTES);
  writeEntry(bytes, DIRECTORY_BYTES, 0x12345, HIGH_BIT);
  writeEntry(bytes, DIRECTORY_BYTES + ENTRY_BYTES, HIGH_BIT | 0x12, 0);

  const table = await readResourceDirectoryEntries(
    createReader(bytes),
    createResolver(),
    0,
    2,
    DIRECTORY_BYTES + 2 * ENTRY_BYTES
  );

  assert.deepStrictEqual(table.entries, [
    { nameIsString: false, subdir: true, nameOrId: 0x12345, target: 0 },
    { nameIsString: true, subdir: false, nameOrId: 0x12, target: 0, invalidNameOffset: true }
  ]);
  assert.deepStrictEqual(table.resourceSubdirectoryTargets, [0]);
  assert.deepStrictEqual(table.issues, [
    "Resource directory at 0x0 has a subdirectory entry that points to itself.",
    "Resource string name at 0x12 points into the directory-entry area."
  ]);
});

void test("entry reader accepts string names at the first byte after the entry table", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + ENTRY_BYTES);
  writeEntry(bytes, DIRECTORY_BYTES, HIGH_BIT | (DIRECTORY_BYTES + ENTRY_BYTES), 0);

  const table = await readResourceDirectoryEntries(
    createReader(bytes),
    createResolver(),
    0,
    1,
    DIRECTORY_BYTES + ENTRY_BYTES
  );

  assert.deepStrictEqual(table.entries, [
    { nameIsString: true, subdir: false, nameOrId: DIRECTORY_BYTES + ENTRY_BYTES, target: 0 }
  ]);
  assert.deepStrictEqual(table.issues, []);
});

void test("entry reader returns no entries without touching file data for an empty table", async () => {
  const reader = createReader(new Uint8Array(DIRECTORY_BYTES));

  const table = await readResourceDirectoryEntries(
    reader,
    createResolver(),
    0,
    0,
    DIRECTORY_BYTES
  );

  assert.deepStrictEqual(table.entries, []);
  assert.deepStrictEqual(reader.readOffsets, []);
});

void test("entry reader falls back to individual entries when the full table is unmappable", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + 2 * ENTRY_BYTES);
  writeEntry(bytes, DIRECTORY_BYTES, 7, 0);
  writeEntry(bytes, DIRECTORY_BYTES + ENTRY_BYTES, 8, 0);
  const resolver = createResolver((rel, len) => {
    if (len === 2 * ENTRY_BYTES) return null;
    if (rel === DIRECTORY_BYTES + ENTRY_BYTES) return null;
    return rel;
  });

  const table = await readResourceDirectoryEntries(
    createReader(bytes),
    resolver,
    0,
    2,
    DIRECTORY_BYTES + 2 * ENTRY_BYTES
  );

  assert.deepStrictEqual(table.entries, [
    { nameIsString: false, subdir: false, nameOrId: 7, target: 0 }
  ]);
  assert.deepStrictEqual(table.issues, [
    "Resource directory entries for 0x0 extend past the declared span."
  ]);
});

void test("entry reader fallback reads exactly the declared successful individual entries", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + ENTRY_BYTES);
  writeEntry(bytes, DIRECTORY_BYTES, 11, 0);
  const reader = createReader(bytes);
  let resolveCount = 0;
  const resolver = createResolver(rel => {
    resolveCount += 1;
    return resolveCount === 1 ? null : rel;
  });

  const table = await readResourceDirectoryEntries(
    reader,
    resolver,
    0,
    1,
    DIRECTORY_BYTES + ENTRY_BYTES
  );

  assert.deepStrictEqual(table.entries, [
    { nameIsString: false, subdir: false, nameOrId: 11, target: 0 }
  ]);
  assert.deepStrictEqual(reader.readOffsets, [DIRECTORY_BYTES]);
  assert.deepStrictEqual(table.issues, []);
});

void test("entry reader warns and keeps readable entries when a bulk-read table is truncated", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + ENTRY_BYTES + 4);
  writeEntry(bytes, DIRECTORY_BYTES, 9, 0);

  const table = await readResourceDirectoryEntries(
    createReader(bytes),
    createResolver(),
    0,
    2,
    DIRECTORY_BYTES + 2 * ENTRY_BYTES
  );

  assert.deepStrictEqual(table.entries, [
    { nameIsString: false, subdir: false, nameOrId: 9, target: 0 }
  ]);
  assert.deepStrictEqual(table.issues, [
    "Resource directory entries for 0x0 are truncated."
  ]);
});

void test("entry reader warns and stops when an individual entry read is truncated", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + 4);
  let resolveCount = 0;
  const resolver = createResolver(rel => {
    resolveCount += 1;
    return resolveCount === 1 ? null : rel;
  });

  const table = await readResourceDirectoryEntries(
    createReader(bytes),
    resolver,
    0,
    1,
    DIRECTORY_BYTES + ENTRY_BYTES
  );

  assert.deepStrictEqual(table.entries, []);
  assert.deepStrictEqual(table.issues, [
    "Resource directory entry at 0x10 is truncated."
  ]);
});
