"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readResourceDirectory } from "../../analyzers/pe/resources/directory-reader.js";
import type { ResourceDirectoryLabelReadResult } from "../../analyzers/pe/resources/directory-rules.js";
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
  describeRelOffsetFailure: (rel, len, subject) => `${subject} failed at ${rel}:${len}`,
  formatRelOffset: rel => `0x${rel.toString(16)}`,
  resolveRvaOffset: rva => rva,
  resolveRelOffset
});

const labelResult = (text: string): ResourceDirectoryLabelReadResult => ({
  text,
  issues: [],
  resourceStringRanges: []
});

const writeHeader = (
  bytes: Uint8Array,
  characteristics: number,
  timeDateStamp: number,
  namedEntries: number,
  idEntries: number
): void => {
  const view = new DataView(bytes.buffer);
  view.setUint32(0, characteristics, true);
  view.setUint32(4, timeDateStamp, true);
  view.setUint16(8, 2, true);
  view.setUint16(10, 3, true);
  view.setUint16(12, namedEntries, true);
  view.setUint16(14, idEntries, true);
};

const writeEntry = (
  bytes: Uint8Array,
  offset: number,
  nameField: number,
  targetField: number
): void => {
  const view = new DataView(bytes.buffer);
  view.setUint32(offset, nameField, true);
  view.setUint32(offset + 4, targetField, true);
};

void test("directory reader exposes entries, metadata, and layout facts", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + ENTRY_BYTES);
  writeHeader(bytes, 0, 0x12345678, 0, 1);
  writeEntry(bytes, DIRECTORY_BYTES, 7, HIGH_BIT | 0x30);
  const reader = createReader(bytes);
  const result = await readResourceDirectory(
    reader,
    { name: "RESOURCE", rva: 0x1000, size: bytes.length },
    createResolver(),
    async () => labelResult(""),
    0
  );

  assert.deepStrictEqual(result.directory, {
    namedEntries: 0,
    idEntries: 1,
    entries: [{ nameIsString: false, subdir: true, nameOrId: 7, target: 0x30 }]
  });
  assert.deepStrictEqual(result.directoryInfo, {
    offset: 0,
    characteristics: 0,
    timeDateStamp: 0x12345678,
    majorVersion: 2,
    minorVersion: 3,
    namedEntries: 0,
    idEntries: 1
  });
  assert.strictEqual(result.maxDirectoryEnd, DIRECTORY_BYTES + ENTRY_BYTES);
  assert.deepStrictEqual(result.resourceSubdirectoryTargets, [0x30]);
  assert.deepStrictEqual(result.issues, []);
  assert.deepStrictEqual(reader.readOffsets, [0, DIRECTORY_BYTES]);
});

void test("directory parser does not build mapping diagnostics for a mapped directory header", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES);
  writeHeader(bytes, 0, 0, 0, 0);
  const result = await readResourceDirectory(
    createReader(bytes),
    { name: "RESOURCE", rva: 0x1000, size: bytes.length },
    {
      ...createResolver(),
      describeRelOffsetFailure: () => {
        throw new Error("mapped directory headers should not request failure diagnostics");
      }
    },
    async () => labelResult(""),
    0
  );

  assert.deepStrictEqual(result.issues, []);
});

void test("directory parser warns for reserved flags and entry counts beyond the resource span", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + ENTRY_BYTES);
  writeHeader(bytes, 0x01000000, 0, 0, 2);
  writeEntry(bytes, DIRECTORY_BYTES, 5, 0);
  const result = await readResourceDirectory(
    createReader(bytes),
    { name: "RESOURCE", rva: 0x1000, size: bytes.length },
    createResolver(),
    async () => labelResult(""),
    0
  );

  assert.deepStrictEqual(result.directory, {
    namedEntries: 0,
    idEntries: 2,
    entries: [{ nameIsString: false, subdir: false, nameOrId: 5, target: 0 }]
  });
  assert.strictEqual(result.directoryInfo?.characteristics, 0x01000000);
  assert.strictEqual(result.maxDirectoryEnd, DIRECTORY_BYTES + ENTRY_BYTES);
  assert.deepStrictEqual(result.issues, [
    "IMAGE_RESOURCE_DIRECTORY.Characteristics at 0x0 is non-zero; "
      + "the field is reserved and should be 0.",
    "Resource directory at 0x0 declares 2 entries, but only 1 fit in the declared span."
  ]);
});

void test("directory parser returns null with a warning when a directory header cannot be mapped", async () => {
  const result = await readResourceDirectory(
    createReader(new Uint8Array(DIRECTORY_BYTES)),
    { name: "RESOURCE", rva: 0x1000, size: DIRECTORY_BYTES },
    createResolver(() => null),
    async () => labelResult(""),
    0
  );

  assert.strictEqual(result.directory, null);
  assert.deepStrictEqual(result.directoryInfo, null);
  assert.match(result.issues.join(" "), /Resource directory at 0x0 failed/i);
});

void test("directory parser returns null with a warning for a truncated directory header", async () => {
  const result = await readResourceDirectory(
    createReader(new Uint8Array(DIRECTORY_BYTES / 2)),
    { name: "RESOURCE", rva: 0x1000, size: DIRECTORY_BYTES },
    createResolver(),
    async () => labelResult(""),
    0
  );

  assert.strictEqual(result.directory, null);
  assert.deepStrictEqual(result.directoryInfo, null);
  assert.match(result.issues.join(" "), /header at 0x0 is truncated/i);
});

void test("directory parser validates named-entry duplicates through the supplied label reader", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + 2 * ENTRY_BYTES);
  writeHeader(bytes, 0, 0, 2, 0);
  writeEntry(bytes, DIRECTORY_BYTES, HIGH_BIT | 0x80, 0);
  writeEntry(bytes, DIRECTORY_BYTES + ENTRY_BYTES, HIGH_BIT | 0x82, 0);
  const labelsRead: number[] = [];
  const result = await readResourceDirectory(
    createReader(bytes),
    { name: "RESOURCE", rva: 0x1000, size: bytes.length },
    createResolver(),
    async rel => {
      labelsRead.push(rel);
      return labelResult("duplicate");
    },
    0
  );

  assert.strictEqual(result.directory?.entries.length, 2);
  assert.strictEqual(result.directory?.namedEntries, 2);
  assert.ok(labelsRead.includes(0x80));
  assert.ok(labelsRead.includes(0x82));
  assert.match(result.issues.join(" "), /duplicate named entries/i);
});

void test("directory parser forwards string ranges collected by name validation", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + 2 * ENTRY_BYTES);
  writeHeader(bytes, 0, 0, 2, 0);
  writeEntry(bytes, DIRECTORY_BYTES, HIGH_BIT | 0x80, 0);
  writeEntry(bytes, DIRECTORY_BYTES + ENTRY_BYTES, HIGH_BIT | 0x84, 0);

  const result = await readResourceDirectory(
    createReader(bytes),
    { name: "RESOURCE", rva: 0x1000, size: bytes.length },
    createResolver(),
    async rel => ({
      text: rel === 0x80 ? "Alpha" : "Beta",
      issues: [],
      resourceStringRanges: [{ start: rel, end: rel + 4 }]
    }),
    0
  );

  assert.deepStrictEqual(result.resourceStringRanges, [
    { start: 0x80, end: 0x84 },
    { start: 0x84, end: 0x88 },
    { start: 0x80, end: 0x84 },
    { start: 0x84, end: 0x88 }
  ]);
});

void test("directory parser passes the computed local directory end to entry validation", async () => {
  const bytes = new Uint8Array(DIRECTORY_BYTES + ENTRY_BYTES);
  writeHeader(bytes, 0, 0, 1, 0);
  writeEntry(bytes, DIRECTORY_BYTES, HIGH_BIT | (DIRECTORY_BYTES + 1), 0);
  const result = await readResourceDirectory(
    createReader(bytes),
    { name: "RESOURCE", rva: 0x1000, size: bytes.length },
    createResolver(),
    async () => labelResult(""),
    0
  );

  assert.deepStrictEqual(result.directory?.entries[0], {
    nameIsString: true,
    subdir: false,
    nameOrId: DIRECTORY_BYTES + 1,
    target: 0,
    invalidNameOffset: true
  });
  assert.deepStrictEqual(result.issues, [
    "Resource string name at 0x11 points into the directory-entry area."
  ]);
});
