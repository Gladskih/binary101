"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCoffStringTableResolver,
  resolveSectionName
} from "../../analyzers/pe/coff-string-table.js";
import { peSectionNameOffset, peSectionNameValue } from "../../analyzers/pe/section-name.js";
import { MockFile } from "../helpers/mock-file.js";

// Microsoft PE/COFF: each COFF symbol-table record is 18 bytes.
const IMAGE_SYMBOL_SIZE = 18;
// Microsoft PE/COFF: the string table starts with a 4-byte size field.
const COFF_STRING_TABLE_SIZE_FIELD = 4;

const createCoffStringTable = (names: string[]): { bytes: Uint8Array; offsets: number[] } => {
  const encodedNames = names.map(name => Uint8Array.from([...name, "\0"].map(ch => ch.charCodeAt(0))));
  const size = COFF_STRING_TABLE_SIZE_FIELD + encodedNames.reduce((sum, entry) => sum + entry.length, 0);
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, size, true);
  const offsets: number[] = [];
  let offset = COFF_STRING_TABLE_SIZE_FIELD;
  for (const entry of encodedNames) {
    offsets.push(offset);
    bytes.set(entry, offset);
    offset += entry.length;
  }
  return { bytes, offsets };
};

const createFileWithCoffStringTable = (
  stringTable: Uint8Array,
  pointerToSymbolTable = 0x80,
  numberOfSymbols = 1
): { file: MockFile; pointerToSymbolTable: number; numberOfSymbols: number } => {
  const stringTableOffset = pointerToSymbolTable + numberOfSymbols * IMAGE_SYMBOL_SIZE;
  const bytes = new Uint8Array(stringTableOffset + stringTable.length);
  bytes.set(stringTable, stringTableOffset);
  return { file: new MockFile(bytes), pointerToSymbolTable, numberOfSymbols };
};

class TrackingMockFile extends MockFile {
  readonly sliceSpans: number[] = [];

  override slice(start?: number, end?: number, contentType?: string): Blob {
    this.sliceSpans.push(Math.max(0, (end ?? this.size) - (start ?? 0)));
    return super.slice(start, end, contentType);
  }
}

void test("createCoffStringTableResolver reads only the string-table size before resolving entries", async () => {
  const { bytes: stringTable } = createCoffStringTable([".debug_line", "filler".repeat(1024)]);
  const fixture = createFileWithCoffStringTable(stringTable);
  const trackingFile = new TrackingMockFile(fixture.file.data);

  const result = await createCoffStringTableResolver(
    trackingFile,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );
  if (!result.resolver) assert.fail("expected COFF string-table resolver");

  const resolved = await resolveSectionName("/4", result.resolver);

  assert.equal(peSectionNameValue(resolved.name), ".debug_line");
  assert.equal(result.warning, undefined);
  assert.equal(trackingFile.sliceSpans[0], COFF_STRING_TABLE_SIZE_FIELD);
  assert.ok(
    trackingFile.sliceSpans.reduce((sum, span) => sum + span, 0) < stringTable.length / 2
  );
});

void test("createCoffStringTableResolver warns when the declared string table does not fit within the file", async () => {
  const bytes = new Uint8Array(COFF_STRING_TABLE_SIZE_FIELD).fill(0);
  new DataView(bytes.buffer).setUint32(0, COFF_STRING_TABLE_SIZE_FIELD + 8, true);
  const fixture = createFileWithCoffStringTable(bytes);

  const result = await createCoffStringTableResolver(
    fixture.file,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );

  assert.strictEqual(
    result.warning,
    "COFF string table does not fit within the file; long section names may stay unresolved."
  );
});

void test("createCoffStringTableResolver warns when the string table is smaller than its size field", async () => {
  const bytes = new Uint8Array(COFF_STRING_TABLE_SIZE_FIELD).fill(0);
  new DataView(bytes.buffer).setUint32(0, COFF_STRING_TABLE_SIZE_FIELD - 1, true);
  const fixture = createFileWithCoffStringTable(bytes);

  const result = await createCoffStringTableResolver(
    fixture.file,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );

  assert.strictEqual(result.resolver, null);
  assert.strictEqual(
    result.warning,
    "COFF string table is smaller than its 4-byte size field; long section names may stay unresolved."
  );
});

void test("resolveSectionName returns the resolved name for a valid COFF string-table offset", async () => {
  const { bytes: stringTable, offsets } = createCoffStringTable([".debug_abbrev"]);
  const stringTableOffset = offsets[0];
  if (stringTableOffset == null) assert.fail("missing COFF string-table offset");
  const fixture = createFileWithCoffStringTable(stringTable);
  const result = await createCoffStringTableResolver(
    fixture.file,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );
  if (!result.resolver) assert.fail("missing COFF string-table resolver");

  const resolved = await resolveSectionName(`/${stringTableOffset}`, result.resolver);

  assert.equal(peSectionNameValue(resolved.name), ".debug_abbrev");
  assert.equal(peSectionNameOffset(resolved.name), stringTableOffset);
  assert.equal(resolved.warning, undefined);
});

void test("resolveSectionName warns when the offset points outside the COFF string table", async () => {
  const { bytes: stringTable } = createCoffStringTable([".debug_abbrev"]);
  const outOfRangeOffset = stringTable.length;
  const fixture = createFileWithCoffStringTable(stringTable);
  const result = await createCoffStringTableResolver(
    fixture.file,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );
  if (!result.resolver) assert.fail("missing COFF string-table resolver");

  const resolved = await resolveSectionName(`/${outOfRangeOffset}`, result.resolver);

  assert.equal(peSectionNameValue(resolved.name), `/${outOfRangeOffset}`);
  assert.equal(peSectionNameOffset(resolved.name), outOfRangeOffset);
  assert.equal(
    resolved.warning,
    `Section name string-table offset /${outOfRangeOffset} is outside the COFF string table.`
  );
});

void test("resolveSectionName warns when the COFF string-table entry is not NUL-terminated", async () => {
  const bytes = new Uint8Array(COFF_STRING_TABLE_SIZE_FIELD + 3);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, bytes.length, true);
  bytes.set(Uint8Array.from([0x61, 0x62, 0x63]), COFF_STRING_TABLE_SIZE_FIELD);
  const fixture = createFileWithCoffStringTable(bytes);
  const result = await createCoffStringTableResolver(
    fixture.file,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );
  if (!result.resolver) assert.fail("missing COFF string-table resolver");

  const resolved = await resolveSectionName("/4", result.resolver);

  assert.equal(peSectionNameValue(resolved.name), "abc");
  assert.equal(peSectionNameOffset(resolved.name), 4);
  assert.equal(
    resolved.warning,
    "Section name string-table entry /4 is not NUL-terminated within the COFF string table."
  );
});
