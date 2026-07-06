"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createCoffStringTableResolver } from "../../../../../analyzers/coff/section-string-table.js";
import { resolvePeSectionName } from "../../../../../analyzers/pe/sections/coff-string-table.js";
import {
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_RECORD_BYTE_LENGTH
} from "../../../../../analyzers/coff/layout.js";
import { peSectionNameOffset, peSectionNameValue } from "../../../../../analyzers/pe/sections/name.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const createCoffStringTable = (names: string[]): { bytes: Uint8Array; offsets: number[] } => {
  const encodedNames = names.map(name => new TextEncoder().encode(`${name}\0`));
  const size = COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH +
    encodedNames.reduce((sum, entry) => sum + entry.length, 0);
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, size, true);
  const table = encodedNames.reduce<{ offsets: number[]; cursor: number }>((acc, entry) => {
    bytes.set(entry, acc.cursor);
    return { offsets: [...acc.offsets, acc.cursor], cursor: acc.cursor + entry.length };
  }, { offsets: [], cursor: COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH });
  return { bytes, offsets: table.offsets };
};

const createFileWithCoffStringTable = (
  stringTable: Uint8Array,
  pointerToSymbolTable = 0x80,
  numberOfSymbols = 1
): { file: MockFile; pointerToSymbolTable: number; numberOfSymbols: number } => {
  const stringTableOffset = pointerToSymbolTable + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
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

void test("resolvePeSectionName reads only the size before resolving entries", async () => {
  const { bytes: stringTable } = createCoffStringTable([".debug_line", "filler".repeat(1024)]);
  const fixture = createFileWithCoffStringTable(stringTable);
  const trackingFile = new TrackingMockFile(fixture.file.data);

  const result = await createCoffStringTableResolver(
    trackingFile,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );
  if (!result.resolver) assert.fail("expected COFF string-table resolver");

  const resolved = await resolvePeSectionName("/4", result.resolver);

  assert.equal(peSectionNameValue(resolved.name), ".debug_line");
  assert.equal(result.readableSize, stringTable.length);
  assert.equal(result.warning, undefined);
  assert.equal(trackingFile.sliceSpans[0], COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  assert.ok(
    trackingFile.sliceSpans.reduce((sum, span) => sum + span, 0) < stringTable.length / 2
  );
});

void test("resolvePeSectionName surfaces warnings when the declared table does not fit", async () => {
  const bytes = new Uint8Array(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH).fill(0);
  new DataView(bytes.buffer).setUint32(0, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH + 8, true);
  const fixture = createFileWithCoffStringTable(bytes);

  const result = await createCoffStringTableResolver(
    fixture.file,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );

  assert.equal(result.readableSize, bytes.length);
  assert.strictEqual(
    result.warning,
    "COFF string table does not fit within the file; long section names may stay unresolved."
  );
});

void test("resolvePeSectionName surfaces warnings when the string table is undersized", async () => {
  const bytes = new Uint8Array(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH).fill(0);
  new DataView(bytes.buffer).setUint32(0, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH - 1, true);
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

void test("resolvePeSectionName returns the resolved name for a valid COFF string-table offset", async () => {
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

  const resolved = await resolvePeSectionName(`/${stringTableOffset}`, result.resolver);

  assert.equal(peSectionNameValue(resolved.name), ".debug_abbrev");
  assert.equal(peSectionNameOffset(resolved.name), stringTableOffset);
  assert.equal(resolved.warning, undefined);
});

void test("resolvePeSectionName warns when the offset points outside the COFF string table", async () => {
  const { bytes: stringTable } = createCoffStringTable([".debug_abbrev"]);
  const outOfRangeOffset = stringTable.length;
  const fixture = createFileWithCoffStringTable(stringTable);
  const result = await createCoffStringTableResolver(
    fixture.file,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );
  if (!result.resolver) assert.fail("missing COFF string-table resolver");

  const resolved = await resolvePeSectionName(`/${outOfRangeOffset}`, result.resolver);

  assert.equal(peSectionNameValue(resolved.name), `/${outOfRangeOffset}`);
  assert.equal(peSectionNameOffset(resolved.name), outOfRangeOffset);
  assert.equal(
    resolved.warning,
    `Section name string-table offset /${outOfRangeOffset} is outside the COFF string table.`
  );
});

void test("resolvePeSectionName warns when the COFF string-table entry is not NUL-terminated", async () => {
  const bytes = new Uint8Array(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH + 3);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, bytes.length, true);
  bytes.set(Uint8Array.from([0x61, 0x62, 0x63]), COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  const fixture = createFileWithCoffStringTable(bytes);
  const result = await createCoffStringTableResolver(
    fixture.file,
    fixture.pointerToSymbolTable,
    fixture.numberOfSymbols
  );
  if (!result.resolver) assert.fail("missing COFF string-table resolver");

  const resolved = await resolvePeSectionName("/4", result.resolver);

  assert.equal(peSectionNameValue(resolved.name), "abc");
  assert.equal(peSectionNameOffset(resolved.name), 4);
  assert.equal(
    resolved.warning,
    "Section name string-table entry /4 is not NUL-terminated within the COFF string table."
  );
});
