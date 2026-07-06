"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { createCoffDebugStringTable } from "../../../../analyzers/coff/debug-string-table.js";
import {
  createCoffStringTableResolver,
  resolveCoffSectionName
} from "../../../../analyzers/coff/section-string-table.js";
import {
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_RECORD_BYTE_LENGTH
} from "../../../../analyzers/coff/layout.js";
import type { FileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { coffSectionNameOffset, coffSectionNameValue } from "../../../../analyzers/coff/section-name.js";
import { MockFile } from "../../../helpers/mock-file.js";

const FIXTURE_SYMBOL_TABLE_OFFSET = 0x20; // Arbitrary aligned fixture offset, not a COFF field size.

const encodeAscii = (text: string): Uint8Array =>
  Uint8Array.from([...text].map(char => char.charCodeAt(0)));

const createStringTable = (entries: string[], declaredSize?: number): Uint8Array => {
  const entryBytes = entries.map(entry => encodeAscii(entry));
  const actualSize = COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH +
    entryBytes.reduce((sum, entry) => sum + entry.length, 0);
  const bytes = new Uint8Array(actualSize);
  new DataView(bytes.buffer).setUint32(0, declaredSize ?? actualSize, true);
  entryBytes.reduce((cursor, entry) => {
    bytes.set(entry, cursor);
    return cursor + entry.length;
  }, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  return bytes;
};

const createStrictReader = (bytes: Uint8Array, requestedLengths: number[]): FileRangeReader => ({
  size: bytes.length,
  read: (offset, length) => Promise.resolve(
    new DataView(bytes.buffer, bytes.byteOffset + offset, Math.max(0, Math.min(length, bytes.length - offset)))
  ),
  readBytes: (offset, length) => {
    requestedLengths.push(length);
    if (length <= 0) throw new Error("zero-length string-table read");
    if (offset + length > bytes.length) throw new Error("oversized string-table read");
    return Promise.resolve(bytes.subarray(offset, offset + length));
  }
});

const createZeroChunkReader = (bytes: Uint8Array): FileRangeReader => ({
  size: bytes.length,
  read: (offset, length) => Promise.resolve(
    new DataView(bytes.buffer, bytes.byteOffset + offset, Math.max(0, Math.min(length, bytes.length - offset)))
  ),
  readBytes: () => Promise.resolve(new Uint8Array())
});

const createReaderThatMustNotRead = (size: number): FileRangeReader => ({
  size,
  read: () => {
    throw new Error("unexpected string-table read");
  },
  readBytes: () => Promise.resolve(new Uint8Array())
});

void test("createCoffDebugStringTable handles exact size-field-only tables at EOF", async () => {
  const warnings: string[] = [];
  const table = await createCoffDebugStringTable(
    new MockFile(createStringTable([])),
    0,
    warnings.push.bind(warnings)
  );
  const outside = await table?.resolve(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  const beforePayload = await table?.resolve(0);

  assert.equal(table?.readableSize, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  assert.equal(outside?.value, `/${COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH}`);
  assert.match(outside?.warning ?? "", /outside the string table/i);
  assert.equal(beforePayload?.value, "/0");
  assert.match(beforePayload?.warning ?? "", /outside the string table/i);
  assert.deepEqual(warnings, []);
});

void test("createCoffDebugStringTable returns null without warning when the size field is absent", async () => {
  const warnings: string[] = [];
  const table = await createCoffDebugStringTable(
    new MockFile(new Uint8Array(10)),
    8,
    warnings.push.bind(warnings)
  );

  assert.equal(table, null);
  assert.deepEqual(warnings, []);
});

void test("createCoffDebugStringTable reads chunked entries and warns on truncation", async () => {
  const longText = "x".repeat(300);
  const truncated = createStringTable([longText], COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH + longText.length + 8);
  const warnings: string[] = [];
  const table = await createCoffDebugStringTable(new MockFile(truncated), 0, warnings.push.bind(warnings));
  const resolved = await table?.resolve(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);

  assert.equal(resolved?.value, longText);
  assert.match(resolved?.warning ?? "", /not NUL-terminated/i);
  assert.equal(table?.readableSize, truncated.length);
  assert.match(warnings.join(" | "), /string table is truncated/i);
});

void test("createCoffDebugStringTable uses bounded positive chunk reads", async () => {
  const tableBytes = createStringTable(["x".repeat(300)]);
  const prefix = 5;
  const bytes = new Uint8Array(prefix + tableBytes.length);
  bytes.set(tableBytes, prefix);
  const requestedLengths: number[] = [];
  const warnings: string[] = [];

  const table = await createCoffDebugStringTable(
    createStrictReader(bytes, requestedLengths),
    prefix,
    warnings.push.bind(warnings)
  );
  const resolved = await table?.resolve(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);

  assert.equal(resolved?.value, "x".repeat(300));
  assert.match(resolved?.warning ?? "", /not NUL-terminated/i);
  assert.deepEqual(requestedLengths, [256, 44]);
});

void test("createCoffDebugStringTable stops when a reader returns an empty string chunk", async () => {
  const tableBytes = createStringTable(["abc"], COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH + 3);
  const warnings: string[] = [];

  const table = await createCoffDebugStringTable(
    createZeroChunkReader(tableBytes),
    0,
    warnings.push.bind(warnings)
  );
  const resolved = await table?.resolve(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);

  assert.equal(resolved?.value, "");
  assert.match(resolved?.warning ?? "", /not NUL-terminated/i);
});

void test("createCoffDebugStringTable preserves readable size for non-zero table offsets", async () => {
  const prefix = 6;
  const tableBytes = createStringTable(["abc\0"]);
  const bytes = new Uint8Array(prefix + tableBytes.length);
  bytes.set(tableBytes, prefix);
  const warnings: string[] = [];

  const table = await createCoffDebugStringTable(new MockFile(bytes), prefix, warnings.push.bind(warnings));
  const resolved = await table?.resolve(COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);

  assert.equal(table?.readableSize, tableBytes.length);
  assert.equal(resolved?.value, "abc");
  assert.deepEqual(warnings, []);
});

void test("createCoffStringTableResolver validates symbol-table-derived string offsets", async () => {
  const stringTable = createStringTable([".long_name\0"]);
  const numberOfSymbols = 2;
  const stringTableOffset = FIXTURE_SYMBOL_TABLE_OFFSET + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const bytes = new Uint8Array(stringTableOffset + stringTable.length);
  bytes.set(stringTable, stringTableOffset);

  const result = await createCoffStringTableResolver(
    new MockFile(bytes),
    FIXTURE_SYMBOL_TABLE_OFFSET,
    numberOfSymbols
  );
  const resolved = await resolveCoffSectionName("/4", result.resolver);
  const beforePayload = await resolveCoffSectionName("/0", result.resolver);
  const inlineDigits = await resolveCoffSectionName("12", result.resolver);

  assert.equal(coffSectionNameValue(resolved.name), ".long_name");
  assert.equal(coffSectionNameOffset(resolved.name), COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  assert.equal(resolved.warning, undefined);
  assert.equal(coffSectionNameValue(beforePayload.name), "/0");
  assert.match(beforePayload.warning ?? "", /outside the COFF string table/i);
  assert.equal(coffSectionNameValue(inlineDigits.name), "12");
  assert.equal(coffSectionNameOffset(inlineDigits.name), null);
});

void test("createCoffStringTableResolver uses bounded positive chunk reads", async () => {
  const numberOfSymbols = 1;
  const stringTableOffset = FIXTURE_SYMBOL_TABLE_OFFSET + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const tableBytes = createStringTable(["y".repeat(300)]);
  const bytes = new Uint8Array(stringTableOffset + tableBytes.length);
  bytes.set(tableBytes, stringTableOffset);
  const requestedLengths: number[] = [];

  const result = await createCoffStringTableResolver(
    createStrictReader(bytes, requestedLengths),
    FIXTURE_SYMBOL_TABLE_OFFSET,
    numberOfSymbols
  );
  const resolved = await resolveCoffSectionName("/4", result.resolver);

  assert.equal(coffSectionNameValue(resolved.name), "y".repeat(300));
  assert.match(resolved.warning ?? "", /not NUL-terminated/i);
  assert.deepEqual(requestedLengths, [256, 44]);
});

void test("createCoffStringTableResolver stops when a reader returns an empty string chunk", async () => {
  const numberOfSymbols = 1;
  const stringTableOffset = FIXTURE_SYMBOL_TABLE_OFFSET + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const tableBytes = createStringTable(["abc"], COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH + 3);
  const bytes = new Uint8Array(stringTableOffset + tableBytes.length);
  bytes.set(tableBytes, stringTableOffset);

  const result = await createCoffStringTableResolver(
    createZeroChunkReader(bytes),
    FIXTURE_SYMBOL_TABLE_OFFSET,
    numberOfSymbols
  );
  const resolved = await resolveCoffSectionName("/4", result.resolver);

  assert.equal(coffSectionNameValue(resolved.name), "");
  assert.match(resolved.warning ?? "", /not NUL-terminated/i);
});

void test("createCoffStringTableResolver rejects impossible symbol-table positions", async () => {
  const truncated = await createCoffStringTableResolver(
    new MockFile(new Uint8Array(64)),
    50,
    1
  );
  const missing = await createCoffStringTableResolver(new MockFile(new Uint8Array(64)), 0, 1);
  const notLong = await resolveCoffSectionName("4", null);
  const slashOnly = await resolveCoffSectionName("/", null);
  const nonDecimal = await resolveCoffSectionName("/abc", null);
  const zeroSymbols = await createCoffStringTableResolver(createReaderThatMustNotRead(64), 16, 0);
  const beyondFile = await createCoffStringTableResolver(createReaderThatMustNotRead(64), 50, 1);
  const unsafe = await createCoffStringTableResolver(
    createReaderThatMustNotRead(Number.MAX_VALUE),
    Number.MAX_SAFE_INTEGER,
    1
  );

  assert.equal(truncated.resolver, null);
  assert.match(truncated.warning ?? "", /does not fit/i);
  assert.equal(missing.resolver, null);
  assert.equal(missing.warning, undefined);
  assert.equal(coffSectionNameValue(notLong.name), "4");
  assert.equal(coffSectionNameValue(slashOnly.name), "/");
  assert.equal(coffSectionNameValue(nonDecimal.name), "/abc");
  assert.equal(zeroSymbols.resolver, null);
  assert.equal(zeroSymbols.warning, undefined);
  assert.equal(beyondFile.resolver, null);
  assert.match(beyondFile.warning ?? "", /does not fit/i);
  assert.equal(unsafe.resolver, null);
  assert.match(unsafe.warning ?? "", /does not fit/i);
});

void test("createCoffStringTableResolver treats mixed decimal text as inline names", async () => {
  const startsDecimal = await resolveCoffSectionName("/12abc", null);
  const endsDecimal = await resolveCoffSectionName("/abc12", null);

  assert.equal(coffSectionNameValue(startsDecimal.name), "/12abc");
  assert.equal(coffSectionNameOffset(startsDecimal.name), null);
  assert.equal(coffSectionNameValue(endsDecimal.name), "/abc12");
  assert.equal(coffSectionNameOffset(endsDecimal.name), null);
});

void test("createCoffStringTableResolver warns when the size-field read is short", async () => {
  const shortReadReader: FileRangeReader = {
    size: 128,
    read: () => Promise.resolve(new DataView(new ArrayBuffer(2))),
    readBytes: () => Promise.resolve(new Uint8Array())
  };

  const result = await createCoffStringTableResolver(shortReadReader, 16, 1);

  assert.equal(result.resolver, null);
  assert.match(result.warning ?? "", /does not fit within the file/i);
});
