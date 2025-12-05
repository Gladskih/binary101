"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseForUi } from "../../analyzers/index.js";
import { parseSqlite } from "../../analyzers/sqlite/index.js";
import {
  createSqliteFile,
  createSqliteWithInvalidPageSize,
  createSqliteWithTruncatedCell,
  createSqliteWithUnknownEncoding,
  createTruncatedSqliteHeader
} from "../fixtures/sqlite-fixtures.js";

void test("parseSqlite reads header and schema entries", async () => {
  const parsed = await parseSqlite(createSqliteFile());
  assert.ok(parsed);
  assert.strictEqual(parsed.header.pageSizeBytes, 512);
  assert.strictEqual(parsed.header.textEncodingName, "UTF-8");
  assert.ok(parsed.schemaPage?.header);
  assert.strictEqual(parsed.schemaPage?.cells.length, 1);
  const [cell] = parsed.schemaPage?.cells ?? [];
  assert.ok(cell);
  assert.strictEqual(cell.rowId?.toString(), "1");
  const values = cell.record.values;
  const textValues = values.map(entry => entry.value);
  assert.deepStrictEqual(textValues.slice(0, 3), ["table", "sample", "sample"]);
  assert.strictEqual(textValues[4], "CREATE TABLE sample(id INTEGER);");
});

void test("parseForUi routes SQLite files to the sqlite analyzer", async () => {
  const { analyzer, parsed } = await parseForUi(createSqliteFile());
  assert.strictEqual(analyzer, "sqlite");
  assert.ok(parsed);
});

void test("parseSqlite reports invalid page sizes and skips schema decoding", async () => {
  const parsed = await parseSqlite(createSqliteWithInvalidPageSize());
  assert.ok(parsed);
  assert.strictEqual(parsed.header.pageSizeBytes, null);
  assert.strictEqual(parsed.schemaPage, null);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("page size")));
});

void test("parseSqlite keeps decoding when encoding or payloads are problematic", async () => {
  const unknownEncoding = await parseSqlite(createSqliteWithUnknownEncoding());
  assert.ok(unknownEncoding);
  assert.ok(unknownEncoding.issues.some(issue => issue.toLowerCase().includes("encoding")));

  const truncatedCell = await parseSqlite(createSqliteWithTruncatedCell());
  assert.ok(truncatedCell);
  assert.ok(truncatedCell.schemaPage);
  const cell = truncatedCell.schemaPage?.cells[0];
  assert.ok(cell);
  assert.strictEqual(cell.overflow, true);

  const truncatedHeader = await parseSqlite(createTruncatedSqliteHeader());
  assert.ok(truncatedHeader);
  assert.ok(truncatedHeader.issues.length > 0);
});
