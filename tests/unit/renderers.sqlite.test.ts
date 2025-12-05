"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSqlite } from "../../renderers/sqlite/index.js";
import { parseSqlite } from "../../analyzers/sqlite/index.js";
import { createSqliteFile } from "../fixtures/sqlite-fixtures.js";
import type { SqliteParseResult } from "../../analyzers/sqlite/types.js";

const cloneParsed = (parsed: SqliteParseResult): SqliteParseResult => ({
  ...parsed,
  header: { ...parsed.header },
  schemaPage: parsed.schemaPage
    ? {
        ...parsed.schemaPage,
        header: parsed.schemaPage.header ? { ...parsed.schemaPage.header } : null,
        cells: parsed.schemaPage.cells.slice()
      }
    : null,
  issues: parsed.issues.slice()
});

void test("renderSqlite handles missing schema pages and warnings", async () => {
  const parsed = await parseSqlite(createSqliteFile());
  assert.ok(parsed);
  const withoutSchema: SqliteParseResult = cloneParsed(parsed);
  withoutSchema.schemaPage = null;
  withoutSchema.issues.push("synthetic SQLite issue");
  withoutSchema.header.writeVersion = null;
  withoutSchema.header.writeVersionMeaning = null;
  const html = renderSqlite(withoutSchema);
  assert.match(html, /SQLite database/);
  assert.match(html, /No schema entries/);
  assert.match(html, /synthetic SQLite issue/);
});

void test("renderSqlite shows schema cell limits and notes", async () => {
  const parsed = await parseSqlite(createSqliteFile());
  assert.ok(parsed?.schemaPage);
  const limited: SqliteParseResult = cloneParsed(parsed);
  if (limited.schemaPage?.header) {
    limited.schemaPage.header.cellCount = (limited.schemaPage.header.cellCount ?? 0) + 3;
    limited.schemaPage.header.rightMostPointer = 2;
  }
  if (limited.schemaPage) {
    limited.schemaPage.limitedByCellCount = true;
    const [firstCell] = limited.schemaPage.cells;
    if (firstCell) {
      firstCell.payloadSize = null;
      firstCell.payloadAvailable = 0;
      firstCell.record.headerTruncated = true;
      firstCell.overflow = true;
      if (firstCell.record.values[0]) firstCell.record.values[0].truncated = true;
      firstCell.record.values = [];
      firstCell.rowId = null;
    }
  }
  limited.header.databaseSizeBytes = null;
  limited.header.databaseSizePages = null;
  const html = renderSqlite(limited);
  assert.match(html, /Only the first/);
  assert.match(html, /sqlite_schema/);
  assert.match(html, /unknown payload/);
  assert.match(html, /Database size<\/dt><dd>Unknown/);
});

void test("renderSqlite returns empty string for null input", () => {
  const html = renderSqlite(null);
  assert.strictEqual(html, "");
});
