"use strict";

import { HEADER_SIZE, hasSqliteSignature, parseDatabaseHeader } from "./header.js";
import { parseSchemaPage } from "./page.js";
import type { SqlitePage, SqliteParseResult } from "./types.js";

const SQLITE_PROBE_LENGTH = 16;

const parseSqlite = async (file: File): Promise<SqliteParseResult | null> => {
  if (file.size < SQLITE_PROBE_LENGTH) return null;
  const headerView = new DataView(
    await file.slice(0, Math.min(file.size, HEADER_SIZE)).arrayBuffer()
  );
  if (!hasSqliteSignature(headerView)) return null;

  const issues: string[] = [];
  const header = parseDatabaseHeader(headerView, file.size, issues);

  let schemaPage: SqlitePage | null = null;
  if (header.pageSizeBytes && header.pageSizeBytes >= HEADER_SIZE) {
    const pageView = new DataView(
      await file.slice(0, Math.min(file.size, header.pageSizeBytes)).arrayBuffer()
    );
    schemaPage = parseSchemaPage(pageView, header, issues);
  } else {
    issues.push("Page size is not available; skipping schema page decode.");
  }

  return { isSqlite: true, header, schemaPage, issues };
};

const buildSqliteLabel = (parsed: SqliteParseResult | null): string | null => {
  if (!parsed) return null;
  const parts: string[] = [];
  if (parsed.header.pageSizeBytes) parts.push(`${parsed.header.pageSizeBytes} byte pages`);
  if (parsed.header.textEncodingName) parts.push(parsed.header.textEncodingName);
  if (parsed.header.databaseSizePages != null) {
    parts.push(`${parsed.header.databaseSizePages} pages`);
  }
  const suffix = parts.length ? ` (${parts.join(", ")})` : "";
  return `SQLite database${suffix}`;
};

export { buildSqliteLabel, hasSqliteSignature, parseSqlite };
