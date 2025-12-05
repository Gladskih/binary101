"use strict";

import type { SqliteHeader } from "./types.js";

const SQLITE_HEADER = "SQLite format 3\u0000";
const HEADER_SIZE = 100;

const hasSqliteSignature = (view: DataView): boolean => {
  if (view.byteLength < SQLITE_HEADER.length) return false;
  for (let index = 0; index < SQLITE_HEADER.length; index += 1) {
    if (view.getUint8(index) !== SQLITE_HEADER.charCodeAt(index)) return false;
  }
  return true;
};

const readUint16BE = (
  view: DataView,
  offset: number,
  label: string,
  issues: string[]
): number | null => {
  if (offset + 2 > view.byteLength) {
    issues.push(`${label} is truncated.`);
    return null;
  }
  return view.getUint16(offset, false);
};

const readUint32BE = (
  view: DataView,
  offset: number,
  label: string,
  issues: string[]
): number | null => {
  if (offset + 4 > view.byteLength) {
    issues.push(`${label} is truncated.`);
    return null;
  }
  return view.getUint32(offset, false);
};

const normalizePageSize = (raw: number | null, issues: string[]): number | null => {
  if (raw == null) return null;
  const size = raw === 1 ? 65536 : raw;
  const isPowerOfTwo = (size & (size - 1)) === 0;
  if (!size || size < 512 || size > 65536 || !isPowerOfTwo) {
    issues.push(
      `Page size ${size} bytes is invalid; expected a power of two between 512 and 65536.`
    );
    return null;
  }
  return size;
};

const describeJournalMode = (mode: number | null): string | null => {
  if (mode === 1) return "Rollback journal (legacy)";
  if (mode === 2) return "Write-Ahead Logging (WAL)";
  return null;
};

const describeSchemaFormat = (schemaFormat: number | null): string | null => {
  if (schemaFormat == null) return null;
  if (schemaFormat === 4) return "Modern format (SQLite 3.7+; default today)";
  if (schemaFormat === 3) return "Format used by mid-era SQLite 3.x releases";
  if (schemaFormat === 2) return "Early SQLite 3.x format (pre-auto-vacuum defaults)";
  if (schemaFormat === 1) return "Original SQLite 3.0.0 format";
  return "Invalid (must be 1 through 4)";
};

const describeVacuumMode = (value: number | null): string | null => {
  if (value == null) return null;
  if (value === 0) return "Auto-vacuum disabled";
  if (value === 1) return "Full auto-vacuum (pages shifted immediately)";
  if (value === 2) return "Incremental auto-vacuum";
  return "Reserved/invalid auto-vacuum setting";
};

const describeEncoding = (code: number | null, issues: string[]): string | null => {
  if (code === 1) return "UTF-8";
  if (code === 2) return "UTF-16LE";
  if (code === 3) return "UTF-16BE";
  if (code == null) return null;
  issues.push(`Unknown text encoding code ${code}; treating text as UTF-8.`);
  return "UTF-8";
};

const toVersionString = (value: number | null): string | null => {
  if (value == null) return null;
  const major = Math.floor(value / 1_000_000);
  const minor = Math.floor(value / 1000) % 1000;
  const patch = value % 1000;
  if (major < 0 || minor < 0 || patch < 0) return null;
  return `${major}.${minor}.${patch}`;
};

const parseDatabaseHeader = (view: DataView, fileSize: number, issues: string[]): SqliteHeader => {
  const rawPageSize = readUint16BE(view, 16, "Page size", issues);
  const pageSize = normalizePageSize(rawPageSize, issues);
  const reservedSpace = view.byteLength >= 21 ? view.getUint8(20) : null;
  if (reservedSpace == null) issues.push("Reserved space per page is missing.");
  const usablePageSize =
    pageSize != null && reservedSpace != null && reservedSpace < pageSize
      ? pageSize - reservedSpace
      : null;
  if (usablePageSize == null && pageSize != null && reservedSpace != null) {
    issues.push("Reserved space is not smaller than the page size.");
  }

  const writeVersion = view.byteLength >= 19 ? view.getUint8(18) : null;
  const readVersion = view.byteLength >= 20 ? view.getUint8(19) : null;

  const maxPayloadFraction = view.byteLength >= 22 ? view.getUint8(21) : null;
  const minPayloadFraction = view.byteLength >= 23 ? view.getUint8(22) : null;
  const leafPayloadFraction = view.byteLength >= 24 ? view.getUint8(23) : null;

  const fileChangeCounter = readUint32BE(view, 24, "File change counter", issues);
  const databaseSizePages = readUint32BE(view, 28, "Database size", issues);
  const databaseSizeBytes =
    pageSize != null && databaseSizePages != null ? pageSize * databaseSizePages : null;
  if (
    databaseSizeBytes != null &&
    Math.abs(databaseSizeBytes - fileSize) > (pageSize ?? 0)
  ) {
    const declared = `Declared database size (${databaseSizeBytes} bytes)`;
    const actual = `file size (${fileSize} bytes).`;
    issues.push(`${declared} does not match ${actual}`);
  }

  const firstFreelistTrunkPage = readUint32BE(view, 32, "First freelist trunk page", issues);
  const totalFreelistPages = readUint32BE(view, 36, "Total freelist pages", issues);
  const schemaCookie = readUint32BE(view, 40, "Schema cookie", issues);
  const schemaFormat = readUint32BE(view, 44, "Schema format number", issues);
  const defaultPageCacheSize = readUint32BE(view, 48, "Default page cache size", issues);
  const largestRootPage = readUint32BE(view, 52, "Largest root b-tree page", issues);
  const textEncoding = readUint32BE(view, 56, "Text encoding", issues);
  const textEncodingName = describeEncoding(textEncoding, issues);
  const userVersion = readUint32BE(view, 60, "User version", issues);
  const vacuumMode = readUint32BE(view, 64, "Auto-vacuum mode", issues);
  const applicationId = readUint32BE(view, 68, "Application ID", issues);
  const versionValidFor = readUint32BE(view, 92, "Version-valid-for", issues);
  const sqliteVersion = readUint32BE(view, 96, "SQLite library version", issues);
  const sqliteVersionString = toVersionString(sqliteVersion);

  const readMeaning = describeJournalMode(readVersion);
  const writeMeaning = describeJournalMode(writeVersion);
  const schemaFormatMeaning = describeSchemaFormat(schemaFormat);
  const vacuumModeMeaning = describeVacuumMode(vacuumMode);

  return {
    pageSizeField: rawPageSize,
    pageSizeBytes: pageSize,
    usablePageSize,
    writeVersion,
    writeVersionMeaning: writeMeaning,
    readVersion,
    readVersionMeaning: readMeaning,
    reservedSpace,
    maxPayloadFraction,
    minPayloadFraction,
    leafPayloadFraction,
    fileChangeCounter,
    databaseSizePages,
    databaseSizeBytes,
    firstFreelistTrunkPage,
    totalFreelistPages,
    schemaCookie,
    schemaFormat,
    schemaFormatMeaning,
    defaultPageCacheSize,
    largestRootPage,
    textEncoding,
    textEncodingName,
    userVersion,
    vacuumMode,
    vacuumModeMeaning,
    applicationId,
    versionValidFor,
    sqliteVersion,
    sqliteVersionString
  };
};

export {
  HEADER_SIZE,
  SQLITE_HEADER,
  describeEncoding,
  hasSqliteSignature,
  parseDatabaseHeader
};
