"use strict";

import { MockFile } from "../helpers/mock-file.js";

type SqliteFixtureOptions = {
  pageSizeField?: number;
  textEncoding?: number;
  schemaFormat?: number;
  cellOffset?: number;
  pageCount?: number;
  vacuumMode?: number;
  sqliteVersion?: number;
};

const encoder = new TextEncoder();

const encodeText = (text: string): Uint8Array => encoder.encode(text);

const buildSqliteBytes = (options: SqliteFixtureOptions = {}): Uint8Array => {
  const pageSize = 512;
  const bytes = new Uint8Array(pageSize).fill(0);
  const view = new DataView(bytes.buffer);
  const headerString = "SQLite format 3\u0000";
  for (let index = 0; index < headerString.length; index += 1) {
    bytes[index] = headerString.charCodeAt(index);
  }

  const rawPageSize = options.pageSizeField ?? pageSize;
  view.setUint16(16, rawPageSize, false);
  view.setUint8(18, 1);
  view.setUint8(19, 1);
  view.setUint8(20, 0);
  view.setUint8(21, 64);
  view.setUint8(22, 32);
  view.setUint8(23, 32);
  view.setUint32(24, 1, false);
  view.setUint32(28, options.pageCount ?? 1, false);
  view.setUint32(32, 0, false);
  view.setUint32(36, 0, false);
  view.setUint32(40, 1, false);
  view.setUint32(44, options.schemaFormat ?? 4, false);
  view.setUint32(48, 0, false);
  view.setUint32(52, 0, false);
  view.setUint32(56, options.textEncoding ?? 1, false);
  view.setUint32(60, 0, false);
  view.setUint32(64, options.vacuumMode ?? 0, false);
  view.setUint32(68, 0, false);
  view.setUint32(92, 1, false);
  view.setUint32(96, options.sqliteVersion ?? 3038000, false);

  const typeText = "table";
  const nameText = "sample";
  const tableText = "sample";
  const sqlText = "CREATE TABLE sample(id INTEGER);";
  const rootPageValue = 2;

  const serialType = (length: number): number => 13 + length * 2;
  const serials = [
    serialType(typeText.length),
    serialType(nameText.length),
    serialType(tableText.length),
    1,
    serialType(sqlText.length)
  ];
  const headerLength = 1 + serials.length;
  const payloadSize =
    headerLength + typeText.length + nameText.length + tableText.length + 1 + sqlText.length;

  const cell: number[] = [];
  cell.push(payloadSize); // payload size varint (1 byte)
  cell.push(1); // rowid varint
  cell.push(headerLength);
  cell.push(...serials);
  cell.push(...encodeText(typeText));
  cell.push(...encodeText(nameText));
  cell.push(...encodeText(tableText));
  cell.push(rootPageValue);
  cell.push(...encodeText(sqlText));

  const cellSize = cell.length;
  const cellStartDefault = pageSize - cellSize;
  const cellStart = Math.max(
    108,
    Math.min(options.cellOffset ?? cellStartDefault, pageSize - cellSize)
  );
  const btreeHeaderOffset = 100;
  view.setUint8(btreeHeaderOffset, 13);
  view.setUint16(btreeHeaderOffset + 1, 0, false);
  view.setUint16(btreeHeaderOffset + 3, 1, false);
  view.setUint16(btreeHeaderOffset + 5, cellStart, false);
  view.setUint8(btreeHeaderOffset + 7, 0);
  view.setUint16(btreeHeaderOffset + 8, cellStart, false);

  bytes.set(cell, cellStart);
  return bytes;
};

export const createSqliteFile = (options?: SqliteFixtureOptions): MockFile =>
  new MockFile(buildSqliteBytes(options), "sample.sqlite", "application/vnd.sqlite3");

export const createSqliteWithUnknownEncoding = (): MockFile =>
  createSqliteFile({ textEncoding: 99 });

export const createSqliteWithInvalidPageSize = (): MockFile =>
  createSqliteFile({ pageSizeField: 0 });

export const createTruncatedSqliteHeader = (): MockFile => {
  const base = buildSqliteBytes();
  const truncated = base.slice(0, 64);
  return new MockFile(truncated, "truncated.sqlite", "application/vnd.sqlite3");
};

export const createSqliteWithTruncatedCell = (): MockFile => {
  const base = buildSqliteBytes();
  const shortened = base.slice(0, 480);
  return new MockFile(shortened, "truncated-cell.sqlite", "application/vnd.sqlite3");
};
