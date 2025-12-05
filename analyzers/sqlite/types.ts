"use strict";

export type SqliteHeader = {
  pageSizeField: number | null;
  pageSizeBytes: number | null;
  usablePageSize: number | null;
  writeVersion: number | null;
  writeVersionMeaning: string | null;
  readVersion: number | null;
  readVersionMeaning: string | null;
  reservedSpace: number | null;
  maxPayloadFraction: number | null;
  minPayloadFraction: number | null;
  leafPayloadFraction: number | null;
  fileChangeCounter: number | null;
  databaseSizePages: number | null;
  databaseSizeBytes: number | null;
  firstFreelistTrunkPage: number | null;
  totalFreelistPages: number | null;
  schemaCookie: number | null;
  schemaFormat: number | null;
  schemaFormatMeaning: string | null;
  defaultPageCacheSize: number | null;
  largestRootPage: number | null;
  textEncoding: number | null;
  textEncodingName: string | null;
  userVersion: number | null;
  vacuumMode: number | null;
  vacuumModeMeaning: string | null;
  applicationId: number | null;
  versionValidFor: number | null;
  sqliteVersion: number | null;
  sqliteVersionString: string | null;
};

export type SqliteRecordValue = {
  name: string | null;
  serialType: number;
  storageClass: string;
  sizeBytes: number | null;
  value: string | number | bigint | ArrayBuffer | SharedArrayBuffer | null;
  description: string;
  truncated: boolean;
};

export type SqliteRecord = {
  headerSize: number | null;
  serialTypes: number[];
  values: SqliteRecordValue[];
  headerTruncated: boolean;
};

export type SqliteLeafTableCell = {
  offset: number;
  payloadSize: number | null;
  payloadAvailable: number;
  rowId: bigint | null;
  record: SqliteRecord;
  overflow: boolean;
};

export type SqliteBtreeHeader = {
  pageType: number | null;
  pageTypeMeaning: string | null;
  firstFreeblock: number | null;
  cellCount: number | null;
  cellContentStart: number | null;
  fragmentedFreeBytes: number | null;
  rightMostPointer: number | null;
  headerSize: number;
};

export type SqlitePage = {
  pageNumber: number;
  header: SqliteBtreeHeader | null;
  cellOffsets: number[];
  cells: SqliteLeafTableCell[];
  limitedByCellCount: boolean;
  truncated: boolean;
};

export type SqliteParseResult = {
  isSqlite: boolean;
  header: SqliteHeader;
  schemaPage: SqlitePage | null;
  issues: string[];
};
