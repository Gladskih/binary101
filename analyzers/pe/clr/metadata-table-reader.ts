"use strict";

import type { PeClrMetadataIndex, PeClrTableRowCount } from "./types.js";
import {
  codedIndexSchemaByName,
  CLRMETADATA_TABLES,
  metadataToken,
  tableNameById,
  tableSchemaById,
  type ClrMetadataColumnSchema,
  type ClrMetadataTableSchema
} from "./metadata-schema.js";

export type ClrMetadataCell = number | PeClrMetadataIndex;
export type ClrMetadataRow = Record<string, ClrMetadataCell>;

export interface ClrParsedTable {
  schema: ClrMetadataTableSchema;
  rowSize: number;
  rows: ClrMetadataRow[];
}

export interface ClrParsedTableStream {
  streamName: "#~" | "#-";
  majorVersion: number;
  minorVersion: number;
  heapSizes: number;
  largestRidLog2: number;
  extraData?: number;
  validMask: bigint;
  sortedMask: bigint;
  heapIndexSizes: {
    string: number;
    guid: number;
    blob: number;
  };
  rowCounts: PeClrTableRowCount[];
  tables: Map<number, ClrParsedTable>;
}

interface ReaderState {
  view: DataView;
  offset: number;
}

const isPresent = (mask: bigint, tableId: number): boolean =>
  ((mask >> BigInt(tableId)) & 1n) !== 0n;

const readUnsigned = (state: ReaderState, size: number): number | null => {
  if (state.offset + size > state.view.byteLength) return null;
  const value = size === 1
    ? state.view.getUint8(state.offset)
    : size === 2
      ? state.view.getUint16(state.offset, true)
      : state.view.getUint32(state.offset, true);
  state.offset += size;
  return value;
};

const knownTableIds = new Set(CLRMETADATA_TABLES.map(table => table.id));

// ECMA-335 II.24.2.6 defines the low three HeapSizes bits. CoreCLR's
// CMiniMdSchemaBase persists the same byte as m_heaps and adds schema flags:
// https://github.com/dotnet/runtime/blob/main/src/coreclr/md/inc/metamodel.h
const HEAP_STRING_4 = 0x01;
const HEAP_GUID_4 = 0x02;
const HEAP_BLOB_4 = 0x04;
const HEAP_PADDING_BIT = 0x08;
const HEAP_DELTA_ONLY = 0x20;
const HEAP_EXTRA_DATA = 0x40;
const HEAP_HAS_DELETE = 0x80;
const KNOWN_HEAP_FLAGS =
  HEAP_STRING_4 |
  HEAP_GUID_4 |
  HEAP_BLOB_4 |
  HEAP_PADDING_BIT |
  HEAP_DELTA_ONLY |
  HEAP_EXTRA_DATA |
  HEAP_HAS_DELETE;

const rowCountFor = (rowCounts: Map<number, number>, tableId: number): number =>
  rowCounts.get(tableId) ?? 0;

const tableIndexSize = (rowCounts: Map<number, number>, tableId: number): number =>
  // ECMA-335 II.24.2.6: table indexes are 2 bytes unless the target table has 2^16 rows or more.
  rowCountFor(rowCounts, tableId) >= 0x10000 ? 4 : 2;

const codedIndexSize = (
  rowCounts: Map<number, number>,
  codedIndexName: string,
  issues: string[]
): number => {
  const schema = codedIndexSchemaByName(codedIndexName);
  if (!schema) {
    issues.push(`Unknown CLR coded index ${codedIndexName}.`);
    return 4;
  }
  const maxRows = Math.max(...schema.tables.map(tableId => tableId < 0 ? 0 : rowCountFor(rowCounts, tableId)));
  return maxRows >= (1 << (16 - schema.tagBits)) ? 4 : 2;
};

const columnSize = (
  column: ClrMetadataColumnSchema,
  rowCounts: Map<number, number>,
  heapIndexSizes: ClrParsedTableStream["heapIndexSizes"],
  issues: string[]
): number => {
  if (column.kind === "u8") return 1;
  if (column.kind === "u16") return 2;
  if (column.kind === "u32") return 4;
  if (column.kind === "string") return heapIndexSizes.string;
  if (column.kind === "guid") return heapIndexSizes.guid;
  if (column.kind === "blob") return heapIndexSizes.blob;
  if (column.kind === "table" && column.table != null) return tableIndexSize(rowCounts, column.table);
  if (column.kind === "coded" && column.coded) return codedIndexSize(rowCounts, column.coded, issues);
  issues.push(`Column ${column.name} has an incomplete CLR metadata schema.`);
  return 4;
};

const decodeTableIndex = (
  raw: number,
  tableId: number,
  rowCounts: Map<number, number>
): PeClrMetadataIndex => ({
  table: tableNameById(tableId),
  tableId,
  row: raw,
  raw,
  valid: raw === 0 || raw <= rowCountFor(rowCounts, tableId),
  ...(raw ? { token: metadataToken(tableId, raw) } : {})
} as PeClrMetadataIndex);

const decodeCodedIndex = (
  raw: number,
  codedIndexName: string,
  rowCounts: Map<number, number>,
  issues: string[]
): PeClrMetadataIndex => {
  const schema = codedIndexSchemaByName(codedIndexName);
  if (!schema) {
    return { table: "Unknown", tableId: -1, row: 0, raw, valid: false };
  }
  const tag = raw & ((1 << schema.tagBits) - 1);
  const row = raw >>> schema.tagBits;
  const tableId = schema.tables[tag] ?? -1;
  if (tableId < 0) {
    if (raw !== 0) issues.push(`CLR coded index ${codedIndexName} uses reserved tag ${tag}.`);
    return { table: row === 0 ? "null" : "Reserved", tableId, row, raw, tag, valid: raw === 0 };
  }
  return {
    table: tableNameById(tableId),
    tableId,
    row,
    raw,
    tag,
    valid: row === 0 || row <= rowCountFor(rowCounts, tableId),
    ...(row ? { token: metadataToken(tableId, row) } : {})
  } as PeClrMetadataIndex;
};

const readCell = (
  state: ReaderState,
  column: ClrMetadataColumnSchema,
  rowCounts: Map<number, number>,
  heapIndexSizes: ClrParsedTableStream["heapIndexSizes"],
  issues: string[]
): ClrMetadataCell => {
  const size = columnSize(column, rowCounts, heapIndexSizes, issues);
  const raw = readUnsigned(state, size) ?? 0;
  if (column.kind === "table" && column.table != null) {
    return decodeTableIndex(raw, column.table, rowCounts);
  }
  if (column.kind === "coded" && column.coded) {
    return decodeCodedIndex(raw, column.coded, rowCounts, issues);
  }
  return raw;
};

const readRow = (
  state: ReaderState,
  schema: ClrMetadataTableSchema,
  rowCounts: Map<number, number>,
  heapIndexSizes: ClrParsedTableStream["heapIndexSizes"],
  issues: string[]
): ClrMetadataRow => {
  const row: ClrMetadataRow = {};
  schema.columns.forEach(column => {
    row[column.name] = readCell(state, column, rowCounts, heapIndexSizes, issues);
  });
  return row;
};

const readRowCounts = (
  state: ReaderState,
  validMask: bigint,
  sortedMask: bigint,
  issues: string[]
): { rowCountList: PeClrTableRowCount[]; rowCountMap: Map<number, number> } => {
  const rowCountList: PeClrTableRowCount[] = [];
  const rowCountMap = new Map<number, number>();
  for (let tableId = 0; tableId < 64; tableId += 1) {
    if (!isPresent(validMask, tableId)) continue;
    const rows = readUnsigned(state, 4);
    if (rows == null) {
      issues.push("CLR metadata table stream is truncated in the row-count array.");
      break;
    }
    rowCountMap.set(tableId, rows);
    rowCountList.push({
      tableId,
      name: tableNameById(tableId),
      rows,
      known: knownTableIds.has(tableId),
      sorted: isPresent(sortedMask, tableId)
    });
  }
  return { rowCountList, rowCountMap };
};

const parseTables = (
  state: ReaderState,
  rowCounts: Map<number, number>,
  heapIndexSizes: ClrParsedTableStream["heapIndexSizes"],
  issues: string[]
): Map<number, ClrParsedTable> => {
  const tables = new Map<number, ClrParsedTable>();
  for (let tableId = 0; tableId < 64; tableId += 1) {
    const rows = rowCountFor(rowCounts, tableId);
    if (rows === 0) continue;
    const schema = tableSchemaById(tableId);
    if (!schema) {
      issues.push(`CLR metadata table ${tableNameById(tableId)} is present but unsupported.`);
      break;
    }
    const rowSize = schema.columns.reduce(
      (total, column) => total + columnSize(column, rowCounts, heapIndexSizes, issues),
      0
    );
    const availableRows = Math.min(rows, Math.floor((state.view.byteLength - state.offset) / rowSize));
    if (availableRows < rows) {
      issues.push(`CLR metadata table ${schema.name} is truncated; ${availableRows}/${rows} rows parsed.`);
    }
    tables.set(tableId, {
      schema,
      rowSize,
      rows: Array.from({ length: availableRows }, () =>
        readRow(state, schema, rowCounts, heapIndexSizes, issues))
    });
    if (availableRows < rows) break;
  }
  return tables;
};

export const parseMetadataTableStream = (
  bytes: Uint8Array,
  streamName: "#~" | "#-",
  issues: string[]
): ClrParsedTableStream | null => {
  if (bytes.length < 24) {
    issues.push(`CLR metadata ${streamName} stream is smaller than the ECMA-335 table header.`);
    return null;
  }
  const state: ReaderState = { view: new DataView(bytes.buffer, bytes.byteOffset, bytes.length), offset: 0 };
  const reserved = readUnsigned(state, 4) ?? 0;
  const majorVersion = readUnsigned(state, 1) ?? 0;
  const minorVersion = readUnsigned(state, 1) ?? 0;
  const heapSizes = readUnsigned(state, 1) ?? 0;
  const largestRidLog2 = readUnsigned(state, 1) ?? 0;
  const validMask = state.view.getBigUint64(state.offset, true);
  state.offset += 8;
  const sortedMask = state.view.getBigUint64(state.offset, true);
  state.offset += 8;
  if (reserved !== 0) {
    issues.push("CLR metadata table stream reserved header field has an unexpected value.");
  }
  if ((heapSizes & ~KNOWN_HEAP_FLAGS) !== 0) {
    issues.push("CLR metadata HeapSizes contains unknown CoreCLR schema flag bits.");
  }
  // ECMA-335 II.24.2.6: HeapSizes bits 0, 1, and 2 select 4-byte #Strings/#GUID/#Blob indexes.
  const heapIndexSizes = {
    string: (heapSizes & HEAP_STRING_4) !== 0 ? 4 : 2,
    guid: (heapSizes & HEAP_GUID_4) !== 0 ? 4 : 2,
    blob: (heapSizes & HEAP_BLOB_4) !== 0 ? 4 : 2
  };
  const rowCounts = readRowCounts(state, validMask, sortedMask, issues);
  const extraData = (heapSizes & HEAP_EXTRA_DATA) !== 0
    ? readUnsigned(state, 4)
    : undefined;
  if (extraData === null) {
    issues.push("CLR metadata table stream declares extra schema data but is truncated before it.");
  }
  return {
    streamName,
    majorVersion,
    minorVersion,
    heapSizes,
    largestRidLog2,
    ...(typeof extraData === "number" ? { extraData } : {}),
    validMask,
    sortedMask,
    heapIndexSizes,
    rowCounts: rowCounts.rowCountList,
    tables: parseTables(state, rowCounts.rowCountMap, heapIndexSizes, issues)
  };
};
