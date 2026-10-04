"use strict";

import type { PeClrAdditionalCell, PeClrAdditionalTable } from "./types.js";
import type { ClrHeapReaders } from "./metadata-heaps.js";
import type { ClrMetadataColumnSchema } from "./metadata-schema.js";
import type { ClrMetadataCell, ClrParsedTableStream } from "./metadata-table-reader.js";
import {
  parseMethodSpecSignature, parsePropertySignature, parseStandaloneSignature, parseTypeSpecSignature
} from "./metadata-spec-signatures.js";

// Tables already represented by named records in metadata-model.ts; all other ECMA-335 II.22
// tables retain every column. Decode heap references once and share index objects with the reader.
const MODELED_TABLES = new Set([
  0x00, 0x01, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c,
  0x1a, 0x1c, 0x20, 0x23, 0x26, 0x27, 0x28
]);

// ECMA-335 II.22: these four tables contain signatures; other blobs retain their bytes.
const BLOB_DECODERS: Record<number, (bytes: Uint8Array | null, context: string) => PeClrAdditionalCell> = {
  0x11: (bytes, context) => bytes ? parseStandaloneSignature(bytes, context) : null,
  0x17: (bytes, context) => bytes ? parsePropertySignature(bytes, context) : null,
  0x1b: (bytes, context) => bytes ? parseTypeSpecSignature(bytes, context) : null,
  0x2b: (bytes, context) => bytes ? parseMethodSpecSignature(bytes, context) : null
};

const retainBlobBytes = (bytes: Uint8Array | null): PeClrAdditionalCell =>
  bytes ? Array.from(bytes) : null;

const decodeCell = (
  tableId: number,
  column: ClrMetadataColumnSchema,
  value: ClrMetadataCell,
  heaps: ClrHeapReaders,
  context: string
): PeClrAdditionalCell => {
  if (typeof value !== "number") return value;
  if (column.kind === "string") return heaps.getString(value, context);
  if (column.kind === "blob") {
    return heaps.decodeBlob(value, context, BLOB_DECODERS[tableId] ?? retainBlobBytes);
  }
  return value;
};

export const createAdditionalTables = (
  parsed: ClrParsedTableStream,
  heaps: ClrHeapReaders
): PeClrAdditionalTable[] =>
  [...parsed.tables.entries()]
    .filter(([tableId]) => !MODELED_TABLES.has(tableId))
    .map(([tableId, table]) => ({
      tableId,
      rows: table.rows.map((row, index) => Object.fromEntries(table.schema.columns.map(column => [
        column.name,
        decodeCell(tableId, column, row[column.name] ?? 0, heaps,
          `${table.schema.name} row ${index + 1}.${column.name}`)
      ])))
    }));
