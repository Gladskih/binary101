"use strict";

import { HEADER_SIZE } from "./header.js";
import { parseRecord, readVarint, safeNumber } from "./record.js";
import type {
  SqliteBtreeHeader,
  SqliteHeader,
  SqliteLeafTableCell,
  SqlitePage
} from "./types.js";

const MAX_SCHEMA_CELLS = 32;

const parseLeafCell = (
  view: DataView,
  cellOffset: number,
  encoding: string | null,
  issues: string[],
  columnNames: string[]
): SqliteLeafTableCell | null => {
  if (cellOffset >= view.byteLength) {
    issues.push(`Cell offset ${cellOffset} is outside the page.`);
    return null;
  }
  const payloadInfo = readVarint(view, cellOffset);
  const payloadSize = safeNumber(payloadInfo.value, "Payload size", issues);
  if (payloadSize == null) return null;
  const rowIdInfo = readVarint(view, cellOffset + payloadInfo.length);
  const rowId = rowIdInfo.truncated ? null : rowIdInfo.value;
  const payloadOffset = cellOffset + payloadInfo.length + rowIdInfo.length;
  const payloadAvailable = Math.max(0, view.byteLength - payloadOffset);
  const record = parseRecord(view, payloadOffset, payloadSize, encoding, issues, columnNames);
  const overflow = payloadAvailable < payloadSize;
  return {
    offset: cellOffset,
    payloadSize,
    payloadAvailable,
    rowId,
    record,
    overflow
  };
};

const describePageType = (pageType: number | null): string | null => {
  if (pageType === 2) return "Index interior b-tree";
  if (pageType === 5) return "Table interior b-tree";
  if (pageType === 10) return "Index leaf b-tree";
  if (pageType === 13) return "Table leaf b-tree";
  return pageType == null ? null : "Unknown b-tree type";
};

const parseBtreeHeader = (
  view: DataView,
  offset: number,
  issues: string[]
): SqliteBtreeHeader | null => {
  if (offset + 1 > view.byteLength) {
    issues.push("B-tree header is missing.");
    return null;
  }
  const pageType = view.getUint8(offset);
  const headerSize = pageType === 2 || pageType === 5 ? 12 : 8;
  if (offset + headerSize > view.byteLength) {
    issues.push("B-tree header is truncated.");
    return null;
  }
  const firstFreeblock = view.getUint16(offset + 1, false);
  const cellCount = view.getUint16(offset + 3, false);
  const cellContentStart = view.getUint16(offset + 5, false);
  const fragmentedFreeBytes = view.getUint8(offset + 7);
  const rightMostPointer =
    headerSize === 12 ? view.getUint32(offset + 8, false) : null;
  return {
    pageType,
    pageTypeMeaning: describePageType(pageType),
    firstFreeblock,
    cellCount,
    cellContentStart,
    fragmentedFreeBytes,
    rightMostPointer,
    headerSize
  };
};

const parseSchemaPage = (
  view: DataView,
  header: SqliteHeader,
  issues: string[]
): SqlitePage | null => {
  if (view.byteLength <= HEADER_SIZE) {
    issues.push("Page 1 is smaller than the required 100-byte header.");
    return null;
  }
  const btreeHeader = parseBtreeHeader(view, HEADER_SIZE, issues);
  if (!btreeHeader) return null;
  if (btreeHeader.pageType !== 13) {
    issues.push("Page 1 is not a table leaf b-tree; schema entries may be elsewhere.");
  }
  const totalCells = btreeHeader.cellCount ?? 0;
  const limitedByCellCount = totalCells > MAX_SCHEMA_CELLS;
  const cellEntries = Math.min(totalCells, MAX_SCHEMA_CELLS);
  const cellOffsets: number[] = [];
  const cells: SqliteLeafTableCell[] = [];
  const pointersStart = HEADER_SIZE + btreeHeader.headerSize;
  const pointerBytesNeeded = cellEntries * 2;
  if (pointersStart + pointerBytesNeeded > view.byteLength) {
    issues.push("Cell pointer array is truncated.");
  }
  for (let index = 0; index < cellEntries; index += 1) {
    const ptrOffset = pointersStart + index * 2;
    if (ptrOffset + 2 > view.byteLength) break;
    const cellOffset = view.getUint16(ptrOffset, false);
    cellOffsets.push(cellOffset);
    const cell = parseLeafCell(
      view,
      cellOffset,
      header.textEncodingName,
      issues,
      ["type", "name", "tbl_name", "rootpage", "sql"]
    );
    if (cell) cells.push(cell);
  }
  return {
    pageNumber: 1,
    header: btreeHeader,
    cellOffsets,
    cells,
    limitedByCellCount,
    truncated: pointersStart + pointerBytesNeeded > view.byteLength
  };
};

export { parseSchemaPage };
