"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { COFF_STORAGE_CLASS_NAMES } from "../../analyzers/pe/debug/coff-storage-classes.js";
import type {
  PeCoffAuxiliaryRecord,
  PeCoffDebugInfo,
  PeCoffLineNumberBlock,
  PeCoffSymbol
} from "../../analyzers/pe/debug/directory.js";
import {
  renderAutoPagedSortableTable,
  type PagedSortableTableCell,
  type PagedSortableTableModel
} from "../paged-sortable-table.js";

export const PE_COFF_SYMBOL_PAGE_SIZE = 250;

type PeCoffLineNumberRow = {
  block: PeCoffLineNumberBlock;
  record: PeCoffLineNumberBlock["records"][number];
};

const BASE_TYPE_NAMES: Record<number, string> = {
  0: "NULL",
  1: "VOID",
  2: "CHAR",
  3: "SHORT",
  4: "INT",
  5: "LONG",
  6: "FLOAT",
  7: "DOUBLE",
  8: "STRUCT",
  9: "UNION",
  10: "ENUM",
  11: "MOE",
  12: "BYTE",
  13: "WORD",
  14: "UINT",
  15: "DWORD"
};

const DERIVED_TYPE_NAMES: Record<number, string> = {
  0: "scalar",
  1: "pointer",
  2: "function",
  3: "array"
};

const getStorageClassName = (value: number): string =>
  COFF_STORAGE_CLASS_NAMES[value] ?? `CLASS_${hex(value, 2)}`;

const getTypeName = (type: number): string => {
  const baseType = BASE_TYPE_NAMES[type & 0x0f] ?? `BASE_${hex(type & 0x0f, 1)}`;
  const derivedType = DERIVED_TYPE_NAMES[(type >>> 4) & 0x03] ?? "unknown";
  return `${derivedType} ${baseType}`;
};

const getAuxSummary = (record: PeCoffAuxiliaryRecord): string => {
  if (record.kind === "function-definition") return `function ${humanSize(record.totalSize)}`;
  if (record.kind === "begin-end-function") return `line ${record.lineNumber}`;
  if (record.kind === "weak-external") return `weak -> #${record.tagIndex}`;
  if (record.kind === "file") return record.fileName || "(empty file name)";
  if (record.kind === "section-definition") return `section ${humanSize(record.length)}`;
  return `${record.bytes.length} raw bytes`;
};

const symbolTableId = (tableIdPrefix: string): string => `${tableIdPrefix}-symbols`;
const lineNumberTableId = (tableIdPrefix: string): string => `${tableIdPrefix}-lines`;

export const getCoffAuxiliaryRecordCount = (info: PeCoffDebugInfo): number =>
  info.symbols.reduce((count, symbol) => count + symbol.auxiliaryRecords.length, 0);

export const getCoffParsedRecordCount = (info: PeCoffDebugInfo): number =>
  info.symbols.length + getCoffAuxiliaryRecordCount(info);

const renderHeader = (info: PeCoffDebugInfo, out: string[]): void => {
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Source", info.source === "debug-directory" ? "Debug directory" : "COFF file header"));
  out.push(renderDefinitionRow("Symbol table", escapeHtml(hex(info.symbolTableOffset, 8))));
  out.push(renderDefinitionRow(
    "Primary symbols parsed",
    escapeHtml(String(info.symbols.length)),
    "Standard symbol-table records after grouping any auxiliary records that follow them."
  ));
  out.push(renderDefinitionRow(
    "Auxiliary records parsed",
    escapeHtml(String(getCoffAuxiliaryRecordCount(info))),
    "Auxiliary symbol-table records attached to the preceding primary symbol."
  ));
  out.push(renderDefinitionRow(
    "Symbol records parsed",
    escapeHtml(String(getCoffParsedRecordCount(info))),
    "Total 18-byte COFF symbol-table records consumed by the parsed rows above."
  ));
  out.push(renderDefinitionRow(
    "String table",
    info.stringTableOffset == null
      ? "not present"
      : `${escapeHtml(hex(info.stringTableOffset, 8))}, ${escapeHtml(humanSize(info.stringTableSize ?? 0))}`
  ));
  if (info.header) {
    out.push(renderDefinitionRow("Code RVA range", `${hex(info.header.rvaToFirstByteOfCode, 8)} - ${hex(info.header.rvaToLastByteOfCode, 8)}`));
    out.push(renderDefinitionRow("Data RVA range", `${hex(info.header.rvaToFirstByteOfData, 8)} - ${hex(info.header.rvaToLastByteOfData, 8)}`));
  }
  out.push(`</dl>`);
};

const renderSymbolCells = (symbol: PeCoffSymbol): PagedSortableTableCell[] => [
  { html: String(symbol.index), sortValue: String(symbol.index) },
  { html: escapeHtml(symbol.name), sortValue: symbol.name },
  { html: hex(symbol.value, 8), sortValue: String(symbol.value) },
  { html: String(symbol.sectionNumber), sortValue: String(symbol.sectionNumber) },
  { html: escapeHtml(getTypeName(symbol.type)), sortValue: getTypeName(symbol.type) },
  {
    html: escapeHtml(getStorageClassName(symbol.storageClass)),
    sortValue: getStorageClassName(symbol.storageClass)
  },
  {
    html: escapeHtml(symbol.auxiliaryRecords.map(getAuxSummary).join("; ")),
    sortValue: symbol.auxiliaryRecords.map(getAuxSummary).join("; ")
  }
];

const symbolSortValue = (symbol: PeCoffSymbol, columnIndex: number): string => {
  switch (columnIndex) {
    case 0:
      return String(symbol.index);
    case 1:
      return symbol.name;
    case 2:
      return String(symbol.value);
    case 3:
      return String(symbol.sectionNumber);
    case 4:
      return getTypeName(symbol.type);
    case 5:
      return getStorageClassName(symbol.storageClass);
    case 6:
      return symbol.auxiliaryRecords.map(getAuxSummary).join("; ");
    default:
      return "";
  }
};

export const createCoffSymbolTableModel = (
  info: PeCoffDebugInfo,
  tableId: string
): PagedSortableTableModel => ({
  columns: [
    { label: "#" },
    { label: "Name" },
    { label: "Value" },
    { label: "Section" },
    { label: "Type" },
    { label: "Class" },
    { label: "Aux" }
  ],
  id: tableId,
  pageSize: PE_COFF_SYMBOL_PAGE_SIZE,
  rowAt: rowIndex => {
    const symbol = info.symbols[rowIndex];
    return symbol ? { cells: renderSymbolCells(symbol) } : null;
  },
  rowCount: info.symbols.length,
  sortValueAt: (rowIndex, columnIndex) =>
    info.symbols[rowIndex] ? symbolSortValue(info.symbols[rowIndex], columnIndex) : ""
});

const renderSymbols = (
  info: PeCoffDebugInfo,
  out: string[],
  tableIdPrefix: string
): void => {
  if (!info.symbols.length) return;
  out.push(renderAutoPagedSortableTable(
    createCoffSymbolTableModel(info, symbolTableId(tableIdPrefix))
  ));
};

const lineNumberRows = (info: PeCoffDebugInfo): PeCoffLineNumberRow[] =>
  info.lineNumberBlocks.flatMap(block => block.records.map(record => ({ block, record })));

const renderLineNumberCells = (row: PeCoffLineNumberRow): PagedSortableTableCell[] => [
  {
    html: escapeHtml(row.block.sectionName ?? hex(row.block.offset, 8)),
    sortValue: row.block.sectionName ?? String(row.block.offset)
  },
  {
    html: hex(row.record.symbolTableIndexOrVirtualAddress, 8),
    sortValue: String(row.record.symbolTableIndexOrVirtualAddress)
  },
  { html: String(row.record.lineNumber), sortValue: String(row.record.lineNumber) }
];

const lineNumberSortValue = (row: PeCoffLineNumberRow, columnIndex: number): string => {
  switch (columnIndex) {
    case 0:
      return row.block.sectionName ?? String(row.block.offset);
    case 1:
      return String(row.record.symbolTableIndexOrVirtualAddress);
    case 2:
      return String(row.record.lineNumber);
    default:
      return "";
  }
};

export const createCoffLineNumberTableModel = (
  info: PeCoffDebugInfo,
  tableId: string
): PagedSortableTableModel => {
  const rows = lineNumberRows(info);
  return {
    columns: [{ label: "Block" }, { label: "Type field" }, { label: "Line" }],
    id: tableId,
    pageSize: PE_COFF_SYMBOL_PAGE_SIZE,
    rowAt: rowIndex => {
      const row = rows[rowIndex];
      return row ? { cells: renderLineNumberCells(row) } : null;
    },
    rowCount: rows.length,
    sortValueAt: (rowIndex, columnIndex) =>
      rows[rowIndex] ? lineNumberSortValue(rows[rowIndex], columnIndex) : ""
  };
};

const renderLineNumbers = (
  info: PeCoffDebugInfo,
  out: string[],
  tableIdPrefix: string
): void => {
  const rows = lineNumberRows(info);
  if (!rows.length) return;
  out.push(renderAutoPagedSortableTable(
    createCoffLineNumberTableModel(info, lineNumberTableId(tableIdPrefix))
  ));
};

export const getCoffDebugTableModel = (
  info: PeCoffDebugInfo,
  tableId: string,
  tableIdPrefix: string
): PagedSortableTableModel | null => {
  if (tableId === symbolTableId(tableIdPrefix)) return createCoffSymbolTableModel(info, tableId);
  if (tableId === lineNumberTableId(tableIdPrefix)) {
    return createCoffLineNumberTableModel(info, tableId);
  }
  return null;
};

export const renderCoffDebugInfo = (
  info: PeCoffDebugInfo,
  out: string[],
  tableIdPrefix = "pe-coff-debug"
): void => {
  renderHeader(info, out);
  renderCoffDebugTables(info, out, tableIdPrefix);
};

export const renderCoffDebugTables = (
  info: PeCoffDebugInfo,
  out: string[],
  tableIdPrefix = "pe-coff-debug"
): void => {
  renderSymbols(info, out, tableIdPrefix);
  renderLineNumbers(info, out, tableIdPrefix);
  if (info.warnings?.length) {
    out.push(`<div class="smallNote">${escapeHtml(info.warnings.join(" | "))}</div>`);
  }
};
