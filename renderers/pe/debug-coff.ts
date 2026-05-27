"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { COFF_STORAGE_CLASS_NAMES } from "../../analyzers/pe/debug/coff-storage-classes.js";
import type {
  PeCoffAuxiliaryRecord,
  PeCoffDebugInfo,
  PeCoffSymbol
} from "../../analyzers/pe/debug/directory.js";

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

const renderHeader = (info: PeCoffDebugInfo, out: string[]): void => {
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Source", info.source === "debug-directory" ? "Debug directory" : "COFF file header"));
  out.push(renderDefinitionRow("Symbol table", escapeHtml(hex(info.symbolTableOffset, 8))));
  out.push(renderDefinitionRow("Symbols parsed", escapeHtml(String(info.symbols.length))));
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

const renderSymbolRows = (symbols: PeCoffSymbol[], out: string[]): void => {
  symbols.forEach(symbol => {
    out.push(
      `<tr><td>${symbol.index}</td><td>${escapeHtml(symbol.name)}</td>` +
        `<td>${hex(symbol.value, 8)}</td><td>${symbol.sectionNumber}</td>` +
        `<td>${escapeHtml(getTypeName(symbol.type))}</td>` +
        `<td>${escapeHtml(getStorageClassName(symbol.storageClass))}</td>` +
        `<td>${escapeHtml(symbol.auxiliaryRecords.map(getAuxSummary).join("; "))}</td></tr>`
    );
  });
};

const renderSymbols = (info: PeCoffDebugInfo, out: string[]): void => {
  if (!info.symbols.length) return;
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>#</th>` +
      `<th>Name</th><th>Value</th><th>Section</th><th>Type</th><th>Class</th>` +
      `<th>Aux</th></tr></thead><tbody>`
  );
  renderSymbolRows(info.symbols, out);
  out.push(`</tbody></table>`);
};

const renderLineNumbers = (info: PeCoffDebugInfo, out: string[]): void => {
  const rows = info.lineNumberBlocks.flatMap(block =>
    block.records.map(record => ({ block, record }))
  );
  if (!rows.length) return;
  out.push(
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>Block</th><th>Type field</th><th>Line</th></tr></thead><tbody>`
  );
  rows.forEach(({ block, record }) => {
    out.push(
      `<tr><td>${escapeHtml(block.sectionName ?? hex(block.offset, 8))}</td>` +
        `<td>${hex(record.symbolTableIndexOrVirtualAddress, 8)}</td>` +
        `<td>${record.lineNumber}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
};

export const renderCoffDebugInfo = (info: PeCoffDebugInfo, out: string[]): void => {
  renderHeader(info, out);
  renderSymbols(info, out);
  renderLineNumbers(info, out);
  if (info.warnings?.length) {
    out.push(`<div class="smallNote">${escapeHtml(info.warnings.join(" | "))}</div>`);
  }
};
