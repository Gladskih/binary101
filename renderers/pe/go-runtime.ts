"use strict";

import type { GoRuntimeFunction } from "../../analyzers/go-runtime/types.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { escapeHtml } from "../../html-utils.js";
import {
  renderAutoPagedSortableTable,
  type PagedSortableTableModel
} from "../paged-sortable-table.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

const GO_FUNCTION_TABLE_ID = "pe-go-runtime-functions";

const formatAddress = (address: bigint): string => `0x${address.toString(16)}`;

const functionSortValue = (
  fn: GoRuntimeFunction,
  index: number,
  columnIndex: number
): string => {
  if (columnIndex === 0) return String(index + 1);
  if (columnIndex === 1) return fn.name;
  if (columnIndex === 2) return fn.start.toString();
  if (columnIndex === 3) return fn.end.toString();
  return (fn.end - fn.start).toString();
};

export const createGoRuntimeFunctionTableModel = (
  functions: GoRuntimeFunction[]
): PagedSortableTableModel => ({
  id: GO_FUNCTION_TABLE_ID,
  pageSize: 250,
  rowCount: functions.length,
  columns: [
    { className: "peNumeric", label: "#" },
    { label: "Function" },
    { className: "peNumeric", label: "Start VA" },
    { className: "peNumeric", label: "End VA" },
    { className: "peNumeric", label: "Size" }
  ],
  rowAt: index => {
    const fn = functions[index];
    if (!fn) return null;
    const size = fn.end - fn.start;
    return {
      cells: [
        { className: "peNumeric", html: String(index + 1), sortValue: String(index + 1) },
        { html: escapeHtml(fn.name), sortValue: fn.name },
        { className: "peNumeric", html: formatAddress(fn.start), sortValue: fn.start.toString() },
        { className: "peNumeric", html: formatAddress(fn.end), sortValue: fn.end.toString() },
        { className: "peNumeric", html: formatAddress(size), sortValue: size.toString() }
      ]
    };
  },
  sortValueAt: (rowIndex, columnIndex) => {
    const fn = functions[rowIndex];
    return fn ? functionSortValue(fn, rowIndex, columnIndex) : "";
  }
});

const locationHtml = (pe: PeWindowsParseResult, address: bigint): string => {
  const rva = address - pe.opt.ImageBase;
  const fileOffset = rva >= 0n && rva <= 0xffff_ffffn ? pe.rvaToOff(Number(rva)) : null;
  return `${formatAddress(address)} (RVA ${formatAddress(rva)}` +
    `${fileOffset == null ? "" : `, file ${formatAddress(BigInt(fileOffset))}`})`;
};

export const renderGoRuntime = (pe: PeWindowsParseResult, out: string[]): void => {
  const runtime = pe.goRuntime;
  if (!runtime) return;
  out.push(renderPeSectionStart(
    "Go runtime metadata",
    `${runtime.layout}, ${runtime.functions.length} functions`
  ));
  out.push(`<dl>`);
  out.push(`<dt>Layout</dt><dd>${escapeHtml(runtime.layout)}</dd>`);
  out.push(`<dt>pcHeader</dt><dd>${locationHtml(pe, runtime.pcHeaderAddress)}</dd>`);
  out.push(`<dt>moduledata</dt><dd>${locationHtml(pe, runtime.moduleDataAddress)}</dd>`);
  out.push(`<dt>Functions</dt><dd>${runtime.functions.length}</dd>`);
  out.push(`<dt>Files</dt><dd>${runtime.fileCount}</dd>`);
  out.push(`<dt>Text range</dt><dd>${formatAddress(runtime.textRange.start)}–` +
    `${formatAddress(runtime.textRange.end)}</dd>`);
  out.push(`</dl>`);
  out.push(renderAutoPagedSortableTable(createGoRuntimeFunctionTableModel(runtime.functions)));
  out.push(renderPeSectionEnd());
};

export { GO_FUNCTION_TABLE_ID };
