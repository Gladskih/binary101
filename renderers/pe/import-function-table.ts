"use strict";

import { getIatSlotRva } from "../../analyzers/pe/disassembly/import-references.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeImportMetadataEntry } from "../../pe-import-metadata-schema.js";
import type { WinapiMetadataEntry } from "../../winapi-metadata-schema.js";
import {
  renderAutoPagedSortableTable,
  type PagedSortableTableCell,
  type PagedSortableTableModel
} from "../paged-sortable-table.js";
import type { DirectIatReferenceCounts } from "./direct-iat-references.js";

interface ImportFunctionRow {
  ordinal?: number;
  hint?: number;
  name?: string;
  apiMetadata?: PeImportMetadataEntry;
  winapiMetadata?: WinapiMetadataEntry;
}

export const PE_IMPORT_FUNCTION_PAGE_SIZE = 250;

const DIRECT_CALL_TOOLTIP =
  "Unique decoded near CALL instructions that directly address this IAT slot during ISA analysis. " +
  "This is a static count, not a runtime call count.";
const DIRECT_JUMP_TOOLTIP =
  "Unique decoded near JMP instructions that directly address this IAT slot during ISA analysis. " +
  "This is a static count; it can represent an import thunk or tail transfer.";

const sourceLabel = (entry: PeImportMetadataEntry): string =>
  entry.sourceKind === "ucrt" ? "UCRT" : "Win32Metadata";

const renderApiMetadataHtml = (entry: PeImportMetadataEntry | undefined): string => {
  if (!entry) return "-";
  const callingConvention = entry.variadic
    ? `${entry.callingConvention}, variadic`
    : entry.callingConvention;
  return (
    `<span class="winapiMetadataNamespace">${escapeHtml(entry.namespace ?? sourceLabel(entry))}</span>` +
    `<code class="winapiMetadataSignature">${escapeHtml(entry.signature)}</code>` +
    `<span class="winapiMetadataConvention">` +
    `${escapeHtml(`${sourceLabel(entry)} - ${callingConvention}`)}</span>`
  );
};

const renderImportName = (fn: ImportFunctionRow): string =>
  fn.name
    ? escapeHtml(fn.name)
    : fn.ordinal != null
      ? `ORD ${fn.ordinal}`
      : "-";

const importNameSortValue = (fn: ImportFunctionRow): string =>
  fn.name ?? (fn.ordinal != null ? `ORD ${fn.ordinal}` : "");

const apiMetadataSortValue = (entry: PeImportMetadataEntry | undefined): string =>
  entry ? `${entry.namespace ?? sourceLabel(entry)} ${entry.signature}` : "";

const directIatReferenceCount = (
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  startRva: unknown,
  functionIndex: number,
  entrySize: number,
  kind: "call" | "jump"
): number => {
  const slotRva = getIatSlotRva(startRva, functionIndex, entrySize);
  const reference = slotRva == null ? undefined : counts.get(slotRva);
  return kind === "call"
    ? reference?.callReferenceCount ?? 0
    : reference?.jumpReferenceCount ?? 0;
};

const renderReferenceCount = (count: number): string =>
  count > 0 ? String(count) : "&mdash;";

const renderFunctionCells = (
  fn: ImportFunctionRow,
  functionIndex: number,
  iatRva: number,
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  entrySize: number
): PagedSortableTableCell[] => {
  const metadata = fn.apiMetadata ?? fn.winapiMetadata;
  const callCount = directIatReferenceCount(counts, iatRva, functionIndex, entrySize, "call");
  const jumpCount = directIatReferenceCount(counts, iatRva, functionIndex, entrySize, "jump");
  return [
    { html: String(functionIndex + 1), sortValue: String(functionIndex + 1) },
    { html: fn.hint != null ? String(fn.hint) : "-", sortValue: String(fn.hint ?? "") },
    { html: renderImportName(fn), sortValue: importNameSortValue(fn) },
    {
      className: "winapiMetadataCell",
      html: renderApiMetadataHtml(metadata),
      sortValue: apiMetadataSortValue(metadata)
    },
    {
      className: "peNumeric",
      html: renderReferenceCount(callCount),
      sortValue: String(callCount)
    },
    {
      className: "peNumeric",
      html: renderReferenceCount(jumpCount),
      sortValue: String(jumpCount)
    }
  ];
};

const importFunctionSortValue = (
  fn: ImportFunctionRow,
  functionIndex: number,
  columnIndex: number,
  iatRva: number,
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  entrySize: number
): string => {
  const metadata = fn.apiMetadata ?? fn.winapiMetadata;
  switch (columnIndex) {
    case 0:
      return String(functionIndex + 1);
    case 1:
      return String(fn.hint ?? "");
    case 2:
      return importNameSortValue(fn);
    case 3:
      return apiMetadataSortValue(metadata);
    case 4:
      return String(directIatReferenceCount(counts, iatRva, functionIndex, entrySize, "call"));
    case 5:
      return String(directIatReferenceCount(counts, iatRva, functionIndex, entrySize, "jump"));
    default:
      return "";
  }
};

export const createImportFunctionTableModel = (
  functions: ImportFunctionRow[],
  tableId: string,
  iatRva: number,
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  entrySize: number
): PagedSortableTableModel => ({
  columns: [
    { label: "#" },
    { label: "Hint" },
    { label: "Name / Ordinal" },
    { label: "API" },
    { className: "peNumeric", label: "Direct CALL refs", tooltip: DIRECT_CALL_TOOLTIP },
    { className: "peNumeric", label: "Direct JMP refs", tooltip: DIRECT_JUMP_TOOLTIP }
  ],
  id: tableId,
  pageSize: PE_IMPORT_FUNCTION_PAGE_SIZE,
  rowAt: rowIndex => {
    const fn = functions[rowIndex];
    return fn ? { cells: renderFunctionCells(fn, rowIndex, iatRva, counts, entrySize) } : null;
  },
  rowCount: functions.length,
  sortValueAt: (rowIndex, columnIndex) => {
    const fn = functions[rowIndex];
    if (!fn) return "";
    return importFunctionSortValue(fn, rowIndex, columnIndex, iatRva, counts, entrySize);
  }
});

export const renderImportFunctionTable = (
  functions: ImportFunctionRow[],
  sortKey: string,
  iatRva: number,
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  entrySize: number
): string =>
  renderAutoPagedSortableTable(
    createImportFunctionTableModel(functions, sortKey, iatRva, counts, entrySize)
  );
