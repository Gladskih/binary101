"use strict";

import type { PeExportEntry } from "../../analyzers/pe/directories/exports.js";
import { hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";

export const EXPORT_TABLE_ID = "pe-exports";
// Preserve literal entity-like sequences in symbol names and forwarded targets.
const exportText = (value: string): string => escapeHtml(value.replaceAll("&", "&amp;"));
const exportSortValue = (entry: PeExportEntry, index: number, column: number): string => {
  switch (column) {
    case 0: return String(index + 1);
    case 1: return String(entry.ordinal);
    case 2: return entry.names.join("\n");
    case 3: return String(entry.rva);
    case 4: return entry.forwarder ?? "";
    default: return "";
  }
};

export const createExportTableModel = (entries: PeExportEntry[]): PagedSortableTableModel => ({
  id: EXPORT_TABLE_ID,
  pageSize: 250,
  rowCount: entries.length,
  columns: [
    { label: "#", className: "peNumeric" },
    { label: "Ordinal", className: "peNumeric" },
    { label: "Names" },
    { label: "RVA", className: "peNumeric" },
    { label: "Forwarder" }
  ],
  rowAt: index => {
    const entry = entries[index];
    if (!entry) return null;
    return { cells: [
      { html: String(index + 1), className: "peNumeric" },
      { html: String(entry.ordinal), className: "peNumeric" },
      { html: entry.names.length ? entry.names.map(exportText).join("<br>") : "-" },
      { html: hex(entry.rva, 8), className: "peNumeric", sortValue: String(entry.rva) },
      { html: entry.forwarder ? exportText(entry.forwarder) : "-" }
    ] };
  },
  sortValueAt: (rowIndex, columnIndex) => {
    const entry = entries[rowIndex];
    return entry ? exportSortValue(entry, rowIndex, columnIndex) : "";
  }
});
