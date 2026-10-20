import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { escapeHtml } from "../../html-utils.js";
import { humanSize } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

const createPogoTableModel = (entry: PeDebugDirectoryEntry, id: string): PagedSortableTableModel => ({
  id, pageSize: 100, rowCount: entry.pogo!.entries.length,
  columns: [{ label: "Region name" }, { label: "Size", className: "peNumeric" }],
  rowAt: index => {
    const region = entry.pogo!.entries[index];
    return region ? { cells: [{ html: escapeHtml(region.name || "(unnamed)") },
      { html: humanSize(region.size), className: "peNumeric" }] } : null;
  },
  sortValueAt: (index, column) => {
    const region = entry.pogo!.entries[index];
    return region ? [region.name, String(region.size)][column] ?? "" : "";
  }
});

export const getPogoTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^pe-debug-entry-(\d+)-pogo$/.exec(tableId);
  if (!match) return null;
  const entry = pe.debug?.entries?.[Number(match[1])];
  return entry?.pogo ? createPogoTableModel(entry, tableId) : null;
};

export const renderPogoRegions = (entry: PeDebugDirectoryEntry, index: number, out: string[]): void => {
  if (!entry.pogo?.entries.length) return;
  out.push(renderAutoPagedSortableTable(createPogoTableModel(entry, `pe-debug-entry-${index}-pogo`)));
};
