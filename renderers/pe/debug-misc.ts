import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { escapeHtml } from "../../html-utils.js";
import { humanSize } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

const createMiscTableModel = (entry: PeDebugDirectoryEntry, id: string): PagedSortableTableModel => ({
  id, pageSize: 100, rowCount: entry.misc!.records.length,
  columns: [{ label: "DBG file" }, { label: "Encoding" }, { label: "Record size", className: "peNumeric" }],
  rowAt: index => {
    const record = entry.misc!.records[index];
    if (!record) return null;
    return { cells: [
      { html: escapeHtml(record.dataType === 1 ? record.text || "(empty)" : `Unsupported MISC type ${record.dataType}`) },
      { html: record.unicode == null ? "Unsupported flag" : record.unicode ? "UTF-16LE" : "ANSI (code page unspecified)" },
      { html: humanSize(record.length), className: "peNumeric" }
    ] };
  },
  sortValueAt: (index, column) => {
    const record = entry.misc!.records[index];
    return record ? [record.text, String(record.unicode), String(record.length)][column] ?? "" : "";
  }
});

export const getMiscDebugTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^pe-debug-entry-(\d+)-misc$/.exec(tableId);
  if (!match) return null;
  const entry = pe.debug?.entries?.[Number(match[1])];
  return entry?.misc ? createMiscTableModel(entry, tableId) : null;
};

export const renderMiscDebug = (entry: PeDebugDirectoryEntry, index: number, out: string[]): void => {
  if (!entry.misc?.records.length) return;
  out.push(renderAutoPagedSortableTable(createMiscTableModel(entry, `pe-debug-entry-${index}-misc`)));
};
