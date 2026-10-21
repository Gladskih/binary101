import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { buildTd32Tables, type Td32Table } from "./td32-tables.js";

const columnClass = (label: string): string =>
  /^(Directory|Module|Index|Bytes|Code segments|Data segments|Contributed bytes|Segments|Line\/address pairs|Distinct source lines|Records)$/.test(label)
    ? "peNumeric" : "";
const model = (table: Td32Table, prefix: string): PagedSortableTableModel => ({
  id: `${prefix}-${table.key}`, pageSize: 100, rowCount: table.rows.length,
  columns: table.columns.map(label => ({ label, className: columnClass(label) })),
  rowAt: index => table.rows[index] ? { cells: table.rows[index]!.map((value, column) =>
    ({ html: escapeHtml(value), className: columnClass(table.columns[column] ?? "") })) } : null,
  sortValueAt: (index, column) => table.rows[index]?.[column] ?? ""
});

export const getTd32TableModel = (pe: PeWindowsParseResult, tableId: string): PagedSortableTableModel | null => {
  const match = /^(pe-debug-entry-(\d+)-td32)-([a-z]+)$/.exec(tableId);
  if (!match) return null;
  const td32 = pe.debug?.entries?.[Number(match[2])]?.td32;
  if (!td32) return null;
  const table = buildTd32Tables(td32).find(value => value.key === match[3]);
  return table ? model(table, match[1]!) : null;
};

export const renderTd32 = (entry: PeDebugDirectoryEntry, index: number, out: string[]): void => {
  if (!entry.td32) return;
  out.push(`<dl>`, renderDefinitionRow("Borland TD32 format", escapeHtml(entry.td32.signature)), `</dl>`);
  out.push(`<p class="smallNote">Type statistics retain every bounded record. Named types resolve ` +
    `verified class, structure and enum name fields; other stored names remain in the shared names table.</p>`);
  for (const table of buildTd32Tables(entry.td32)) out.push(`<h4>${escapeHtml(table.title)}</h4>`,
    renderAutoPagedSortableTable(model(table, `pe-debug-entry-${index}-td32`)));
};
