import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { buildLegacyCodeViewTables, type LegacyCodeViewTable } from "./legacy-codeview-tables.js";

const columnClass = (label: string): string =>
  /^(Directory|Module|Index|Segments|Contributed bytes|Line\/address pairs|Distinct source lines|Referencing modules|Segment|Bytes|Mapped segments|Distinct frames|Records|Payload bytes)$/.test(label)
    ? "peNumeric" : "";

const model = (table: LegacyCodeViewTable, prefix: string): PagedSortableTableModel => ({
  id: `${prefix}-${table.key}`, pageSize: 100, rowCount: table.rows.length,
  columns: table.columns.map(label => ({ label, className: columnClass(label) })),
  rowAt: index => table.rows[index] ? { cells: table.rows[index]!.map((value, column) =>
    ({ html: escapeHtml(value), className: columnClass(table.columns[column] ?? "") })) } : null,
  sortValueAt: (index, column) => table.rows[index]?.[column] ?? ""
});

export const getLegacyCodeViewTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^(pe-debug-entry-(\d+)-legacy)-([a-zA-Z]+)$/.exec(tableId);
  if (!match) return null;
  const legacy = pe.debug?.entries?.[Number(match[2])]?.legacyCodeView;
  if (!legacy) return null;
  const table = buildLegacyCodeViewTables(legacy).find(value => value.key === match[3]);
  return table ? model(table, match[1]!) : null;
};

export const renderLegacyCodeView = (entry: PeDebugDirectoryEntry, index: number, out: string[]): void => {
  const legacy = entry.legacyCodeView;
  if (!legacy) return;
  out.push(`<dl>`, renderDefinitionRow("Embedded CodeView format", escapeHtml(legacy.signature)),
    renderDefinitionRow("Directory generations", String(legacy.directories.length)), `</dl>`);
  if (legacy.directories.length > 1) out.push(`<p class="smallNote">Directory generations are shown separately; ` +
    `later incremental-link records update earlier module records.</p>`);
  for (const table of buildLegacyCodeViewTables(legacy)) {
    out.push(`<h4>${escapeHtml(table.title)}</h4>`, renderAutoPagedSortableTable(model(table, `pe-debug-entry-${index}-legacy`)));
  }
};
