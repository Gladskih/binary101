import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import type { PeTd32Info } from "../../analyzers/pe/debug/td32.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { humanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { buildTd32Tables, type Td32Table } from "./td32-tables.js";

const columnClass = (label: string): string =>
  /^(Directory|Module|Index|Bytes|Code segments|Data segments|Contributed bytes|Segments|Line\/address pairs|Distinct source lines|Records)$/.test(label)
    || ["Code bytes", "Debug bytes", "Count / bytes", "Members/values", "Count", "Parameters",
      "Vtable offset", "Overloads", "Offset/value"].includes(label) ? "peNumeric" : "";
const model = (table: Td32Table, prefix: string): PagedSortableTableModel => ({
  id: `${prefix}-${table.key}`, pageSize: 100, rowCount: table.rows.length,
  ...(["procedures", "symbolmetadata", "typeaggregates", "typemembers", "typemethods"].includes(table.key)
    ? { tableClassName: "peCodeViewLocalTable" } : {}),
  columns: table.columns.map(label => ({ label, className: columnClass(label) })),
  rowAt: index => table.rows[index] ? { cells: table.rows[index]!.map((value, column) =>
    ({ html: escapeHtml(value), className: columnClass(table.columns[column] ?? "") })) } : null,
  sortValueAt: (index, column) => table.rows[index]?.[column] ?? ""
});

const td32Info = (pe: PeWindowsParseResult, kind: string, index: number): PeTd32Info | undefined =>
  kind === "entry" ? pe.debug?.entries?.[index]?.td32 : pe.debug?.td32Sources?.[index]?.td32;

export const getTd32TableModel = (pe: PeWindowsParseResult, tableId: string): PagedSortableTableModel | null => {
  const match = /^(pe-debug-(entry|source)-(\d+)-td32)-([a-z]+)$/.exec(tableId);
  if (!match) return null;
  const td32 = td32Info(pe, match[2]!, Number(match[3]));
  if (!td32) return null;
  const table = buildTd32Tables(td32).find(value => value.key === match[4]);
  return table ? model(table, match[1]!) : null;
};

const renderTd32Info = (info: PeTd32Info, prefix: string, out: string[]): void => {
  out.push(`<dl>`, renderDefinitionRow("Borland TD32 format", escapeHtml(info.signature)), `</dl>`);
  out.push(`<p class="smallNote">Stored symbol locations use producer segment and offset fields. ` +
    `Frame bases and disputed layouts remain unresolved. Named types retain sizes and properties; ` +
    `anonymous type descriptions are summarized.</p>`);
  for (const table of buildTd32Tables(info)) out.push(`<h4>${escapeHtml(table.title)}</h4>`,
    renderAutoPagedSortableTable(model(table, prefix)));
};

export const renderTd32 = (entry: PeDebugDirectoryEntry, index: number, out: string[]): void => {
  if (entry.td32) renderTd32Info(entry.td32, `pe-debug-entry-${index}-td32`, out);
};

export const renderTd32Sources = (pe: PeWindowsParseResult, out: string[]): void => {
  pe.debug?.td32Sources?.forEach((source, index) => {
    out.push(`<details><summary>TD32 source #${index + 1}: ` +
      `${source.kind === "section" ? ".debug section" : "Appended debug data"} ` +
      `(${humanSize(source.size)})</summary>`);
    renderTd32Info(source.td32, `pe-debug-source-${index}-td32`, out);
    out.push(`</details>`);
  });
};
