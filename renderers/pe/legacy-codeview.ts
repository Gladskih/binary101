import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { escapeHtml, escapeHtmlText, renderDefinitionRow } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { buildLegacyCodeViewTables, type LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import type { PeLegacyCodeViewInfo } from "../../analyzers/pe/debug/legacy-codeview.js";
import { humanSize } from "../../binary-utils.js";

const columnClass = (label: string): string =>
  /^(Directory|Module|Index|Segments|Contributed bytes|Line\/address pairs|Distinct source lines|Distinct lines or path codes|Referencing modules|Segment|Bytes|Mapped segments|Distinct frames|Records|Payload bytes|Groups|Nonempty groups|References|Largest group|References per bucket|Buckets|With source line|First source line|Last source line)$/.test(label)
    || ["Declared parameters", "Value / placement", "Byte size", "Declared members", "Source line", "Build",
      "String list", "Component", "Dimension", "Lower bound", "Upper bound", "Pointer offset", "Image RVA", "Code length",
      "Frame bytes", "Padding bytes", "Saved register bytes", "Range records", "Declared range bytes (sum)", "Gap bytes (sum)",
      "Stored method names", "Path type index", "PDB age", "Bit size"].includes(label) ? "peNumeric" : "";

const TABLE_CLASSES = new Map([
  ["indexes", "peCodeViewIndexTable"], ["discardedSymbols", "peCodeViewDiscardedTable"],
  ["members", "peCodeViewMemberTable"], ["types", "peCodeViewTypeTable"],
  ["functions", "peCodeViewFunctionTable"], ["procedureSymbols", "peCodeViewProcedureTable"],
  ["compilerFrames", "peCodeViewLocalTable"], ["localVariables", "peCodeViewLocalTable"],
  ["arrayBounds", "peCodeViewBoundsTable"]
]);

const model = (table: LegacyCodeViewTable, prefix: string): PagedSortableTableModel => ({
  id: `${prefix}-${table.key}`, pageSize: 100, rowCount: table.rows.length,
  ...(TABLE_CLASSES.has(table.key) ? { tableClassName: TABLE_CLASSES.get(table.key)! } : {}),
  ...(["buildInfo", "typeSources", "stringComponents", "derivedTypes", "virtualTables", "vtablePaths", "typeServers",
    "legacyTypeDetails"]
    .includes(table.key)
    ? { tableClassName: "peCodeViewMetadataTable" } : {}),
  columns: table.columns.map(label => ({ label, className: columnClass(label) })),
  rowAt: index => table.rows[index] ? { cells: table.rows[index]!.map((value, column) =>
    ({ html: escapeHtmlText(value),
      className: columnClass(table.columns[column] ?? "") })) } : null,
  sortValueAt: (index, column) => table.rows[index]?.[column] ?? ""
});

export const getLegacyCodeViewTableModel = (
  pe: PeWindowsParseResult, tableId: string
): PagedSortableTableModel | null => {
  const match = /^(pe-debug-(entry|codeviewSource)-(\d+)-legacy)-([a-zA-Z]+)$/.exec(tableId);
  if (!match) return null;
  const legacy = codeViewInfo(pe, match[2]!, Number(match[3]));
  if (!legacy) return null;
  const table = buildLegacyCodeViewTables(legacy, pe).find(value => value.key === match[4]);
  return table ? model(table, match[1]!) : null;
};

const codeViewInfo = (pe: PeWindowsParseResult, kind: string, index: number): PeLegacyCodeViewInfo | undefined =>
  kind === "entry" ? pe.debug?.entries?.[index]?.legacyCodeView : pe.debug?.codeViewSources?.[index]?.legacyCodeView;

const renderInfo = (legacy: PeLegacyCodeViewInfo, prefix: string, out: string[], pe?: PeWindowsParseResult): void => {
  out.push(`<dl>`, renderDefinitionRow("Embedded CodeView format", escapeHtml(legacy.signature)),
    renderDefinitionRow("Directory generations", String(legacy.directories.length)), `</dl>`);
  if (legacy.directories.length > 1) out.push(`<p class="smallNote">Directory generations are shown separately; ` +
    `later incremental-link records update earlier module records.</p>`);
  for (const table of buildLegacyCodeViewTables(legacy, pe)) {
    out.push(`<h4>${escapeHtml(table.title)}</h4>`, renderAutoPagedSortableTable(model(table, prefix)));
  }
};

export const renderLegacyCodeView = (entry: PeDebugDirectoryEntry, index: number, out: string[],
  pe?: PeWindowsParseResult): void => {
  if (entry.legacyCodeView) renderInfo(entry.legacyCodeView, `pe-debug-entry-${index}-legacy`, out, pe);
};

export const renderCodeViewSources = (pe: PeWindowsParseResult, out: string[]): void => {
  pe.debug?.codeViewSources?.forEach((source, index) => {
    const location = { section: ".debug section", overlay: "Appended debug data", directory: "Direct DEBUG data" }[source.kind];
    out.push(`<details><summary>CodeView source #${index + 1}: ${location} (${humanSize(source.size)})</summary>`);
    renderInfo(source.legacyCodeView, `pe-debug-codeviewSource-${index}-legacy`, out, pe);
    out.push(`</details>`);
  });
};
