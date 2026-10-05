import type { NativeAotStackTraceMap } from "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";
import { hex } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

export const getNativeAotStackTraceTableModel = (
  map: NativeAotStackTraceMap | undefined, id: string
): PagedSortableTableModel | null => {
  if (!map || id !== "native-aot-stack-trace-map") return null;
  const rows = map.entries.map(entry => [entry.methodRva === null ? "-" : hex(entry.methodRva, 8),
    hex(entry.command, 2), entry.owningTypeToken === undefined ? "-" : hex(entry.owningTypeToken, 8),
    entry.nameOffset === undefined ? "-" : hex(entry.nameOffset, 8),
    entry.signatureOffset === undefined ? "-" : hex(entry.signatureOffset, 8),
    entry.genericSignature ? `${hex(entry.genericSignature.signatureOffset, 8)} / ` +
      hex(entry.genericSignature.argumentCollectionOffset, 8) : "-"]);
  return { id, rowCount: rows.length, pageSize: 100, tableClassName: "nativeAotStackTraceTable",
    columns: ["Method RVA", "Command", "Owning type token update", "Name offset update",
      "Signature offset update", "Generic signature / arguments update"].map(label =>
      ({ label, className: "peNumeric" })),
    rowAt: index => rows[index] ? { cells: rows[index]!.map(value => ({
      html: escapeHtml(value), sortValue: value, className: "peNumeric"
    })) } : null,
    sortValueAt: (row, column) => rows[row]?.[column] ?? "" };
};

export const renderNativeAotStackTraceMap = (map: NativeAotStackTraceMap | undefined): string => {
  if (!map) return "";
  const table = getNativeAotStackTraceTableModel(map, "native-aot-stack-trace-map")!;
  const warnings = map.warnings.length ?
    `<ul class="smallNote">${map.warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join("")}</ul>` : "";
  return `<h4>NativeAOT stack-trace method map</h4><p class="smallNote">Validated method addresses ` +
    `supply disassembly seeds. Metadata columns show context updates in stack-trace metadata; ` +
    `unchanged fields retain the previous row's context. Hidden methods can still supply seeds.</p>` +
    warnings + (table.rowCount ? renderAutoPagedSortableTable(table) : "");
};
