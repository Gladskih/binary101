import type { NativeAotInvokeMap } from "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";
import { hex } from "../../binary-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";

export const getNativeAotInvokeTableModel = (
  map: NativeAotInvokeMap | undefined, id: string
): PagedSortableTableModel | null => {
  if (!map || id !== "native-aot-invoke-map") return null;
  const rows = map.entries.map(entry => [hex(entry.metadataOffset, 8), hex(entry.flags, 4),
    entry.declaringTypeIndex, entry.entrypointRva === null ? "-" : hex(entry.entrypointRva, 8),
    entry.invokeStubRva === null ? "-" : hex(entry.invokeStubRva, 8),
    entry.genericArgumentIndices.join(", ") || "-"]);
  return { id, rowCount: rows.length, pageSize: 100, tableClassName: "nativeAotInvokeTable",
    columns: ["Method metadata offset", "Flags", "Declaring type index", "Entry point RVA",
      "Invoke stub RVA", "Generic type indices"].map(label => ({ label, className: "peNumeric" })),
    rowAt: index => rows[index] ? { cells: rows[index]!.map(value => ({
      html: escapeHtml(String(value)), sortValue: String(value), className: "peNumeric"
    })) } : null,
    sortValueAt: (row, column) => String(rows[row]?.[column] ?? "") };
};

export const renderNativeAotInvokeMap = (map: NativeAotInvokeMap | undefined): string => {
  if (!map) return "";
  const table = getNativeAotInvokeTableModel(map, "native-aot-invoke-map")!;
  const warnings = map.warnings.length ?
    `<ul class="smallNote">${map.warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join("")}</ul>` : "";
  return `<h4>NativeAOT invoke map</h4><p class="smallNote">Validated method and invoke-stub ` +
    `addresses supply disassembly seeds. Method offsets refer to retained NativeFormat metadata; ` +
    `multiple entries may share the same native code.</p>` + warnings +
    (table.rowCount ? renderAutoPagedSortableTable(table) : "");
};
