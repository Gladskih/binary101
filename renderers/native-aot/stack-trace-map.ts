import type { NativeAotStackTraceMap } from "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { createAnalysisStatisticsTable } from "../analysis-statistics.js";

export const getNativeAotStackTraceTableModel = (
  map: NativeAotStackTraceMap | undefined, id: string
): PagedSortableTableModel | null => {
  if (!map || id !== "native-aot-stack-trace-map") return null;
  return createAnalysisStatisticsTable(id, [
    { label: "Stack-trace records", value: map.entries.length,
      description: "Retained metadata used to describe native methods in managed stack traces." },
    { label: "Distinct compiled methods", value: new Set(map.entries.flatMap(entry =>
      entry.methodRva === null ? [] : [entry.methodRva])).size,
    description: "Validated code addresses also seed disassembly, including methods hidden from stack traces." },
    { label: "Records with method names", value: map.entries.filter(entry => entry.nameOffset !== undefined).length,
      description: "Explicit name context updates; later records can reuse an earlier name." },
    { label: "Records with signatures", value: map.entries.filter(entry => entry.signatureOffset !== undefined).length,
      description: "Explicit method-signature context updates, not the total number of named methods." },
    { label: "Generic signature records", value: map.entries.filter(entry => entry.genericSignature).length,
      description: "Additional signatures describe generic method instantiations." }
  ]);
};

export const renderNativeAotStackTraceMap = (map: NativeAotStackTraceMap | undefined): string => {
  if (!map) return "";
  const warnings = map.warnings.length ?
    `<ul class="smallNote">${map.warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join("")}</ul>` : "";
  return `<h4>NativeAOT stack-trace metadata</h4>` + warnings +
    renderAutoPagedSortableTable(getNativeAotStackTraceTableModel(map, "native-aot-stack-trace-map")!);
};
