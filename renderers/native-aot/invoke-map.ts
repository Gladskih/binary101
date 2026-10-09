import type { NativeAotInvokeMap } from "../../analyzers/native-aot/format.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { createAnalysisStatisticsTable } from "../analysis-statistics.js";

export const getNativeAotInvokeTableModel = (
  map: NativeAotInvokeMap | undefined, id: string
): PagedSortableTableModel | null => {
  if (!map || id !== "native-aot-invoke-map") return null;
  return createAnalysisStatisticsTable(id, [
    { label: "Reflection invocation records", value: map.entries.length,
      description: "Retained methods that can be invoked through reflection." },
    { label: "Distinct method bodies", value: new Set(map.entries.flatMap(entry =>
      entry.entrypointRva === null ? [] : [entry.entrypointRva])).size,
    description: "Validated compiled methods; several reflection records can share a body." },
    { label: "Distinct invocation stubs", value: new Set(map.entries.flatMap(entry =>
      entry.invokeStubRva === null ? [] : [entry.invokeStubRva])).size,
    description: "Adapters that translate reflection arguments into native calls." },
    { label: "Records with generic arguments", value: map.entries.filter(entry => entry.genericArgumentIndices.length).length,
      description: "Generic instantiations retained for reflective invocation." }
  ]);
};

export const renderNativeAotInvokeMap = (map: NativeAotInvokeMap | undefined): string => {
  if (!map) return "";
  const warnings = map.warnings.length ?
    `<ul class="smallNote">${map.warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join("")}</ul>` : "";
  return `<h4>NativeAOT reflection invocation</h4>` + warnings +
    renderAutoPagedSortableTable(getNativeAotInvokeTableModel(map, "native-aot-invoke-map")!);
};
