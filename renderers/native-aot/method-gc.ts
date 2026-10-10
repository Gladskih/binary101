import type { NativeAotMethodGcMaps } from "../../analyzers/native-aot/gc-info-types.js";
import { escapeHtml } from "../../html-utils.js";
import { managedGcStatistics } from "../managed-gc-statistics.js";
import { createAnalysisStatisticsTable } from "../analysis-statistics.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";

export const renderNativeAotMethodGc = (data: NativeAotMethodGcMaps | undefined): string => {
  if (!data) return "";
  return `<h4>Managed method GC maps</h4>` + renderAutoPagedSortableTable(
    createAnalysisStatisticsTable("native-aot-method-gc", managedGcStatistics(data.methods.map(method => method.info)))) +
    (data.warnings.length ? `<ul class="smallNote">${data.warnings.map(warning =>
      `<li>${escapeHtml(warning)}</li>`).join("")}</ul>` : "");
};
