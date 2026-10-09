import { escapeHtml } from "../html-utils.js";
import type { PagedSortableTableModel } from "./paged-sortable-table.js";

export interface AnalysisStatistic {
  label: string;
  value: number;
  description: string;
}

/** Compact, explained facts rather than one row for every binary address. */
export const createAnalysisStatisticsTable = (
  id: string, statistics: AnalysisStatistic[]
): PagedSortableTableModel => ({
  id, rowCount: statistics.length, pageSize: 100,
  tableClassName: "analysisStatisticsTable",
  columns: [
    { label: "What was found" }, { label: "Count", className: "peNumeric" }, { label: "Why it matters" }
  ],
  rowAt: index => {
    const statistic = statistics[index];
    return statistic ? { cells: [
      { html: escapeHtml(statistic.label), sortValue: statistic.label },
      { html: String(statistic.value), sortValue: String(statistic.value), className: "peNumeric" },
      { html: escapeHtml(statistic.description), sortValue: statistic.description }
    ] } : null;
  },
  sortValueAt: (row, column) => {
    const statistic = statistics[row];
    return statistic ? String([statistic.label, statistic.value, statistic.description][column] ?? "") : "";
  }
});
