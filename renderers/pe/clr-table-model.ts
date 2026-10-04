"use strict";

import type { PagedSortableTableModel } from "../paged-sortable-table.js";

const numericHeaders = new Set(["RID", "Rows", "RVA", "Flags", "Sequence", "Methods"]);

export const createClrTableModel = (
  title: string, headers: string[], rowCount: number, cellsAt: (index: number) => string[] | null
): PagedSortableTableModel => {
  const columns = headers.map(label => ({ label,
    ...(numericHeaders.has(label) ? { className: "peNumeric" } : {}) }));
  return {
  id: `pe-clr-${encodeURIComponent(title)}`,
  // A page size affects presentation only; every parsed row remains available.
  pageSize: 80, rowCount, columns,
  rowAt: index => {
    const cells = cellsAt(index);
    return cells ? { cells: cells.map((html, column) => ({ html,
      ...(columns[column]?.className ? { className: columns[column]!.className } : {}) })) } : null;
  },
  sortValueAt: (index, column) => cellsAt(index)?.[column] ?? ""
  };
};
