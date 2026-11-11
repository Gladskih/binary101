import type { PagedSortableTableModel } from "./paged-sortable-table-state.js";

export const filterPagedTable = (
  model: PagedSortableTableModel,
  query: string
): PagedSortableTableModel => {
  const normalized = query.trim().toLowerCase();
  if (!normalized || !model.searchValueAt) return model;
  const matches: number[] = [];
  for (let index = 0; index < model.rowCount; index += 1) {
    if (model.searchValueAt(index).toLowerCase().includes(normalized)) matches.push(index);
  }
  return {
    ...model,
    rowCount: matches.length,
    rowAt: index => matches[index] == null ? null : model.rowAt(matches[index]),
    sortValueAt: (index, column) => matches[index] == null ? "" :
      model.sortValueAt(matches[index], column),
    searchValueAt: index => matches[index] == null ? "" :
      model.searchValueAt?.(matches[index]) ?? ""
  };
};
