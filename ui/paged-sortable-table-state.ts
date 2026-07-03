"use strict";

import { compareSortValues } from "./sortable-tables.js";

export type PagedSortableSortDirection = "ascending" | "descending";

export type PagedSortableTableState = {
  pageIndex: number;
  sortColumnIndex: number | null;
  sortDirection: PagedSortableSortDirection | null;
};

export type PagedSortableTableModel = {
  id: string;
  rowCount: number;
  pageSize: number;
  columns: PagedSortableTableColumn[];
  rowAt: (rowIndex: number) => PagedSortableTableRow | null;
  sortValueAt: (rowIndex: number, columnIndex: number) => string;
  tableClassName?: string;
};

export type PagedSortableTableColumn = {
  label: string;
  className?: string;
  tooltip?: string;
};

export type PagedSortableTableRow = {
  additionalRowsHtml?: string;
  cells: PagedSortableTableCell[];
  className?: string;
};

export type PagedSortableTableCell = {
  html: string;
  sortValue?: string;
  className?: string;
};

export const DEFAULT_PAGED_SORTABLE_TABLE_STATE: PagedSortableTableState = {
  pageIndex: 0,
  sortColumnIndex: null,
  sortDirection: null
};

export const getPagedSortableTablePageCount = (
  rowCount: number,
  pageSize: number
): number => {
  if (!Number.isSafeInteger(rowCount) || rowCount <= 0) return 1;
  if (!Number.isSafeInteger(pageSize) || pageSize <= 0) return 1;
  return Math.max(1, Math.ceil(rowCount / pageSize));
};

export const normalizePagedSortableTableState = (
  state: PagedSortableTableState,
  model: Pick<PagedSortableTableModel, "columns" | "pageSize" | "rowCount">
): PagedSortableTableState => {
  const pageCount = getPagedSortableTablePageCount(model.rowCount, model.pageSize);
  const sortColumnIndex = normalizeSortColumnIndex(state.sortColumnIndex, model.columns.length);
  const sortDirection = sortColumnIndex == null ? null : normalizeSortDirection(state.sortDirection);
  return {
    pageIndex: clampPageIndex(state.pageIndex, pageCount),
    sortColumnIndex,
    sortDirection
  };
};

export const pageIndexesForPagedSortableTable = (
  model: PagedSortableTableModel,
  state: PagedSortableTableState,
  sortedIndexes?: readonly number[]
): number[] => {
  const normalized = normalizePagedSortableTableState(state, model);
  const start = normalized.pageIndex * model.pageSize;
  const end = Math.min(model.rowCount, start + model.pageSize);
  if (normalized.sortColumnIndex != null && normalized.sortDirection && sortedIndexes) {
    return sortedIndexes.slice(start, end);
  }
  return Array.from({ length: Math.max(0, end - start) }, (_, index) => start + index);
};

export const sortIndexesForPagedSortableTable = (
  model: PagedSortableTableModel,
  state: PagedSortableTableState
): number[] | null => {
  const normalized = normalizePagedSortableTableState(state, model);
  if (normalized.sortColumnIndex == null || !normalized.sortDirection) return null;
  const sign = normalized.sortDirection === "ascending" ? 1 : -1;
  const columnIndex = normalized.sortColumnIndex;
  return Array.from({ length: Math.max(0, model.rowCount) }, (_, index) => index)
    .sort((left, right) => {
      const compared = compareSortValues(
        model.sortValueAt(left, columnIndex),
        model.sortValueAt(right, columnIndex)
      ) * sign;
      return compared || left - right;
    });
};

export const togglePagedSortableTableSort = (
  state: PagedSortableTableState,
  columnIndex: number
): PagedSortableTableState => {
  const direction =
    state.sortColumnIndex === columnIndex && state.sortDirection === "ascending"
      ? "descending"
      : "ascending";
  return { pageIndex: 0, sortColumnIndex: columnIndex, sortDirection: direction };
};

export const movePagedSortableTablePage = (
  state: PagedSortableTableState,
  model: Pick<PagedSortableTableModel, "columns" | "pageSize" | "rowCount">,
  target: "first" | "previous" | "next" | "last" | number
): PagedSortableTableState => {
  const normalized = normalizePagedSortableTableState(state, model);
  const pageCount = getPagedSortableTablePageCount(model.rowCount, model.pageSize);
  if (target === "first") return { ...normalized, pageIndex: 0 };
  if (target === "previous") {
    return { ...normalized, pageIndex: Math.max(0, normalized.pageIndex - 1) };
  }
  if (target === "next") {
    return { ...normalized, pageIndex: Math.min(pageCount - 1, normalized.pageIndex + 1) };
  }
  if (target === "last") return { ...normalized, pageIndex: pageCount - 1 };
  return { ...normalized, pageIndex: clampPageIndex(target, pageCount) };
};

const normalizeSortColumnIndex = (
  columnIndex: number | null,
  columnCount: number
): number | null =>
  typeof columnIndex === "number" &&
  Number.isInteger(columnIndex) &&
  columnIndex >= 0 &&
  columnIndex < columnCount
    ? columnIndex
    : null;

const normalizeSortDirection = (
  direction: PagedSortableSortDirection | null
): PagedSortableSortDirection | null =>
  direction === "ascending" || direction === "descending" ? direction : null;

const clampPageIndex = (pageIndex: number, pageCount: number): number => {
  if (!Number.isInteger(pageIndex) || pageIndex < 0) return 0;
  return Math.min(pageIndex, Math.max(1, pageCount) - 1);
};
