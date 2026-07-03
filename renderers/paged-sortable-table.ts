"use strict";

import { escapeHtml } from "../html-utils.js";
import {
  DEFAULT_PAGED_SORTABLE_TABLE_STATE,
  getPagedSortableTablePageCount,
  normalizePagedSortableTableState,
  pageIndexesForPagedSortableTable,
  sortIndexesForPagedSortableTable,
  type PagedSortableTableModel,
  type PagedSortableTableState
} from "../ui/paged-sortable-table-state.js";

export type {
  PagedSortableTableCell,
  PagedSortableTableModel,
  PagedSortableTableRow
} from "../ui/paged-sortable-table-state.js";

const renderSortIcon = (): string =>
  `<span class="sortableTableHeaderSortIcon" aria-hidden="true"></span>`;

export const renderPagedSortableTable = (
  model: PagedSortableTableModel,
  state: PagedSortableTableState = DEFAULT_PAGED_SORTABLE_TABLE_STATE
): string => {
  const normalized = normalizePagedSortableTableState(state, model);
  return `<div class="pagedSortableTable" data-paged-sortable-table-root ` +
    `data-paged-sortable-table-id="${escapeHtml(model.id)}" ` +
    renderStateAttributes(normalized) +
    `>${renderPagedSortableToolbar(model, normalized)}` +
    `<div class="tableWrap"><table class="${tableClassName(model)}" data-sortable="false" ` +
    `data-paged-sortable-table><thead>${renderHeader(model, normalized)}</thead>` +
    `<tbody data-paged-sortable-table-body>` +
    `${renderPagedSortableTableRows(model, normalized)}</tbody></table></div></div>`;
};

export const renderAutoPagedSortableTable = (
  model: PagedSortableTableModel,
  state: PagedSortableTableState = DEFAULT_PAGED_SORTABLE_TABLE_STATE
): string =>
  model.rowCount > model.pageSize
    ? renderPagedSortableTable(model, state)
    : renderSortableTable(model);

export const renderSortableTable = (model: PagedSortableTableModel): string =>
  `<div class="tableWrap"><table class="${tableClassName(model)}" ` +
  `data-sort-state-key="${escapeHtml(model.id)}"><thead>` +
  `${renderPlainHeader(model)}</thead><tbody>` +
  `${Array.from({ length: model.rowCount }, (_, index) => renderRow(model, index)).join("")}` +
  `</tbody></table></div>`;

export const renderPagedSortableTableRows = (
  model: PagedSortableTableModel,
  state: PagedSortableTableState,
  sortedIndexes?: readonly number[]
): string =>
  pageIndexesForPagedSortableTable(
    model,
    state,
    sortedIndexes ?? sortIndexesForPagedSortableTable(model, state) ?? undefined
  )
    .map(rowIndex => renderRow(model, rowIndex))
    .join("");

export const renderPagedSortableToolbar = (
  model: PagedSortableTableModel,
  state: PagedSortableTableState
): string => {
  const pageCount = getPagedSortableTablePageCount(model.rowCount, model.pageSize);
  const firstDisabled = state.pageIndex <= 0 ? " disabled" : "";
  const lastDisabled = state.pageIndex >= pageCount - 1 ? " disabled" : "";
  return `<div class="pagedSortableTableToolbar">` +
    `<span class="pagedSortableTableRange" data-paged-sortable-table-range>` +
    `${escapeHtml(formatRange(model, state))}</span>` +
    `<span class="pagedSortableTableControls">` +
    renderPageButton("first", "First", firstDisabled) +
    renderPageButton("previous", "Prev", firstDisabled) +
    `<input class="pagedSortableTablePageInput" type="number" min="1" ` +
    `max="${pageCount}" value="${state.pageIndex + 1}" ` +
    `name="${escapeHtml(model.id)}-page" aria-label="Page" ` +
    `data-paged-sortable-page-input>` +
    `<span class="pagedSortableTablePageCount">/ ${pageCount}</span>` +
    renderPageButton("next", "Next", lastDisabled) +
    renderPageButton("last", "Last", lastDisabled) +
    `</span></div>`;
};

const renderHeader = (
  model: PagedSortableTableModel,
  state: PagedSortableTableState
): string => {
  const columns = model.columns.map((column, columnIndex) => {
    const sortDirection =
      state.sortColumnIndex === columnIndex && state.sortDirection
        ? ` data-sort-direction="${state.sortDirection}"`
        : "";
    const ariaSort =
      state.sortColumnIndex === columnIndex && state.sortDirection
        ? ` aria-sort="${state.sortDirection}"`
        : "";
    const className = column.className ? ` ${escapeHtml(column.className)}` : "";
    const tooltip = column.tooltip
      ? ` data-accessible-tooltip title="${escapeHtml(column.tooltip)}"`
      : "";
    return `<th class="sortableTableHeader${className}"${ariaSort}${tooltip}>` +
      `<button type="button" class="sortableTableHeaderButton" ` +
      `data-paged-sortable-column="${columnIndex}" aria-label="Sort by ${escapeHtml(column.label)}"` +
      `${sortDirection}><span class="sortableTableHeaderLabel">` +
      `${escapeHtml(column.label)}</span>${renderSortIcon()}</button></th>`;
  });
  return `<tr>${columns.join("")}</tr>`;
};

const renderPlainHeader = (model: PagedSortableTableModel): string => {
  const columns = model.columns.map(column => {
    const className = column.className ? ` class="${escapeHtml(column.className)}"` : "";
    const tooltip = column.tooltip
      ? ` data-accessible-tooltip title="${escapeHtml(column.tooltip)}"`
      : "";
    return `<th${className}${tooltip}>${escapeHtml(column.label)}</th>`;
  });
  return `<tr>${columns.join("")}</tr>`;
};

const renderRow = (model: PagedSortableTableModel, rowIndex: number): string => {
  const row = model.rowAt(rowIndex);
  if (!row || row.cells.length !== model.columns.length) return "";
  const rowClassName = row.className ? ` class="${escapeHtml(row.className)}"` : "";
  const primaryRow = `<tr${rowClassName}>${row.cells.map(cell => {
    const cellClassName = cell.className ? ` class="${escapeHtml(cell.className)}"` : "";
    const sortValue = cell.sortValue == null ? "" : ` data-sort-value="${escapeHtml(cell.sortValue)}"`;
    return `<td${cellClassName}${sortValue}>${cell.html}</td>`;
  }).join("")}</tr>`;
  return row.additionalRowsHtml ? `${primaryRow}${row.additionalRowsHtml}` : primaryRow;
};

const renderPageButton = (
  action: "first" | "previous" | "next" | "last",
  label: string,
  disabled: string
): string =>
  `<button type="button" class="tableButton" data-paged-sortable-action="${action}"` +
  `${disabled}>${label}</button>`;

const renderStateAttributes = (state: PagedSortableTableState): string =>
  `data-paged-sortable-page-index="${state.pageIndex}" ` +
  `data-paged-sortable-sort-column="${state.sortColumnIndex ?? ""}" ` +
  `data-paged-sortable-sort-direction="${state.sortDirection ?? ""}"`;

const tableClassName = (model: PagedSortableTableModel): string =>
  model.tableClassName ? `table ${escapeHtml(model.tableClassName)}` : "table";

const formatRange = (model: PagedSortableTableModel, state: PagedSortableTableState): string => {
  if (model.rowCount <= 0) return "Showing 0 of 0";
  const start = state.pageIndex * model.pageSize + 1;
  const end = Math.min(model.rowCount, state.pageIndex * model.pageSize + model.pageSize);
  return `Showing ${start}-${end} of ${model.rowCount}`;
};
