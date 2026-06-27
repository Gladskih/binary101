"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  DEFAULT_PAGED_SORTABLE_TABLE_STATE,
  getPagedSortableTablePageCount,
  movePagedSortableTablePage,
  normalizePagedSortableTableState,
  pageIndexesForPagedSortableTable,
  sortIndexesForPagedSortableTable,
  togglePagedSortableTableSort,
  type PagedSortableTableModel
} from "../../../ui/paged-sortable-table-state.js";

const createModel = (): PagedSortableTableModel => ({
  id: "test",
  rowCount: 4,
  pageSize: 2,
  columns: [{ label: "RVA" }, { label: "Text" }],
  rowAt: rowIndex => ({ cells: [{ html: String(rowIndex) }, { html: `row-${rowIndex}` }] }),
  sortValueAt: (rowIndex, columnIndex) => {
    const values = [
      [0x4000, "delta"],
      [0x1000, "alpha"],
      [0x3000, "charlie"],
      [0x2000, "bravo"]
    ];
    return String(values[rowIndex]?.[columnIndex] ?? "");
  }
});

void test("getPagedSortableTablePageCount handles empty and partial pages", () => {
  assert.equal(getPagedSortableTablePageCount(0, 500), 1);
  assert.equal(getPagedSortableTablePageCount(1000, 500), 2);
  assert.equal(getPagedSortableTablePageCount(1001, 500), 3);
});

void test("normalizePagedSortableTableState clamps invalid page and sort fields", () => {
  assert.deepEqual(
    normalizePagedSortableTableState({
      pageIndex: -1,
      sortColumnIndex: 7,
      sortDirection: "ascending"
    }, createModel()),
    DEFAULT_PAGED_SORTABLE_TABLE_STATE
  );
});

void test("sortIndexesForPagedSortableTable sorts across every row before paging", () => {
  const model = createModel();
  const state = togglePagedSortableTableSort(DEFAULT_PAGED_SORTABLE_TABLE_STATE, 1);
  const sortedIndexes = sortIndexesForPagedSortableTable(model, state);

  assert.deepEqual(sortedIndexes, [1, 3, 2, 0]);
  assert.deepEqual(pageIndexesForPagedSortableTable(model, state, sortedIndexes ?? []), [1, 3]);
  assert.deepEqual(
    pageIndexesForPagedSortableTable(
      model,
      movePagedSortableTablePage(state, model, "next"),
      sortedIndexes ?? []
    ),
    [2, 0]
  );
});

void test("togglePagedSortableTableSort flips the active column direction", () => {
  const ascending = togglePagedSortableTableSort(DEFAULT_PAGED_SORTABLE_TABLE_STATE, 0);
  const descending = togglePagedSortableTableSort(ascending, 0);

  assert.equal(ascending.sortDirection, "ascending");
  assert.equal(descending.sortDirection, "descending");
  assert.deepEqual(sortIndexesForPagedSortableTable(createModel(), descending), [0, 2, 3, 1]);
});

void test("movePagedSortableTablePage supports button and direct page targets", () => {
  const model = createModel();
  const secondPage = movePagedSortableTablePage(DEFAULT_PAGED_SORTABLE_TABLE_STATE, model, "next");

  assert.equal(secondPage.pageIndex, 1);
  assert.equal(movePagedSortableTablePage(secondPage, model, "last").pageIndex, 1);
  assert.equal(movePagedSortableTablePage(secondPage, model, "first").pageIndex, 0);
  assert.equal(movePagedSortableTablePage(secondPage, model, "previous").pageIndex, 0);
  assert.equal(movePagedSortableTablePage(secondPage, model, 40).pageIndex, 1);
});
