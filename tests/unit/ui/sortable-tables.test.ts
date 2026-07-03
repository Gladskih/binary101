"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  captureSortableTableState,
  compareSortValues,
  enhanceSortableTables,
  restoreSortableTableState
} from "../../../ui/sortable-tables.js";

type FakeCell = {
  colSpan: number;
  rowSpan: number;
};

type FakeRow = {
  cells: FakeCell[];
};

const SORT_STATE_KEY = "imports";
const SORT_COLUMN_INDEX = 0;
const ASCENDING_SORT_VALUES = ["1", "2"] as const;

const rowsWithItem = <Value>(rows: Value[]): Value[] & { item(index: number): Value | null } =>
  Object.assign(rows, { item: (index: number) => rows[index] ?? null });

const fakeRow = (cellCount: number): FakeRow => ({
  cells: Array.from({ length: cellCount }, () => ({ colSpan: 1, rowSpan: 1 }))
});

type FakePathElement = {
  children: ReturnType<typeof rowsWithItem<FakePathElement>>;
  parentElement: FakePathElement | null;
};

const fakeSortableRoot = (bodyRowCount: number, table: { setAttributeCalls: number }) => ({
  querySelectorAll: () => [
    {
      tHead: { rows: rowsWithItem([fakeRow(2)]) },
      tBodies: rowsWithItem([
        { rows: Array.from({ length: bodyRowCount }, () => fakeRow(2)) }
      ]),
      setAttribute: () => {
        table.setAttributeCalls += 1;
      }
    }
  ]
});

const createPathElement = (children: FakePathElement[] = []): FakePathElement => {
  const element: FakePathElement = { children: rowsWithItem([]), parentElement: null };
  children.forEach(child => {
    child.parentElement = element;
    element.children.push(child);
  });
  return element;
};

void test("compareSortValues sorts numeric strings numerically", () => {
  assert.ok(compareSortValues("16", "1024") < 0);
  assert.ok(compareSortValues("1024", "16") > 0);
  assert.equal(compareSortValues("16", "16"), 0);
});

void test("compareSortValues sorts hex and human-readable sizes numerically", () => {
  assert.ok(compareSortValues("0x00000010", "0x00000100") < 0);
  assert.ok(compareSortValues("120 KB", "1020 B") > 0);
  assert.ok(compareSortValues("2.9 KB", "4632 B") < 0);
});

void test("compareSortValues sorts text naturally when values are not numeric", () => {
  assert.ok(compareSortValues("IMPORT", "RESOURCE") < 0);
  assert.ok(compareSortValues("entry 2", "entry 10") < 0);
});

void test("enhanceSortableTables skips tables with fewer than two body rows", () => {
  const table = { setAttributeCalls: 0 };
  enhanceSortableTables(fakeSortableRoot(1, table) as unknown as ParentNode);
  assert.equal(table.setAttributeCalls, 0);
});

const createStatefulTableDom = () => {
  const shape = createStatefulTableShape(SORT_STATE_KEY);
  const root = { querySelectorAll: () => [shape.table] };
  return { ...shape, root };
};

const createStatefulTableShape = (sortStateKey?: string) => {
  const rows = ASCENDING_SORT_VALUES.map(value => ({
    cells: rowsWithItem([{
      colSpan: 1,
      rowSpan: 1,
      dataset: { sortValue: value },
      textContent: value
    }])
  }));
  const tbody = {
    rows,
    append: (row: (typeof rows)[number]): void => {
      const index = rows.indexOf(row);
      if (index >= 0) rows.splice(index, 1);
      rows.push(row);
    }
  };
  const headerAttributes = new Map<string, string>();
  const header = {
    removeAttribute: (name: string): void => { headerAttributes.delete(name); },
    setAttribute: (name: string, value: string): void => { headerAttributes.set(name, value); }
  };
  const button: {
    dataset: { sortTableColumn: string; sortDirection?: string };
    closest: (selector: string) => typeof header | null;
    removeAttribute: (name: string) => void;
  } = {
    dataset: { sortTableColumn: String(SORT_COLUMN_INDEX), sortDirection: "ascending" },
    closest: (selector: string) => selector === "th" ? header : null,
    removeAttribute: (name: string): void => {
      if (name === "data-sort-direction") delete button.dataset.sortDirection;
    }
  };
  const table = {
    dataset: sortStateKey ? { sortStateKey } : {},
    tBodies: rowsWithItem([tbody]),
    querySelector: () => button,
    querySelectorAll: (selector: string) => selector === "th" ? [header] : [button]
  };
  return { button, headerAttributes, rows, table };
};

void test("sortable table state restores keyed column, direction, and row order", () => {
  const dom = createStatefulTableDom();
  const captured = captureSortableTableState(dom.root as unknown as ParentNode);

  assert.deepEqual(captured, [{
    key: SORT_STATE_KEY,
    columnIndex: SORT_COLUMN_INDEX,
    direction: "ascending"
  }]);

  restoreSortableTableState(
    dom.root as unknown as ParentNode,
    [{ key: SORT_STATE_KEY, columnIndex: SORT_COLUMN_INDEX, direction: "descending" }]
  );

  assert.deepEqual(
    dom.rows.map(row => row.cells[SORT_COLUMN_INDEX]?.textContent),
    [...ASCENDING_SORT_VALUES].reverse()
  );
  assert.equal(dom.button.dataset.sortDirection, "descending");
  assert.equal(dom.headerAttributes.get("aria-sort"), "descending");
});

void test("sortable table state restores keyless lazy tables by DOM path", () => {
  const shape = createStatefulTableShape();
  const table = Object.assign(
    shape.table,
    createPathElement()
  ) as unknown as FakePathElement & typeof shape.table;
  const wrapper = createPathElement([table]);
  const root = Object.assign(createPathElement([wrapper]), {
    querySelectorAll: () => [table]
  });
  const captured = captureSortableTableState(root as unknown as ParentNode);

  assert.deepEqual(captured, [{
    columnIndex: SORT_COLUMN_INDEX,
    direction: "ascending",
    path: "0.0"
  }]);

  restoreSortableTableState(
    root as unknown as ParentNode,
    [{ columnIndex: SORT_COLUMN_INDEX, direction: "descending", path: "0.0" }]
  );

  assert.deepEqual(
    shape.rows.map(row => row.cells[SORT_COLUMN_INDEX]?.textContent),
    [...ASCENDING_SORT_VALUES].reverse()
  );
  assert.equal(shape.button.dataset.sortDirection, "descending");
  assert.equal(shape.headerAttributes.get("aria-sort"), "descending");
});
