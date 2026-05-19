"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  compareSortValues,
  enhanceSortableTables
} from "../../ui/sortable-tables.js";

type FakeCell = {
  colSpan: number;
  rowSpan: number;
};

type FakeRow = {
  cells: FakeCell[];
};

const rowsWithItem = <Value>(rows: Value[]): Value[] & { item(index: number): Value | null } =>
  Object.assign(rows, { item: (index: number) => rows[index] ?? null });

const fakeRow = (cellCount: number): FakeRow => ({
  cells: Array.from({ length: cellCount }, () => ({ colSpan: 1, rowSpan: 1 }))
});

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
