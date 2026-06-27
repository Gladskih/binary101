"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  capturePagedSortableTableState,
  enhancePagedSortableTables
} from "../../../ui/paged-sortable-tables.js";
import type { PagedSortableTableModel } from "../../../ui/paged-sortable-table-state.js";

type Listener = (event: { target: FakeElement; preventDefault: () => void }) => void;
type GlobalDom = { Element?: unknown; HTMLElement?: unknown; HTMLInputElement?: unknown };

class FakeElement {
  dataset: Record<string, string> = {};
  attributes = new Map<string, string>();
  innerHTML = "";
  outerHTML = "";
  value = "";
  private listeners = new Map<string, Listener>();
  constructor(readonly role: string, readonly parent: FakeElement | null = null) {}
  addEventListener(type: string, listener: Listener): void {
    this.listeners.set(type, listener);
  }
  dispatch(type: string, target: FakeElement): void {
    this.listeners.get(type)?.({ target, preventDefault: () => {} });
  }
  matches(selector: string): boolean {
    return selector === "[data-paged-sortable-page-input]" &&
      this.role === "pageInput";
  }
  closest(selector: string): FakeElement | null {
    if (selector === "[data-paged-sortable-column]") {
      return this.dataset["pagedSortableColumn"] == null ? null : this;
    }
    if (selector === "[data-paged-sortable-action]") {
      return this.dataset["pagedSortableAction"] == null ? null : this;
    }
    if (selector === "th") return this.parent;
    return null;
  }
  removeAttribute(name: string): void {
    this.attributes.delete(name);
    if (name === "data-sort-direction") delete this.dataset["sortDirection"];
  }
  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }
  querySelector(selector: string): FakeElement | null {
    return selector === "[data-paged-sortable-table-body]"
      ? fakeBody
      : selector === ".pagedSortableTableToolbar"
        ? fakeToolbar
        : null;
  }
  querySelectorAll(selector: string): FakeElement[] {
    if (selector === "[data-paged-sortable-table-root]") return [fakeRoot];
    if (selector === "th") return [fakeHeader];
    if (selector === "[data-paged-sortable-column]") return [fakeSortButton];
    return [];
  }
}

class FakeInputElement extends FakeElement {}

const fakeRoot = new FakeElement("root");
const fakeBody = new FakeElement("body", fakeRoot);
const fakeToolbar = new FakeElement("toolbar", fakeRoot);
const fakeHeader = new FakeElement("header", fakeRoot);
const fakeSortButton = new FakeElement("sort", fakeHeader);

const createModel = (): PagedSortableTableModel => ({
  id: "strings",
  rowCount: 3,
  pageSize: 2,
  columns: [{ label: "RVA" }, { label: "Text" }],
  rowAt: rowIndex => ({
    cells: [
      { html: `0x${rowIndex}` },
      { html: ["charlie", "alpha", "bravo"][rowIndex] ?? "" }
    ]
  }),
  sortValueAt: (rowIndex, columnIndex) => {
    const rows = [
      ["3", "charlie"],
      ["1", "alpha"],
      ["2", "bravo"]
    ];
    return rows[rowIndex]?.[columnIndex] ?? "";
  }
});

const withFakeDom = (callback: () => void): void => {
  const globals = globalThis as unknown as GlobalDom;
  const originalElement = globals.Element;
  const originalHTMLElement = globals.HTMLElement;
  const originalHTMLInputElement = globals.HTMLInputElement;
  globals.Element = FakeElement;
  globals.HTMLElement = FakeElement;
  globals.HTMLInputElement = FakeInputElement;
  try {
    callback();
  } finally {
    globals.Element = originalElement;
    globals.HTMLElement = originalHTMLElement;
    globals.HTMLInputElement = originalHTMLInputElement;
  }
};

void test("enhancePagedSortableTables sorts, pages, and captures state", () => {
  withFakeDom(() => {
    fakeRoot.dataset = { pagedSortableTableId: "strings" };
    fakeBody.innerHTML = "";
    fakeSortButton.dataset = { pagedSortableColumn: "1" };
    fakeHeader.attributes.clear();
    enhancePagedSortableTables(
      fakeRoot as unknown as ParentNode,
      tableId => tableId === "strings" ? createModel() : null
    );

    assert.match(fakeBody.innerHTML, /charlie/);
    fakeRoot.dispatch("click", fakeSortButton);

    assert.match(fakeBody.innerHTML, /alpha/);
    assert.equal(fakeSortButton.dataset["sortDirection"], "ascending");
    assert.equal(fakeHeader.attributes.get("aria-sort"), "ascending");

    const lastButton = new FakeElement("action", fakeRoot);
    lastButton.dataset["pagedSortableAction"] = "last";
    fakeRoot.dispatch("click", lastButton);
    assert.match(fakeBody.innerHTML, /charlie/);
    assert.deepEqual(capturePagedSortableTableState(fakeRoot as unknown as ParentNode), [{
      key: "strings",
      state: { pageIndex: 1, sortColumnIndex: 1, sortDirection: "ascending" }
    }]);

    const input = new FakeInputElement("pageInput", fakeRoot);
    input.value = "1";
    fakeRoot.dispatch("change", input);
    assert.match(fakeBody.innerHTML, /alpha/);
  });
});
