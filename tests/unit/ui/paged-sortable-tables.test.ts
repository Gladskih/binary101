"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  capturePagedSortableTableState,
  enhancePagedSortableTables
} from "../../../ui/paged-sortable-tables.js";
import type { PagedSortableTableModel } from "../../../ui/paged-sortable-table-state.js";

type Listener = (event: { target: unknown; preventDefault: () => void }) => void;
type GlobalDom = { Element?: unknown; HTMLElement?: unknown; HTMLInputElement?: unknown };

class FakeElement {
  dataset: Record<string, string> = {};
  attributes = new Map<string, string>();
  innerHTML = "";
  outerHTML = "";
  value = "";
  tables: FakeElement[] | null = null;
  body: FakeElement | null = null;
  toolbar: FakeElement | null = null;
  headers: FakeElement[] | null = null;
  buttons: FakeElement[] | null = null;
  private listeners = new Map<string, Listener[]>();
  constructor(readonly role: string, readonly parent: FakeElement | null = null) {}
  get parentElement(): FakeElement | null { return this.parent; }
  addEventListener(type: string, listener: Listener): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }
  dispatch(type: string, target: unknown): void {
    this.listeners.get(type)?.forEach(listener => listener({ target, preventDefault: () => {} }));
  }
  matches(selector: string): boolean {
    return selector === "[data-paged-sortable-page-input]" &&
      this.role === "pageInput";
  }
  closest(selector: string): FakeElement | null {
    if (selector === "[data-paged-sortable-table-root]") {
      return this.role === "root" ? this : this.parent?.closest(selector) ?? null;
    }
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
      ? this.body ?? fakeBody
      : selector === ".pagedSortableTableToolbar"
        ? this.toolbar ?? fakeToolbar
        : null;
  }
  querySelectorAll(selector: string): FakeElement[] {
    if (selector === "[data-paged-sortable-table-root]") return this.tables ?? (this.role === "container" ? [fakeRoot] : []);
    if (selector === "th") return this.headers ?? [fakeHeader];
    if (selector === "[data-paged-sortable-column]") return this.buttons ?? [fakeSortButton];
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

const createNestedTable = (parent: FakeElement, id: string): FakeElement => {
  const table = new FakeElement("root", parent);
  table.dataset = { pagedSortableTableId: id };
  table.body = new FakeElement("body", table);
  table.toolbar = new FakeElement("toolbar", table);
  table.headers = [new FakeElement("header", table)];
  table.buttons = [new FakeElement("sort", table.headers[0]!)];
  table.buttons[0]!.dataset = { pagedSortableColumn: "1" };
  return table;
};

void test("nested tables keep their page and sort state without changing their parent", () => {
  withFakeDom(() => {
    const outer = createNestedTable(new FakeElement("container"), "outer");
    const inner = createNestedTable(outer, "inner");
    const container = new FakeElement("container");
    container.tables = [outer, inner];
    outer.tables = [inner];
    outer.headers = [outer.headers![0]!, inner.headers![0]!];
    outer.buttons = [outer.buttons![0]!, inner.buttons![0]!];
    outer.headers[0]!.attributes.set("aria-sort", "descending");
    outer.buttons[0]!.dataset = { pagedSortableColumn: "0" };
    enhancePagedSortableTables(container as unknown as ParentNode, id => ({ ...createModel(), id }));
    inner.dispatch("click", inner.buttons![0]!);
    outer.dispatch("click", inner.buttons![0]!);
    assert.equal(inner.headers![0]!.attributes.get("aria-sort"), "ascending");
    assert.equal(outer.headers![0]!.attributes.has("aria-sort"), false);
    const last = new FakeElement("action", inner);
    last.dataset = { pagedSortableAction: "last" };
    inner.dispatch("click", last);
    outer.dispatch("click", last);
    assert.equal(inner.dataset["pagedSortablePageIndex"], "1");
    assert.equal(outer.dataset["pagedSortablePageIndex"], "0");
    const input = new FakeInputElement("pageInput", inner);
    input.value = "2";
    inner.dispatch("change", input);
    outer.dispatch("change", input);
    assert.equal(inner.dataset["pagedSortablePageIndex"], "1");
    assert.equal(outer.dataset["pagedSortablePageIndex"], "0");
    input.value = "1";
    inner.dispatch("change", input);
    outer.dispatch("change", input);
    assert.equal(inner.dataset["pagedSortablePageIndex"], "0");
    assert.equal(outer.dataset["pagedSortablePageIndex"], "0");
    inner.dispatch("click", last);
    outer.tables = [];
    container.tables = [outer];
    assert.deepEqual(capturePagedSortableTableState(container as unknown as ParentNode).find(entry => entry.key === "inner"),
      { key: "inner", state: { pageIndex: 1, sortColumnIndex: 1, sortDirection: "ascending" } });
    const remounted = createNestedTable(outer, "inner");
    outer.tables = [remounted];
    outer.headers = [outer.headers[0]!, remounted.headers![0]!];
    outer.buttons = [outer.buttons[0]!, remounted.buttons![0]!];
    outer.dispatch("click", outer.buttons![0]!);
    assert.equal(remounted.dataset["pagedSortablePageIndex"], "1");
    assert.equal(remounted.headers![0]!.attributes.get("aria-sort"), "ascending");
    assert.equal(remounted.buttons![0]!.dataset["sortDirection"], "ascending");
    assert.match(remounted.body!.innerHTML, /charlie/);
  });
});

void test("table snapshots restore initial state and retain temporarily unmounted tables", () => {
  withFakeDom(() => {
    const table = createNestedTable(new FakeElement("container"), "table");
    const container = new FakeElement("container");
    container.tables = [table];
    enhancePagedSortableTables(container as unknown as ParentNode, id => ({ ...createModel(), id }), [
      { key: "table", state: { pageIndex: 1, sortColumnIndex: 1, sortDirection: "ascending" } },
      { key: "hidden", state: { pageIndex: 0, sortColumnIndex: null, sortDirection: null } }
    ]);
    assert.equal(table.dataset["pagedSortablePageIndex"], "1");
    assert.match(table.body!.innerHTML, /charlie/);
    assert.equal(capturePagedSortableTableState(container as unknown as ParentNode).length, 2);
    const noKey = new FakeElement("root");
    container.tables = [noKey];
    assert.deepEqual(capturePagedSortableTableState(container as unknown as ParentNode), []);
    noKey.dataset = { pagedSortableTableId: "offline", pagedSortablePageIndex: "1",
      pagedSortableSortColumn: "", pagedSortableSortDirection: "" };
    assert.deepEqual(capturePagedSortableTableState(container as unknown as ParentNode), [{
      key: "offline", state: { pageIndex: 1, sortColumnIndex: null, sortDirection: null }
    }]);
    noKey.dataset = {};
    enhancePagedSortableTables(container as unknown as ParentNode, () => null);
    assert.deepEqual(capturePagedSortableTableState(container as unknown as ParentNode), []);
  });
});

void test("paged table handlers ignore events whose target is not a DOM element", () => {
  withFakeDom(() => {
    const table = createNestedTable(new FakeElement("container"), "table");
    const container = new FakeElement("container");
    container.tables = [table];
    enhancePagedSortableTables(container as unknown as ParentNode, id => ({ ...createModel(), id }));
    assert.doesNotThrow(() => table.dispatch("click", null));
    assert.doesNotThrow(() => table.dispatch("click", {}));
    assert.doesNotThrow(() => table.dispatch("change", {}));
    assert.equal(table.dataset["pagedSortablePageIndex"], "0");
  });
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
    const container = new FakeElement("container");
    fakeRoot.dataset = { pagedSortableTableId: "strings" };
    fakeBody.innerHTML = "";
    fakeSortButton.dataset = { pagedSortableColumn: "1" };
    fakeHeader.attributes.clear();
    enhancePagedSortableTables(
      container as unknown as ParentNode,
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
    assert.deepEqual(capturePagedSortableTableState(container as unknown as ParentNode), [{
      key: "strings",
      state: { pageIndex: 1, sortColumnIndex: 1, sortDirection: "ascending" }
    }]);

    const input = new FakeInputElement("pageInput", fakeRoot);
    input.value = "1";
    fakeRoot.dispatch("change", input);
    assert.match(fakeBody.innerHTML, /alpha/);
  });
});
