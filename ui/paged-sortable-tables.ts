"use strict";

import {
  renderPagedSortableTableRows,
  renderPagedSortableToolbar
} from "../renderers/paged-sortable-table.js";
import {
  DEFAULT_PAGED_SORTABLE_TABLE_STATE,
  movePagedSortableTablePage,
  normalizePagedSortableTableState,
  sortIndexesForPagedSortableTable,
  togglePagedSortableTableSort,
  type PagedSortableTableModel,
  type PagedSortableTableState,
  type PagedSortableSortDirection
} from "./paged-sortable-table-state.js";

export type PagedSortableTableProvider = (
  tableId: string
) => PagedSortableTableModel | null;

export type PagedSortableTableSnapshot = {
  key: string;
  state: PagedSortableTableState;
};

type PagedSortableTableRuntime = {
  model: PagedSortableTableModel;
  state: PagedSortableTableState;
  sortedIndexes: number[] | null;
  sortedKey: string;
  provider: PagedSortableTableProvider;
  nestedSnapshots: Map<string, PagedSortableTableState>;
};

const ROOT_SELECTOR = "[data-paged-sortable-table-root]";
const runtimeByElement = new WeakMap<HTMLElement, PagedSortableTableRuntime>();
const snapshotsByProvider = new WeakMap<PagedSortableTableProvider, Map<string, PagedSortableTableState>>();

const providerSnapshots = (
  provider: PagedSortableTableProvider, snapshots: readonly PagedSortableTableSnapshot[]
): Map<string, PagedSortableTableState> => {
  const states = snapshotsByProvider.get(provider) ?? new Map<string, PagedSortableTableState>();
  for (const snapshot of snapshots) states.set(snapshot.key, snapshot.state);
  snapshotsByProvider.set(provider, states);
  return states;
};

export const enhancePagedSortableTables = (
  root: ParentNode,
  provider: PagedSortableTableProvider,
  snapshots: readonly PagedSortableTableSnapshot[] = []
): void => {
  const states = providerSnapshots(provider, snapshots);
  root.querySelectorAll<HTMLElement>(ROOT_SELECTOR).forEach(element => {
    const parent = element.parentElement?.closest(ROOT_SELECTOR);
    if (parent && parent !== root) return;
    const model = provider(element.dataset["pagedSortableTableId"] ?? "");
    if (!model) return;
    const state = states.get(model.id) ??
      readPagedSortableTableState(element);
    const runtime = {
      model,
      state: normalizePagedSortableTableState(state, model),
      sortedIndexes: null,
      sortedKey: "",
      provider,
      nestedSnapshots: states
    };
    runtimeByElement.set(element, runtime);
    renderRuntime(element, runtime);
    element.addEventListener("click", event => handleClick(element, event));
    element.addEventListener("change", event => handleChange(element, event));
  });
};

export const capturePagedSortableTableState = (
  root: ParentNode
): PagedSortableTableSnapshot[] => {
  const elements = Array.from(root.querySelectorAll<HTMLElement>(ROOT_SELECTOR));
  const states = new Map<string, PagedSortableTableState>();
  const seen = new Set<Map<string, PagedSortableTableState>>();
  for (const element of elements) {
    const saved = runtimeByElement.get(element)?.nestedSnapshots;
    if (!saved || seen.has(saved)) continue;
    for (const [key, state] of saved) states.set(key, state);
    seen.add(saved);
  }
  for (const element of elements) {
    const key = element.dataset["pagedSortableTableId"] ?? "";
    if (key) states.set(key, readPagedSortableTableState(element));
  }
  return Array.from(states, ([key, state]) => ({ key, state }));
};

const handleClick = (element: HTMLElement, event: Event): void => {
  const target = event.target instanceof Element ? event.target : null;
  if (target?.closest(ROOT_SELECTOR) !== element) return;
  const column = target?.closest<HTMLElement>("[data-paged-sortable-column]");
  if (column) {
    event.preventDefault();
    sortByColumn(element, column);
    return;
  }
  const action = target?.closest<HTMLElement>("[data-paged-sortable-action]");
  if (!action) return;
  event.preventDefault();
  movePage(element, action.dataset["pagedSortableAction"] ?? "");
};

const handleChange = (element: HTMLElement, event: Event): void => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  if (target.closest(ROOT_SELECTOR) !== element) return;
  if (!target.matches("[data-paged-sortable-page-input]")) return;
  const runtime = runtimeByElement.get(element);
  if (!runtime) return;
  runtime.state = movePagedSortableTablePage(
    runtime.state,
    runtime.model,
    Number(target.value) - 1
  );
  renderRuntime(element, runtime);
};

const sortByColumn = (element: HTMLElement, column: HTMLElement): void => {
  const runtime = runtimeByElement.get(element);
  const columnIndex = Number(column.dataset["pagedSortableColumn"]);
  if (!runtime || !Number.isInteger(columnIndex)) return;
  runtime.state = togglePagedSortableTableSort(runtime.state, columnIndex);
  runtime.sortedIndexes = null;
  renderRuntime(element, runtime);
};

const movePage = (element: HTMLElement, action: string): void => {
  const runtime = runtimeByElement.get(element);
  if (!runtime || !isPageAction(action)) return;
  runtime.state = movePagedSortableTablePage(runtime.state, runtime.model, action);
  renderRuntime(element, runtime);
};

const renderRuntime = (
  element: HTMLElement,
  runtime: PagedSortableTableRuntime
): void => {
  runtime.state = normalizePagedSortableTableState(runtime.state, runtime.model);
  updatePagedSortableTableStateAttributes(element, runtime.state);
  runtime.nestedSnapshots.set(runtime.model.id, runtime.state);
  const body = element.querySelector<HTMLElement>("[data-paged-sortable-table-body]");
  if (body) {
    body.innerHTML = renderPagedSortableTableRows(
      runtime.model,
      runtime.state,
      sortedIndexes(runtime) ?? undefined
    );
    enhancePagedSortableTables(element, runtime.provider);
  }
  const toolbar = element.querySelector<HTMLElement>(".pagedSortableTableToolbar");
  if (toolbar) toolbar.outerHTML = renderPagedSortableToolbar(runtime.model, runtime.state);
  updateHeaderState(element, runtime.state);
};

const updatePagedSortableTableStateAttributes = (
  element: HTMLElement,
  state: PagedSortableTableState
): void => {
  element.dataset["pagedSortablePageIndex"] = String(state.pageIndex);
  element.dataset["pagedSortableSortColumn"] =
    state.sortColumnIndex == null ? "" : String(state.sortColumnIndex);
  element.dataset["pagedSortableSortDirection"] = state.sortDirection ?? "";
};

const sortedIndexes = (runtime: PagedSortableTableRuntime): number[] | null => {
  const key = sortKey(runtime.state);
  if (!key) return null;
  if (runtime.sortedKey !== key) {
    runtime.sortedIndexes = sortIndexesForPagedSortableTable(runtime.model, runtime.state);
    runtime.sortedKey = key;
  }
  return runtime.sortedIndexes;
};

const updateHeaderState = (
  element: HTMLElement,
  state: PagedSortableTableState
): void => {
  element.querySelectorAll("th").forEach(header => {
    if (header.closest(ROOT_SELECTOR) === element) header.removeAttribute("aria-sort");
  });
  element.querySelectorAll<HTMLElement>("[data-paged-sortable-column]").forEach(button => {
    if (button.closest(ROOT_SELECTOR) !== element) return;
    button.removeAttribute("data-sort-direction");
    if (Number(button.dataset["pagedSortableColumn"]) !== state.sortColumnIndex) return;
    if (!state.sortDirection) return;
    button.dataset["sortDirection"] = state.sortDirection;
    button.closest("th")?.setAttribute("aria-sort", state.sortDirection);
  });
};

const readPagedSortableTableState = (element: HTMLElement): PagedSortableTableState => ({
  pageIndex: Number(element.dataset["pagedSortablePageIndex"] ?? 0),
  sortColumnIndex: readSortColumn(element.dataset["pagedSortableSortColumn"]),
  sortDirection: readSortDirection(element.dataset["pagedSortableSortDirection"])
});

const readSortColumn = (value: string | undefined): number | null => {
  if (value == null || value === "") return null;
  const columnIndex = Number(value);
  return Number.isInteger(columnIndex) && columnIndex >= 0 ? columnIndex : null;
};

const readSortDirection = (
  value: string | undefined
): PagedSortableSortDirection | null =>
  value === "ascending" || value === "descending" ? value : null;

const isPageAction = (
  action: string
): action is "first" | "previous" | "next" | "last" =>
  action === "first" || action === "previous" || action === "next" || action === "last";

const sortKey = (state: PagedSortableTableState): string =>
  state.sortColumnIndex == null || !state.sortDirection
    ? ""
    : `${state.sortColumnIndex}:${state.sortDirection}`;

export { DEFAULT_PAGED_SORTABLE_TABLE_STATE };
