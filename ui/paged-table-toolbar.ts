import { renderPagedSortableToolbar } from "../renderers/paged-sortable-table.js";
import type { PagedSortableTableModel, PagedSortableTableState } from "./paged-sortable-table-state.js";

const observedToolbars = new WeakSet<HTMLElement>();

const measureToolbar = (root: HTMLElement, toolbar: HTMLElement): void => {
  root.style.setProperty("--paged-toolbar-height", `${toolbar.getBoundingClientRect().height}px`);
  if (observedToolbars.has(toolbar) || typeof ResizeObserver === "undefined") return;
  observedToolbars.add(toolbar);
  const observer = new ResizeObserver(() => {
    if (!root.isConnected) return observer.disconnect();
    root.style.setProperty("--paged-toolbar-height", `${toolbar.getBoundingClientRect().height}px`);
  });
  observer.observe(toolbar);
};

export const updatePagedTableToolbar = (
  root: HTMLElement,
  model: PagedSortableTableModel,
  state: PagedSortableTableState
): void => {
  const toolbar = root.querySelector<HTMLElement>(":scope > .pagedSortableTableToolbar");
  if (!toolbar) return;
  const focused = toolbar.ownerDocument.activeElement;
  const template = toolbar.ownerDocument.createElement("template");
  template.innerHTML = renderPagedSortableToolbar(model, state);
  for (const selector of ["[data-paged-sortable-table-range]", ".pagedSortableTablePageCount"]) {
    const target = toolbar.querySelector(selector);
    if (target) target.textContent = template.content.querySelector(selector)?.textContent ?? "";
  }
  const page = toolbar.querySelector<HTMLInputElement>("[data-paged-sortable-page-input]");
  const updated = template.content.querySelector<HTMLInputElement>("[data-paged-sortable-page-input]");
  if (page && updated) {
    page.min = updated.min;
    page.max = updated.max;
    page.value = updated.value;
  }
  toolbar.querySelectorAll<HTMLButtonElement>("[data-paged-sortable-action]").forEach(button => {
    button.disabled = Boolean(template.content.querySelector<HTMLButtonElement>(
      `[data-paged-sortable-action="${button.dataset["pagedSortableAction"]}"]`
    )?.disabled);
  });
  if (focused instanceof HTMLButtonElement && toolbar.contains(focused) && focused.disabled) {
    page?.focus({ preventScroll: true });
  }
  measureToolbar(root, toolbar);
};
