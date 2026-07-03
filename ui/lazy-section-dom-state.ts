"use strict";

type LazyControlElement = HTMLElement & {
  checked?: boolean;
  selectedIndex?: number;
  value?: string;
};

export type LazyControlState = {
  checked?: boolean;
  path: string;
  selectedIndex?: number;
  value?: string;
};

export type LazySelectedElementState = {
  ariaSelected: boolean;
  classSelected: boolean;
  dataSelected: boolean;
  path: string;
};

export type LazyDomState = {
  controls: LazyControlState[];
  selectedElements: LazySelectedElementState[];
};

const CONTROL_SELECTOR =
  "[data-pe-lazy-state-control], [data-filter], input[type=\"search\"], select[data-filter], textarea[data-filter]";
const SELECTED_SELECTOR = "[aria-selected=\"true\"], [data-selected=\"true\"], .selected";

export const emptyLazyDomState = (): LazyDomState => ({
  controls: [],
  selectedElements: []
});

const elementIndex = (element: Element): number =>
  element.parentElement ? Array.from(element.parentElement.children).indexOf(element) : -1;

const elementPath = (root: Element, element: Element): string => {
  const indexes: number[] = [];
  let current: Element | null = element;
  while (current && current !== root) {
    const index = elementIndex(current);
    if (index < 0) return "";
    indexes.unshift(index);
    current = current.parentElement;
  }
  return current === root ? indexes.join(".") : "";
};

const elementAtPath = (root: Element, path: string): HTMLElement | null => {
  if (!path) return root instanceof HTMLElement ? root : null;
  let current: Element | undefined = root;
  for (const part of path.split(".")) {
    const index = Number(part);
    if (!Number.isInteger(index) || index < 0) return null;
    current = current.children.item(index) ?? undefined;
    if (!current) return null;
  }
  return current instanceof HTMLElement ? current : null;
};

const captureControlState = (root: Element, control: LazyControlElement): LazyControlState | null => {
  const path = elementPath(root, control);
  if (!path) return null;
  const state: LazyControlState = { path };
  if (typeof control.value === "string") state.value = control.value;
  if (typeof control.checked === "boolean") state.checked = control.checked;
  const selectedIndex = control.selectedIndex;
  if (typeof selectedIndex === "number" && Number.isInteger(selectedIndex)) {
    state.selectedIndex = selectedIndex;
  }
  return state;
};

const captureSelectedState = (
  root: Element,
  element: HTMLElement
): LazySelectedElementState | null => {
  const path = elementPath(root, element);
  if (!path) return null;
  return {
    ariaSelected: element.getAttribute("aria-selected") === "true",
    classSelected: element.classList.contains("selected"),
    dataSelected: element.dataset["selected"] === "true",
    path
  };
};

const restoreControlState = (root: Element, state: LazyControlState): void => {
  const control = elementAtPath(root, state.path) as LazyControlElement | null;
  if (!control) return;
  if (typeof state.value === "string") control.value = state.value;
  if (typeof state.checked === "boolean") control.checked = state.checked;
  const selectedIndex = state.selectedIndex;
  if (typeof selectedIndex === "number" && Number.isInteger(selectedIndex)) {
    control.selectedIndex = selectedIndex;
  }
};

const restoreSelectedState = (root: Element, state: LazySelectedElementState): void => {
  const element = elementAtPath(root, state.path);
  if (!element) return;
  if (state.ariaSelected) element.setAttribute("aria-selected", "true");
  if (state.dataSelected) element.dataset["selected"] = "true";
  if (state.classSelected) element.classList.add("selected");
};

export const captureLazyDomState = (root: HTMLElement): LazyDomState => ({
  controls: Array.from(root.querySelectorAll<LazyControlElement>(CONTROL_SELECTOR))
    .map(control => captureControlState(root, control))
    .filter((state): state is LazyControlState => state != null),
  selectedElements: Array.from(root.querySelectorAll<HTMLElement>(SELECTED_SELECTOR))
    .map(element => captureSelectedState(root, element))
    .filter((state): state is LazySelectedElementState => state != null)
});

export const restoreLazyDomState = (root: HTMLElement, state: LazyDomState): void => {
  state.controls.forEach(controlState => restoreControlState(root, controlState));
  state.selectedElements.forEach(selectedState => restoreSelectedState(root, selectedState));
};
