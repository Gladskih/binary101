"use strict";

const SORTABLE_TABLE_SELECTOR = "table.table:not([data-sortable=\"false\"])";

type SortDirection = "ascending" | "descending";

export type SortableTableState = {
  columnIndex: number;
  direction: SortDirection;
  key?: string;
  path?: string;
};

const parseSortNumber = (value: string): number | null => {
  const normalized = value.trim().replace(/,/g, "");
  if (/^0x[0-9a-f]+$/i.test(normalized)) return Number.parseInt(normalized.slice(2), 16);
  const sizeMatch = normalized.match(/^(-?\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)\b/i);
  if (sizeMatch?.[1] && sizeMatch[2]) {
    const unitPower = ["B", "KB", "MB", "GB", "TB"].indexOf(sizeMatch[2].toUpperCase());
    return Number(sizeMatch[1]) * (1024 ** Math.max(0, unitPower));
  }
  if (/^-?\d+(?:\.\d+)?$/.test(normalized)) return Number(normalized);
  return null;
};

const getSortValue = (row: HTMLTableRowElement, columnIndex: number): string =>
  row.cells.item(columnIndex)?.dataset["sortValue"] ??
  row.cells.item(columnIndex)?.textContent?.trim() ??
  "";

const compareSortValues = (left: string, right: string): number => {
  const leftNumber = parseSortNumber(left);
  const rightNumber = parseSortNumber(right);
  if (leftNumber != null && rightNumber != null) {
    return leftNumber - rightNumber;
  }
  return left.localeCompare(right, undefined, { numeric: true, sensitivity: "base" });
};

const hasSimpleCells = (cells: HTMLCollectionOf<HTMLTableCellElement>): boolean =>
  Array.from(cells).every(cell => cell.colSpan === 1 && cell.rowSpan === 1);

const isAutoSortableTable = (table: HTMLTableElement): boolean => {
  const headerRow = table.tHead?.rows.item(0);
  const tbody = table.tBodies.item(0);
  if (!headerRow || !tbody || table.tHead?.rows.length !== 1) return false;
  const columnCount = headerRow.cells.length;
  if (tbody.rows.length < 2 || columnCount < 2 || !hasSimpleCells(headerRow.cells)) return false;
  return Array.from(tbody.rows).every(
    row => row.cells.length === columnCount && hasSimpleCells(row.cells)
  );
};

const appendSortIcon = (document: Document, button: HTMLButtonElement): void => {
  const icon = document.createElement("span");
  icon.className = "sortableTableHeaderSortIcon";
  icon.setAttribute("aria-hidden", "true");
  button.append(icon);
};

const wrapHeaderContent = (header: HTMLTableCellElement, columnIndex: number): void => {
  const existingButton = header.querySelector<HTMLButtonElement>("[data-sort-table-column]");
  header.classList.add("sortableTableHeader");
  if (existingButton) return;
  const document = header.ownerDocument;
  const labelText = header.textContent?.trim() || `Column ${columnIndex + 1}`;
  const button = document.createElement("button");
  const label = document.createElement("span");
  button.type = "button";
  button.className = "sortableTableHeaderButton";
  button.dataset["sortTableColumn"] = String(columnIndex);
  button.setAttribute("aria-label", `Sort by ${labelText}`);
  label.className = "sortableTableHeaderLabel";
  while (header.firstChild) label.append(header.firstChild);
  button.append(label);
  appendSortIcon(document, button);
  header.append(button);
};

export const enhanceSortableTables = (root: ParentNode): void => {
  root.querySelectorAll<HTMLTableElement>(SORTABLE_TABLE_SELECTOR).forEach(table => {
    if (!isAutoSortableTable(table)) return;
    table.setAttribute("data-sortable", "");
    const headerRow = table.tHead?.rows.item(0);
    if (!headerRow) return;
    Array.from(headerRow.cells).forEach((header, columnIndex) => {
      wrapHeaderContent(header, columnIndex);
    });
  });
};

const updateSortHeaders = (
  table: HTMLTableElement,
  activeButton: HTMLButtonElement,
  direction: SortDirection
): void => {
  table.querySelectorAll("th").forEach(header => header.removeAttribute("aria-sort"));
  table.querySelectorAll<HTMLButtonElement>("[data-sort-table-column]").forEach(button => {
    button.removeAttribute("data-sort-direction");
  });
  activeButton.dataset["sortDirection"] = direction;
  activeButton.closest("th")?.setAttribute("aria-sort", direction);
};

const sortTableRows = (
  table: HTMLTableElement,
  columnIndex: number,
  direction: SortDirection
): void => {
  const tbody = table.tBodies.item(0);
  if (!tbody) return;
  const sign = direction === "ascending" ? 1 : -1;
  Array.from(tbody.rows)
    .map((row, index) => ({ row, index }))
    .sort((left, right) => {
      const compared = compareSortValues(
        getSortValue(left.row, columnIndex),
        getSortValue(right.row, columnIndex)
      ) * sign;
      return compared || left.index - right.index;
    })
    .forEach(({ row }) => tbody.append(row));
};

const elementIndex = (element: Element): number =>
  element.parentElement ? Array.from(element.parentElement.children).indexOf(element) : -1;

const elementPath = (root: ParentNode, element: Element): string => {
  if (!("children" in root)) return "";
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

const elementAtPath = (root: ParentNode, path: string): Element | null => {
  if (!("children" in root)) return null;
  let current: ParentNode | Element | undefined = root;
  for (const part of path.split(".")) {
    const index = Number(part);
    if (!Number.isInteger(index) || index < 0 || !("children" in current)) return null;
    current = current.children.item(index) ?? undefined;
    if (!current) return null;
  }
  return "tBodies" in current ? current as Element : null;
};

export const handleSortableTableClick = (target: Element | null): boolean => {
  const directButton = target?.closest<HTMLButtonElement>("[data-sort-table-column]");
  const headerButton = target
    ?.closest<HTMLElement>(".sortableTableHeader")
    ?.querySelector<HTMLButtonElement>("[data-sort-table-column]");
  const button = directButton || headerButton;
  const table = button?.closest<HTMLTableElement>("table[data-sortable]");
  if (!button || !table) return false;
  const columnIndex = Number(button.dataset["sortTableColumn"]);
  if (!Number.isInteger(columnIndex) || columnIndex < 0) return true;
  const previousDirection = button.dataset["sortDirection"];
  const direction = previousDirection === "ascending" ? "descending" : "ascending";
  sortTableRows(table, columnIndex, direction);
  updateSortHeaders(table, button, direction);
  return true;
};

const readSortDirection = (value: string | undefined): SortDirection | null =>
  value === "ascending" || value === "descending" ? value : null;

export const captureSortableTableState = (root: ParentNode): SortableTableState[] => {
  const states: SortableTableState[] = [];
  root.querySelectorAll<HTMLTableElement>("table[data-sortable]").forEach(table => {
    const key = table.dataset["sortStateKey"];
    const button = table.querySelector<HTMLButtonElement>("[data-sort-direction]");
    const direction = readSortDirection(button?.dataset["sortDirection"]);
    const columnIndex = Number(button?.dataset["sortTableColumn"]);
    const path = elementPath(root, table);
    if ((!key && !path) || !direction || !Number.isInteger(columnIndex) || columnIndex < 0) {
      return;
    }
    states.push({
      columnIndex,
      direction,
      ...(key ? { key } : {}),
      ...(path ? { path } : {})
    });
  });
  return states;
};

const findRestorableTable = (
  root: ParentNode,
  tables: HTMLTableElement[],
  state: SortableTableState
): HTMLTableElement | null => {
  if (state.key) {
    return tables.find(entry => entry.dataset["sortStateKey"] === state.key) ?? null;
  }
  return state.path ? elementAtPath(root, state.path) as HTMLTableElement | null : null;
};

export const restoreSortableTableState = (
  root: ParentNode,
  states: SortableTableState[]
): void => {
  const tables = Array.from(
    root.querySelectorAll<HTMLTableElement>("table[data-sortable]")
  );
  for (const state of states) {
    const table = findRestorableTable(root, tables, state);
    const button = table?.querySelector<HTMLButtonElement>(
      `[data-sort-table-column="${state.columnIndex}"]`
    );
    if (!table || !button) continue;
    sortTableRows(table, state.columnIndex, state.direction);
    updateSortHeaders(table, button, state.direction);
  }
};

export { compareSortValues };
