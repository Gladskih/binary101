"use strict";

const SORTABLE_TABLE_SELECTOR = "table.table:not([data-sortable=\"false\"])";

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
  if (columnCount < 2 || !hasSimpleCells(headerRow.cells)) return false;
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
  direction: "ascending" | "descending"
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
  direction: "ascending" | "descending"
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

export { compareSortValues };
