"use strict";

const getSortValue = (row: HTMLTableRowElement, columnIndex: number): string =>
  row.cells.item(columnIndex)?.dataset["sortValue"] ??
  row.cells.item(columnIndex)?.textContent?.trim() ??
  "";

const compareSortValues = (left: string, right: string): number => {
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  if (Number.isFinite(leftNumber) && Number.isFinite(rightNumber)) {
    return leftNumber - rightNumber;
  }
  return left.localeCompare(right, undefined, { numeric: true, sensitivity: "base" });
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
