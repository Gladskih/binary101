"use strict";

import { formatHumanSize } from "../binary-utils.js";
import type {
  DirectoryFileRow,
  DirectoryFolderRow,
  DirectoryRow,
  DirectoryWarningRow
} from "./directory-handles.js";

interface DirectoryTableElements {
  folderSectionElement: HTMLElement;
  fileSectionElement: HTMLElement;
  warningSectionElement: HTMLElement;
  folderTableBodyElement: HTMLElement;
  fileTableBodyElement: HTMLElement;
  warningTableBodyElement: HTMLElement;
}

interface DirectoryFileCells {
  readonly rowElement: HTMLTableRowElement;
  readonly sizeCell: HTMLElement;
  readonly mimeTypeCell: HTMLElement;
  readonly modifiedCell: HTMLElement;
  readonly typeCell: HTMLElement;
}

const NOT_PROVIDED_TEXT = "Not provided";
const UNAVAILABLE_TEXT = "Unavailable";

const appendCell = (row: HTMLTableRowElement, text: string, className?: string): HTMLElement => {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (className) cell.className = className;
  row.append(cell);
  return cell;
};

const displayPathForDirectory = (path: string): string => `${path}/`;

const markActionRow = (
  row: HTMLTableRowElement,
  kind: "directory" | "file",
  path: string,
  title: string
): void => {
  row.className = "directoryActionRow";
  row.tabIndex = 0;
  row.dataset["directoryActionKind"] = kind;
  row.dataset["directoryActionPath"] = path;
  row.title = title;
};

const formatBrowserTimestamp = (timestamp: number): string => {
  if (!Number.isFinite(timestamp)) return NOT_PROVIDED_TEXT;
  try {
    return new Date(timestamp).toISOString();
  } catch {
    return NOT_PROVIDED_TEXT;
  }
};

const formatBrowserMimeType = (mimeType: string): string =>
  mimeType.length > 0 ? mimeType : NOT_PROVIDED_TEXT;

const renderFolderRow = (row: DirectoryFolderRow): HTMLTableRowElement => {
  const tableRow = document.createElement("tr");
  const displayPath = displayPathForDirectory(row.path);
  markActionRow(tableRow, "directory", row.path, `Open ${displayPath}`);
  appendCell(tableRow, displayPath, "directoryPathCell").title = displayPath;
  appendCell(tableRow, String(row.childCounts.directFolderCount), "directoryNumericCell");
  appendCell(tableRow, String(row.childCounts.directFileCount), "directoryNumericCell");
  appendCell(tableRow, String(row.childCounts.totalFolderCount), "directoryNumericCell");
  appendCell(tableRow, String(row.childCounts.totalFileCount), "directoryNumericCell");
  return tableRow;
};

const renderFileRow = (
  row: DirectoryFileRow,
  fileCells: Map<string, DirectoryFileCells>
): HTMLTableRowElement => {
  const tableRow = document.createElement("tr");
  markActionRow(tableRow, "file", row.path, `Analyze ${row.path}`);
  appendCell(tableRow, row.path, "directoryPathCell").title = row.path;
  const sizeCell = appendCell(tableRow, "Queued", "directoryNumericCell");
  const mimeTypeCell = appendCell(tableRow, "Queued");
  const modifiedCell = appendCell(tableRow, "Queued");
  const typeCell = appendCell(tableRow, "Queued");
  fileCells.set(row.path, { rowElement: tableRow, sizeCell, mimeTypeCell, modifiedCell, typeCell });
  return tableRow;
};

const renderWarningRow = (row: DirectoryWarningRow): HTMLTableRowElement => {
  const tableRow = document.createElement("tr");
  appendCell(tableRow, row.path, "directoryPathCell").title = row.path;
  appendCell(tableRow, row.message);
  return tableRow;
};

const replaceRows = (
  sectionElement: HTMLElement,
  tableBodyElement: HTMLElement,
  rows: readonly HTMLTableRowElement[]
): void => {
  sectionElement.hidden = rows.length === 0;
  tableBodyElement.replaceChildren(...rows);
};

const renderDirectoryTables = (
  elements: DirectoryTableElements,
  rows: readonly DirectoryRow[]
): Map<string, DirectoryFileCells> => {
  const fileCells = new Map<string, DirectoryFileCells>();
  replaceRows(
    elements.folderSectionElement,
    elements.folderTableBodyElement,
    rows.filter((row): row is DirectoryFolderRow => row.kind === "directory").map(renderFolderRow)
  );
  replaceRows(
    elements.fileSectionElement,
    elements.fileTableBodyElement,
    rows.filter((row): row is DirectoryFileRow => row.kind === "file").map(row => renderFileRow(row, fileCells))
  );
  replaceRows(
    elements.warningSectionElement,
    elements.warningTableBodyElement,
    rows.filter((row): row is DirectoryWarningRow => row.kind === "warning").map(renderWarningRow)
  );
  return fileCells;
};

const clearDirectoryTables = (elements: DirectoryTableElements): void => {
  elements.folderTableBodyElement.replaceChildren();
  elements.fileTableBodyElement.replaceChildren();
  elements.warningTableBodyElement.replaceChildren();
  elements.folderSectionElement.hidden = true;
  elements.fileSectionElement.hidden = true;
  elements.warningSectionElement.hidden = true;
};

const setFileMetadataCells = (cells: DirectoryFileCells, file: File): void => {
  cells.sizeCell.textContent = formatHumanSize(file.size);
  cells.sizeCell.dataset["sortValue"] = String(file.size);
  cells.mimeTypeCell.textContent = formatBrowserMimeType(file.type);
  cells.modifiedCell.textContent = formatBrowserTimestamp(file.lastModified);
  cells.modifiedCell.dataset["sortValue"] = String(file.lastModified);
  cells.modifiedCell.title = Number.isFinite(file.lastModified) ? `${file.lastModified} ms` : "";
  cells.rowElement.title = `Analyze ${file.name || "file"}`;
};

const setUnreadableFileCells = (cells: DirectoryFileCells, message: string): void => {
  cells.sizeCell.textContent = UNAVAILABLE_TEXT;
  cells.mimeTypeCell.textContent = UNAVAILABLE_TEXT;
  cells.modifiedCell.textContent = UNAVAILABLE_TEXT;
  cells.typeCell.textContent = `Unable to read: ${message}`;
};

export {
  clearDirectoryTables,
  renderDirectoryTables,
  setFileMetadataCells,
  setUnreadableFileCells
};
export type { DirectoryFileCells, DirectoryTableElements };
