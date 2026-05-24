"use strict";
import { collectDirectoryRows, formatAccessError, getDroppedFileSystemHandles } from "./directory-handles.js";
import { scanDirectoryFileRows } from "./directory-file-scanning.js";
import {
  createDirectoryRootForFiles,
  createDirectoryRootForHandles
} from "./directory-virtual-roots.js";
import { clearDirectoryTables, renderDirectoryTables } from "./directory-table-rendering.js";
import { enhanceSortableTables, handleSortableTableClick } from "./sortable-tables.js";
import type {
  BrowserDirectoryHandle,
  DirectoryDropItemList,
  DirectoryFileRow,
  DirectoryFolderRow,
  DirectoryRow
} from "./directory-handles.js";
import type { DirectoryTableElements } from "./directory-table-rendering.js";
type StatusWriter = (message: string | null | undefined) => void;
type FileTypeDetector = (file: File) => Promise<string>;
type FileOpener = (file: File, sourceDescription: string) => Promise<void>;
type TimeSource = () => number;
interface DirectoryInspectionConfig extends DirectoryTableElements {
  openButtonElement: HTMLButtonElement;
  backButtonElement: HTMLButtonElement;
  cardElement: HTMLElement;
  nameElement: HTMLElement;
  summaryElement: HTMLElement;
  progressWrapElement: HTMLElement;
  progressElement: HTMLProgressElement;
  progressTextElement: HTMLElement;
  resetFileInspection: () => void;
  setStatusMessage: StatusWriter;
  openFile: FileOpener;
  detectFileType?: FileTypeDetector;
  now?: TimeSource;
  yieldToBrowser?: () => Promise<void>;
}
interface DirectoryInspectionController {
  cancel(): void;
  hide(): void;
  openFiles(files: readonly File[], sourceDescription: string): Promise<boolean>;
  open(): Promise<void>;
  openDroppedItems(items: DirectoryDropItemList, sourceDescription?: string): Promise<boolean>;
}
interface DirectoryLocation {
  readonly displayPath: string;
  readonly handle: BrowserDirectoryHandle;
}
interface DirectoryViewState {
  fileRows: ReadonlyMap<string, DirectoryFileRow>;
  folderRows: ReadonlyMap<string, DirectoryFolderRow>;
  locations: DirectoryLocation[];
  sourceDescription: string;
}
const isAbortError = (error: unknown): boolean =>
  error instanceof DOMException && error.name === "AbortError";
const getDirectoryPicker = (): (() => Promise<BrowserDirectoryHandle>) | null => {
  const picker = (window as Window & {
    showDirectoryPicker?: () => Promise<BrowserDirectoryHandle>;
  }).showDirectoryPicker;
  return typeof picker === "function" ? () => picker.call(window) : null;
};

const createRowMap = <Row extends DirectoryRow>(
  rows: readonly DirectoryRow[],
  kind: Row["kind"]
): Map<string, Row> => new Map(
  rows
    .filter((row): row is Row => row.kind === kind)
    .map(row => [row.path, row])
);

const setBackButtonState = (
  config: DirectoryInspectionConfig,
  locations: readonly DirectoryLocation[]
): void => {
  config.backButtonElement.hidden = locations.length <= 1;
  config.backButtonElement.disabled = locations.length <= 1;
};
const updateSummary = (
  element: HTMLElement,
  rows: readonly DirectoryRow[],
  scannedFiles: number | null
): void => {
  const fileCount = rows.filter(row => row.kind === "file").length;
  const folderCount = rows.filter(row => row.kind === "directory").length;
  const warningCount = rows.filter(row => row.kind === "warning").length;
  const scanText = scannedFiles == null ? "" : `, ${scannedFiles}/${fileCount} files scanned`;
  const warningText = warningCount ? `, ${warningCount} warning${warningCount === 1 ? "" : "s"}` : "";
  const fileText = `${fileCount} file${fileCount === 1 ? "" : "s"}`;
  const folderText = `${folderCount} folder${folderCount === 1 ? "" : "s"}`;
  element.textContent = `${fileText}, ${folderText}${scanText}${warningText}`;
};
const inspectDirectoryLocation = async (
  config: DirectoryInspectionConfig,
  state: DirectoryViewState,
  isCurrent: () => boolean
): Promise<void> => {
  if (!isCurrent()) return;
  const location = state.locations.at(-1);
  if (!location) return;
  config.resetFileInspection();
  config.cardElement.hidden = false;
  config.nameElement.textContent = location.displayPath;
  config.summaryElement.textContent = "Listing folder...";
  clearDirectoryTables(config);
  config.progressWrapElement.hidden = true;
  setBackButtonState(config, state.locations);
  const rows = await collectDirectoryRows(location.handle, isCurrent);
  if (!rows) return;
  state.fileRows = createRowMap<DirectoryFileRow>(rows, "file");
  state.folderRows = createRowMap<DirectoryFolderRow>(rows, "directory");
  const fileCells = renderDirectoryTables(config, rows);
  enhanceSortableTables(config.cardElement);
  updateSummary(config.summaryElement, rows, null);
  config.setStatusMessage("Scanning file types...");
  const scannedFiles = await scanDirectoryFileRows(config, rows, fileCells, isCurrent);
  if (scannedFiles == null) return;
  updateSummary(config.summaryElement, rows, scannedFiles);
  config.setStatusMessage(`Folder scan complete: ${scannedFiles} file${scannedFiles === 1 ? "" : "s"}.`);
};
const createDirectoryInspectionController = (
  config: DirectoryInspectionConfig
): DirectoryInspectionController => {
  let generation = 0;
  const state: DirectoryViewState = {
    fileRows: new Map(),
    folderRows: new Map(),
    locations: [],
    sourceDescription: ""
  };
  const inspectCurrentLocation = async (currentGeneration: number): Promise<void> =>
    inspectDirectoryLocation(config, state, () => generation === currentGeneration);
  const resetToRoot = (handle: BrowserDirectoryHandle, sourceDescription: string): number => {
    const currentGeneration = generation + 1;
    generation = currentGeneration;
    state.sourceDescription = sourceDescription;
    state.locations = [{ displayPath: handle.name || "Selected folder", handle }];
    return currentGeneration;
  };
  const openRoot = async (
    root: BrowserDirectoryHandle,
    sourceDescription: string,
    statusMessage: string
  ): Promise<void> => {
    const currentGeneration = resetToRoot(root, sourceDescription);
    config.setStatusMessage(statusMessage);
    await inspectCurrentLocation(currentGeneration);
  };
  const openFileRow = async (path: string): Promise<void> => {
    const row = state.fileRows.get(path);
    if (!row) return;
    const currentGeneration = generation + 1;
    generation = currentGeneration;
    try {
      config.setStatusMessage(`Opening ${path}...`);
      const file = await row.handle.getFile();
      if (generation !== currentGeneration) return;
      await config.openFile(file, `${state.sourceDescription}: ${state.locations.at(-1)?.displayPath}/${path}`);
    } catch (error) {
      if (generation === currentGeneration) config.setStatusMessage(`Unable to open file: ${formatAccessError(error)}`);
    }
  };
  const openFolderRow = async (path: string): Promise<void> => {
    const row = state.folderRows.get(path);
    const current = state.locations.at(-1);
    if (!row || !current) return;
    const currentGeneration = generation + 1;
    generation = currentGeneration;
    state.locations.push({ displayPath: `${current.displayPath}/${path}`, handle: row.handle });
    await inspectCurrentLocation(currentGeneration);
  };
  const activateRow = (target: Element | null): boolean => {
    const row = target?.closest<HTMLTableRowElement>("[data-directory-action-kind]");
    const path = row?.dataset["directoryActionPath"];
    if (!row || !path) return false;
    if (row.dataset["directoryActionKind"] === "file") void openFileRow(path);
    else if (row.dataset["directoryActionKind"] === "directory") void openFolderRow(path);
    return true;
  };
  const hide = (): void => {
    generation += 1;
    config.cardElement.hidden = true;
    state.locations = [];
    state.sourceDescription = "";
    state.fileRows = new Map();
    state.folderRows = new Map();
    clearDirectoryTables(config);
    config.progressWrapElement.hidden = true;
    setBackButtonState(config, state.locations);
  };
  const cancel = (): void => {
    generation += 1;
  };
  const open = async (): Promise<void> => {
    const picker = getDirectoryPicker();
    if (!picker) {
      config.setStatusMessage("Folder picker is not supported by this browser.");
      return;
    }
    const currentGeneration = generation + 1;
    generation = currentGeneration;
    state.locations = [];
    state.sourceDescription = "Folder";
    try {
      config.setStatusMessage("Opening folder...");
      const root = await picker();
      if (generation !== currentGeneration) return;
      state.locations = [{ displayPath: root.name || "Selected folder", handle: root }];
      await inspectCurrentLocation(currentGeneration);
    } catch (error) {
      if (isAbortError(error)) {
        config.setStatusMessage(
          "Folder selection cancelled or blocked by browser. Drop the folder onto the page instead."
        );
      } else {
        config.setStatusMessage(`Unable to open folder: ${formatAccessError(error)}`);
      }
    }
  };
  const openFiles = async (files: readonly File[], sourceDescription: string): Promise<boolean> => {
    const [onlyFile] = files;
    if (!onlyFile) return false;
    if (files.length === 1) {
      generation += 1;
      await config.openFile(onlyFile, sourceDescription);
      return true;
    }
    const root = createDirectoryRootForFiles("Selected files", files);
    if (!root) return false;
    await openRoot(root, sourceDescription, "Opening selected files...");
    return true;
  };
  const openDroppedItems = async (
    items: DirectoryDropItemList,
    sourceDescription = "Drop"
  ): Promise<boolean> => {
    try {
      const handles = await getDroppedFileSystemHandles(items);
      if (handles.length === 1 && handles[0]?.kind === "file") return false;
      const root = createDirectoryRootForHandles("Dropped items", handles);
      if (!root) return false;
      await openRoot(root, sourceDescription, "Opening selected items...");
      return true;
    } catch (error) {
      config.setStatusMessage(`Unable to open dropped items: ${formatAccessError(error)}`);
      return true;
    }
  };
  config.openButtonElement.addEventListener("click", () => {
    void open();
  });
  config.backButtonElement.addEventListener("click", () => {
    if (state.locations.length <= 1) return;
    const currentGeneration = generation + 1;
    generation = currentGeneration;
    state.locations = state.locations.slice(0, -1);
    void inspectCurrentLocation(currentGeneration);
  });
  config.cardElement.addEventListener("click", event => {
    const target = event.target instanceof Element ? event.target : null;
    if (handleSortableTableClick(target)) return;
    if (activateRow(target)) event.preventDefault();
  });
  config.cardElement.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const target = event.target instanceof Element ? event.target : null;
    if (activateRow(target)) event.preventDefault();
  });
  return { cancel, hide, open, openFiles, openDroppedItems };
};
export { createDirectoryInspectionController };
export type { DirectoryInspectionController, DirectoryInspectionConfig };
