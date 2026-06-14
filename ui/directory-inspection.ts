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
type DirectoryOpener = (route: DirectoryInspectionRoute) => void;
type TimeSource = () => number;
interface DirectoryInspectionConfig extends DirectoryTableElements {
  openButtonElement: HTMLButtonElement;
  cardElement: HTMLElement;
  nameElement: HTMLElement;
  summaryElement: HTMLElement;
  progressWrapElement: HTMLElement;
  progressElement: HTMLProgressElement;
  progressTextElement: HTMLElement;
  resetFileInspection: () => void;
  setStatusMessage: StatusWriter;
  openFile: FileOpener;
  openDirectory: DirectoryOpener;
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
  showRoute(route: DirectoryInspectionRoute): Promise<void>;
}
interface DirectoryLocation {
  readonly displayPath: string;
  readonly handle: BrowserDirectoryHandle;
}
interface DirectoryInspectionRoute {
  readonly locations: readonly DirectoryLocation[];
  readonly sourceDescription: string;
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

const copyLocations = (locations: readonly DirectoryLocation[]): DirectoryLocation[] =>
  locations.map(location => ({ displayPath: location.displayPath, handle: location.handle }));
const createDirectoryRoute = (state: DirectoryViewState): DirectoryInspectionRoute => ({
  locations: copyLocations(state.locations),
  sourceDescription: state.sourceDescription
});
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
class DirectoryInspectionControllerImpl implements DirectoryInspectionController {
  private generation = 0;
  private readonly state: DirectoryViewState = {
    fileRows: new Map(),
    folderRows: new Map(),
    locations: [],
    sourceDescription: ""
  };

  constructor(private readonly config: DirectoryInspectionConfig) {
    config.openButtonElement.addEventListener("click", () => {
      void this.open();
    });
    config.cardElement.addEventListener("click", event => {
      const target = event.target instanceof Element ? event.target : null;
      if (handleSortableTableClick(target)) return;
      if (this.activateRow(target)) event.preventDefault();
    });
    config.cardElement.addEventListener("keydown", event => {
      if (event.key !== "Enter" && event.key !== " ") return;
      const target = event.target instanceof Element ? event.target : null;
      if (this.activateRow(target)) event.preventDefault();
    });
  }
  cancel(): void {
    this.generation += 1;
  }
  hide(): void {
    this.generation += 1;
    this.config.cardElement.hidden = true;
    this.state.locations = [];
    this.state.sourceDescription = "";
    this.state.fileRows = new Map();
    this.state.folderRows = new Map();
    clearDirectoryTables(this.config);
    this.config.progressWrapElement.hidden = true;
  }
  async open(): Promise<void> {
    const picker = getDirectoryPicker();
    if (!picker) {
      this.config.setStatusMessage("Folder picker is not supported by this browser.");
      return;
    }
    const currentGeneration = this.startFolderSelection();
    try {
      this.config.setStatusMessage("Opening folder...");
      const root = await picker();
      if (this.generation !== currentGeneration) return;
      this.state.locations = [{ displayPath: root.name || "Selected folder", handle: root }];
      this.config.openDirectory(createDirectoryRoute(this.state));
      await this.inspectCurrentLocation(currentGeneration);
    } catch (error) {
      this.reportFolderPickerError(error);
    }
  }
  async openFiles(files: readonly File[], sourceDescription: string): Promise<boolean> {
    const [onlyFile] = files;
    if (!onlyFile) return false;
    if (files.length === 1) {
      this.generation += 1;
      await this.config.openFile(onlyFile, sourceDescription);
      return true;
    }
    const root = createDirectoryRootForFiles("Selected files", files);
    if (!root) return false;
    await this.openRoot(root, sourceDescription, "Opening selected files...");
    return true;
  }
  async openDroppedItems(
    items: DirectoryDropItemList,
    sourceDescription = "Drop"
  ): Promise<boolean> {
    try {
      const handles = await getDroppedFileSystemHandles(items);
      if (handles.length === 1 && handles[0]?.kind === "file") return false;
      const root = createDirectoryRootForHandles("Dropped items", handles);
      if (!root) return false;
      await this.openRoot(root, sourceDescription, "Opening selected items...");
      return true;
    } catch (error) {
      this.config.setStatusMessage(`Unable to open dropped items: ${formatAccessError(error)}`);
      return true;
    }
  }
  async showRoute(route: DirectoryInspectionRoute): Promise<void> {
    if (route.locations.length === 0) {
      this.hide();
      return;
    }
    const currentGeneration = this.generation + 1;
    this.generation = currentGeneration;
    this.state.sourceDescription = route.sourceDescription;
    this.state.locations = copyLocations(route.locations);
    await this.inspectCurrentLocation(currentGeneration);
  }
  private activateRow(target: Element | null): boolean {
    const row = target?.closest<HTMLTableRowElement>("[data-directory-action-kind]");
    const path = row?.dataset["directoryActionPath"];
    if (!row || !path) return false;
    if (row.dataset["directoryActionKind"] === "file") void this.openFileRow(path);
    else if (row.dataset["directoryActionKind"] === "directory") void this.openFolderRow(path);
    return true;
  }
  private async inspectCurrentLocation(currentGeneration: number): Promise<void> {
    await inspectDirectoryLocation(this.config, this.state, () => this.generation === currentGeneration);
  }
  private async openFileRow(path: string): Promise<void> {
    const row = this.state.fileRows.get(path);
    if (!row) return;
    const currentGeneration = this.generation + 1;
    const location = this.state.locations.at(-1);
    this.generation = currentGeneration;
    try {
      this.config.setStatusMessage(`Opening ${path}...`);
      const file = await row.handle.getFile();
      if (this.generation !== currentGeneration) return;
      await this.config.openFile(file, `${this.state.sourceDescription}: ${location?.displayPath}/${path}`);
    } catch (error) {
      if (this.generation === currentGeneration) this.config.setStatusMessage(`Unable to open file: ${formatAccessError(error)}`);
    }
  }
  private async openFolderRow(path: string): Promise<void> {
    const row = this.state.folderRows.get(path);
    const current = this.state.locations.at(-1);
    if (!row || !current) return;
    const currentGeneration = this.generation + 1;
    this.generation = currentGeneration;
    this.state.locations.push({ displayPath: `${current.displayPath}/${path}`, handle: row.handle });
    this.config.openDirectory(createDirectoryRoute(this.state));
    await this.inspectCurrentLocation(currentGeneration);
  }
  private async openRoot(
    root: BrowserDirectoryHandle,
    sourceDescription: string,
    statusMessage: string
  ): Promise<void> {
    const currentGeneration = this.resetToRoot(root, sourceDescription);
    this.config.openDirectory(createDirectoryRoute(this.state));
    this.config.setStatusMessage(statusMessage);
    await this.inspectCurrentLocation(currentGeneration);
  }
  private reportFolderPickerError(error: unknown): void {
    if (isAbortError(error)) {
      this.config.setStatusMessage(
        "Folder selection cancelled or blocked by browser. Drop the folder onto the page instead."
      );
    } else {
      this.config.setStatusMessage(`Unable to open folder: ${formatAccessError(error)}`);
    }
  }
  private resetToRoot(handle: BrowserDirectoryHandle, sourceDescription: string): number {
    const currentGeneration = this.generation + 1;
    this.generation = currentGeneration;
    this.state.sourceDescription = sourceDescription;
    this.state.locations = [{ displayPath: handle.name || "Selected folder", handle }];
    return currentGeneration;
  }
  private startFolderSelection(): number {
    const currentGeneration = this.generation + 1;
    this.generation = currentGeneration;
    this.state.locations = [];
    this.state.sourceDescription = "Folder";
    return currentGeneration;
  }
}

const createDirectoryInspectionController = (
  config: DirectoryInspectionConfig
): DirectoryInspectionController => new DirectoryInspectionControllerImpl(config);
export { createDirectoryInspectionController };
export type { DirectoryInspectionController, DirectoryInspectionConfig, DirectoryInspectionRoute };
