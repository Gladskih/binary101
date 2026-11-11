import { collectDirectoryRows, formatAccessError, getDroppedFileSystemHandles } from "./directory-handles.js";
import { scanDirectoryFileRows } from "./directory-file-scanning.js";
import { createDirectoryRootForFiles, createDirectoryRootForHandles } from "./directory-virtual-roots.js";
import { clearDirectoryTables, renderDirectoryTables } from "./directory-table-rendering.js";
import { renderInspectionContext } from "./inspection-context.js";
import {
  appendRelativeDirectoryPath,
  copyDirectoryLocations,
  createDirectoryInspectionRoute,
  createRootDirectoryLocation
} from "./directory-inspection-route.js";
import { enhanceSortableTables, handleSortableTableClick } from "./sortable-tables.js";
import type { DirectoryDropItemList, DirectoryFileRow, DirectoryFolderRow, DirectoryRow } from "./directory-handles.js";
import type { DirectoryTableElements } from "./directory-table-rendering.js";
import type {
  DirectInspectionSource,
  InspectionContext,
  InspectionContextElements,
  TransferInspectionSource
} from "./inspection-context.js";
import type { BrowserDirectoryHandle } from "./directory-handles.js";
import type { DirectoryInspectionRoute, DirectoryLocation } from "./directory-inspection-route.js";
type StatusWriter = (message: string | null | undefined) => void;
type FileTypeDetector = (file: File) => Promise<string>;
type FileOpener = (file: File, context: InspectionContext) => Promise<void>;
type DirectoryOpener = (route: DirectoryInspectionRoute) => void;
type TimeSource = () => number;
interface DirectoryInspectionConfig extends DirectoryTableElements {
  openButtonElement: HTMLButtonElement;
  cardElement: HTMLElement;
  nameElement: HTMLElement;
  contextElements: InspectionContextElements;
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
  openFiles(files: readonly File[], source: DirectInspectionSource): Promise<boolean>;
  open(): Promise<void>;
  openDroppedItems(items: DirectoryDropItemList, source?: TransferInspectionSource): Promise<boolean>;
  showRoute(route: DirectoryInspectionRoute): Promise<void>;
}
interface DirectoryViewState {
  context: InspectionContext | null;
  fileRows: ReadonlyMap<string, DirectoryFileRow>;
  folderRows: ReadonlyMap<string, DirectoryFolderRow>;
  locations: DirectoryLocation[];
}
const isAbortError = (error: unknown): boolean => error instanceof DOMException && error.name === "AbortError";
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
  isCurrent: () => boolean,
  onContentsRendered: () => void
): Promise<void> => {
  if (!isCurrent()) return;
  const location = state.locations.at(-1);
  if (!location || !state.context) return;
  config.resetFileInspection();
  config.cardElement.hidden = false;
  config.nameElement.textContent = location.name;
  renderInspectionContext(config.contextElements, state.context);
  config.summaryElement.textContent = "Listing contents...";
  config.setStatusMessage(null);
  clearDirectoryTables(config);
  config.progressWrapElement.hidden = true;
  const rows = await collectDirectoryRows(location.handle, isCurrent);
  if (!rows) return;
  state.fileRows = createRowMap<DirectoryFileRow>(rows, "file");
  state.folderRows = createRowMap<DirectoryFolderRow>(rows, "directory");
  const fileCells = renderDirectoryTables(config, rows);
  enhanceSortableTables(config.cardElement);
  onContentsRendered();
  updateSummary(config.summaryElement, rows, null);
  const scannedFiles = await scanDirectoryFileRows(config, rows, fileCells, isCurrent);
  if (scannedFiles == null || !isCurrent()) return;
  updateSummary(config.summaryElement, rows, scannedFiles);
};
class DirectoryInspectionControllerImpl implements DirectoryInspectionController {
  private generation = 0;
  private readonly focusByDirectory = new WeakMap<BrowserDirectoryHandle, string>();
  private readonly state: DirectoryViewState = {
    context: null,
    fileRows: new Map(),
    folderRows: new Map(),
    locations: []
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
    this.state.locations = []; this.state.context = null;
    this.state.fileRows = new Map();
    this.state.folderRows = new Map();
    clearDirectoryTables(this.config);
    this.config.progressWrapElement.hidden = true;
    renderInspectionContext(this.config.contextElements, null);
  }
  async open(): Promise<void> {
    const picker = getDirectoryPicker();
    if (!picker) {
      this.config.setStatusMessage("Folder picker is not supported by this browser.");
      return;
    }
    let currentGeneration = this.generation;
    try {
      const root = await picker();
      if (this.generation !== currentGeneration) return;
      const context: InspectionContext = { source: "selection", object: "directory" };
      currentGeneration = this.resetToRoot(root, context);
      this.config.openDirectory(createDirectoryInspectionRoute(context, this.state.locations));
      this.config.setStatusMessage("Opening folder...");
      await this.inspectCurrentLocation(currentGeneration);
    } catch (error) {
      // A dismissed picker and a rejected permission both surface as AbortError.
      // https://wicg.github.io/file-system-access/#api-showdirectorypicker
      if (this.generation === currentGeneration && !isAbortError(error)) {
        this.config.setStatusMessage(`Unable to open folder: ${formatAccessError(error)}`);
      }
    }
  }
  async openFiles(files: readonly File[], source: DirectInspectionSource): Promise<boolean> {
    const [onlyFile] = files;
    if (!onlyFile) return false;
    if (files.length === 1) {
      this.generation += 1;
      await this.config.openFile(onlyFile, { source, object: "file" });
      return true;
    }
    const root = createDirectoryRootForFiles("Selected files", files);
    if (!root) return false;
    await this.openRoot(root, { source, object: "collection" }, "Opening selected files...");
    return true;
  }
  async openDroppedItems(
    items: DirectoryDropItemList,
    source: TransferInspectionSource = "drop"
  ): Promise<boolean> {
    try {
      const handles = await getDroppedFileSystemHandles(items);
      if (handles.length === 1 && handles[0]?.kind === "file") return false;
      const root = createDirectoryRootForHandles(source === "paste" ? "Pasted items" : "Dropped items", handles);
      if (!root) return false;
      const object = handles.length === 1 && handles[0]?.kind === "directory" ? "directory" : "collection";
      await this.openRoot(root, { source, object }, "Opening selected items...");
      return true;
    } catch (error) {
      const action = source === "paste" ? "pasted" : "dropped";
      this.config.setStatusMessage(`Unable to open ${action} items: ${formatAccessError(error)}`);
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
    this.state.context = route.context; this.state.locations = copyDirectoryLocations(route.locations);
    await this.inspectCurrentLocation(currentGeneration);
  }
  private activateRow(target: Element | null): boolean {
    const row = target?.closest<HTMLTableRowElement>("[data-directory-action-kind]");
    const path = row?.dataset["directoryActionPath"];
    if (!row || !path) return false;
    const directory = this.state.locations.at(-1)?.handle;
    if (directory) this.focusByDirectory.set(directory, path);
    if (row.dataset["directoryActionKind"] === "file") void this.openFileRow(path);
    else if (row.dataset["directoryActionKind"] === "directory") void this.openFolderRow(path);
    return true;
  }
  private async inspectCurrentLocation(currentGeneration: number): Promise<void> {
    await inspectDirectoryLocation(this.config, this.state,
      () => this.generation === currentGeneration, () => this.restoreDirectoryFocus());
  }
  private restoreDirectoryFocus(): void {
    const owner = this.config.cardElement.ownerDocument;
    const active = owner.activeElement;
    if (active && active instanceof HTMLElement && active !== owner.body &&
      active.getClientRects().length) return;
    const directory = this.state.locations.at(-1)?.handle;
    const path = directory && this.focusByDirectory.get(directory);
    if (!path) {
      this.config.nameElement.focus({ preventScroll: true });
      return;
    }
    (Array.from(this.config.cardElement.querySelectorAll<HTMLElement>("[data-directory-action-path]"))
      .find(row => row.dataset["directoryActionPath"] === path)
      ?.querySelector<HTMLElement>(".directoryPathButton") ?? this.config.nameElement)
      .focus({ preventScroll: true });
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
      if (!location) return;
      await this.config.openFile(file, {
        source: "navigation",
        object: "file",
        relativePath: appendRelativeDirectoryPath(location.relativePath, path)
      });
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
    const relativePath = appendRelativeDirectoryPath(current.relativePath, path);
    const context: InspectionContext = { source: "navigation", object: "directory", relativePath };
    this.state.context = context;
    this.state.locations.push({ handle: row.handle, name: path, relativePath });
    this.config.openDirectory(createDirectoryInspectionRoute(context, this.state.locations));
    await this.inspectCurrentLocation(currentGeneration);
  }
  private async openRoot(
    root: BrowserDirectoryHandle,
    context: InspectionContext,
    statusMessage: string
  ): Promise<void> {
    const currentGeneration = this.resetToRoot(root, context);
    this.config.openDirectory(createDirectoryInspectionRoute(context, this.state.locations));
    this.config.setStatusMessage(statusMessage);
    await this.inspectCurrentLocation(currentGeneration);
  }
  private resetToRoot(handle: BrowserDirectoryHandle, context: InspectionContext): number {
    const currentGeneration = this.generation + 1;
    this.generation = currentGeneration; this.state.context = context;
    this.state.locations = [createRootDirectoryLocation(handle, context)];
    return currentGeneration;
  }
}
const createDirectoryInspectionController = (config: DirectoryInspectionConfig): DirectoryInspectionController =>
  new DirectoryInspectionControllerImpl(config);
export { createDirectoryInspectionController };
export type { DirectoryInspectionController, DirectoryInspectionConfig, DirectoryInspectionRoute };
