"use strict";

interface BrowserFileSystemHandle {
  kind: string;
  name: string;
}

interface BrowserFileHandle extends BrowserFileSystemHandle {
  kind: "file";
  getFile(): Promise<File>;
}

interface BrowserDirectoryHandle extends BrowserFileSystemHandle {
  kind: "directory";
  entries(): AsyncIterable<[string, BrowserFileSystemHandle]>;
}

interface DirectoryRowBase {
  path: string;
}

interface DirectoryChildCounts {
  readonly directFileCount: number;
  readonly directFolderCount: number;
  readonly totalFileCount: number;
  readonly totalFolderCount: number;
}

interface DirectoryFolderBaseRow extends DirectoryRowBase {
  kind: "directory";
  handle: BrowserDirectoryHandle;
}

interface DirectoryFolderRow extends DirectoryFolderBaseRow {
  childCounts: DirectoryChildCounts;
}

interface DirectoryFileRow extends DirectoryRowBase {
  kind: "file";
  handle: BrowserFileHandle;
}

interface DirectoryWarningRow extends DirectoryRowBase {
  kind: "warning";
  message: string;
}

interface DirectoryDropItem {
  kind: string;
  getAsFileSystemHandle?: () => Promise<BrowserFileSystemHandle | null>;
}

interface DirectoryDropItemArrayLike {
  length: number;
  readonly [index: number]: DirectoryDropItem | undefined;
}

interface DirectoryDropItemMethodList {
  length: number;
  item(index: number): DirectoryDropItem | null;
}

type DirectoryDropItemList = DirectoryDropItemArrayLike | DirectoryDropItemMethodList;
type DirectoryCollectedRow = DirectoryFolderBaseRow | DirectoryFileRow | DirectoryWarningRow;
type DirectoryRow = DirectoryFolderRow | DirectoryFileRow | DirectoryWarningRow;

interface DirectoryCountState {
  parentPath: string | null;
  directFileCount: number;
  directFolderCount: number;
  totalFileCount: number;
  totalFolderCount: number;
}

const directoryPathCollator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

const formatAccessError = (error: unknown): string =>
  error instanceof Error && error.message ? error.message : String(error);

const isDirectoryHandle = (handle: BrowserFileSystemHandle): handle is BrowserDirectoryHandle => {
  const maybe = handle as BrowserFileSystemHandle & { entries?: unknown };
  return handle.kind === "directory" && typeof maybe.entries === "function";
};

const isFileHandle = (handle: BrowserFileSystemHandle): handle is BrowserFileHandle => {
  const maybe = handle as BrowserFileSystemHandle & { getFile?: unknown };
  return handle.kind === "file" && typeof maybe.getFile === "function";
};

const joinPath = (parentPath: string, name: string): string =>
  parentPath ? `${parentPath}/${name || "(unnamed)"}` : name || "(unnamed)";

const compareDirectoryRows = (left: DirectoryRowBase, right: DirectoryRowBase): number =>
  directoryPathCollator.compare(left.path, right.path);

const createDirectoryCountState = (parentPath: string | null): DirectoryCountState => ({
  parentPath,
  directFileCount: 0,
  directFolderCount: 0,
  totalFileCount: 0,
  totalFolderCount: 0
});

const addDirectChildCount = (state: DirectoryCountState, row: DirectoryCollectedRow): void => {
  if (row.kind === "directory") {
    state.directFolderCount += 1;
    state.totalFolderCount += 1;
  } else if (row.kind === "file") {
    state.directFileCount += 1;
    state.totalFileCount += 1;
  }
};

const settleDirectoryCounts = (
  states: Map<string, DirectoryCountState>,
  directoryPaths: readonly string[]
): void => {
  for (let index = directoryPaths.length - 1; index >= 0; index -= 1) {
    const state = states.get(directoryPaths[index] ?? "");
    if (!state?.parentPath) continue;
    const parent = states.get(state.parentPath);
    if (!parent) continue;
    parent.totalFileCount += state.totalFileCount;
    parent.totalFolderCount += state.totalFolderCount;
  }
};

const addDirectoryCounts = (
  rows: readonly DirectoryCollectedRow[],
  states: ReadonlyMap<string, DirectoryCountState>
): DirectoryRow[] => rows.map(row => {
  if (row.kind !== "directory") return row;
  const state = states.get(row.path);
  return {
    ...row,
    childCounts: {
      directFileCount: state?.directFileCount ?? 0,
      directFolderCount: state?.directFolderCount ?? 0,
      totalFileCount: state?.totalFileCount ?? 0,
      totalFolderCount: state?.totalFolderCount ?? 0
    }
  };
});

const isDirectChildRow = (row: DirectoryRow): boolean =>
  row.kind === "warning" || !row.path.includes("/");

const readDirectoryEntries = async (
  folderPath: string,
  handle: BrowserDirectoryHandle
): Promise<DirectoryCollectedRow[]> => {
  const rows: DirectoryCollectedRow[] = [];
  try {
    for await (const [entryName, entry] of handle.entries()) {
      const path = joinPath(folderPath, entryName || entry.name);
      if (isDirectoryHandle(entry)) rows.push({ kind: "directory", path, handle: entry });
      else if (isFileHandle(entry)) rows.push({ kind: "file", path, handle: entry });
      else rows.push({ kind: "warning", path, message: `Unsupported entry kind: ${entry.kind}` });
    }
  } catch (error) {
    const path = folderPath || handle.name || "(root)";
    rows.push({ kind: "warning", path, message: `Unable to list folder: ${formatAccessError(error)}` });
  }
  return rows.sort(compareDirectoryRows);
};

const collectDirectoryRows = async (
  root: BrowserDirectoryHandle,
  isCurrent: () => boolean
): Promise<DirectoryRow[] | null> => {
  const rows: DirectoryCollectedRow[] = [];
  const states = new Map<string, DirectoryCountState>([["", createDirectoryCountState(null)]]);
  const directoryPaths: string[] = [];
  const pendingFolders: Array<{ path: string; handle: BrowserDirectoryHandle }> = [
    { path: "", handle: root }
  ];
  for (let index = 0; index < pendingFolders.length; index += 1) {
    if (!isCurrent()) return null;
    const pending = pendingFolders[index];
    if (!pending) continue;
    const children = await readDirectoryEntries(pending.path, pending.handle);
    if (!isCurrent()) return null;
    const state = states.get(pending.path);
    children.forEach(row => {
      rows.push(row);
      if (state) addDirectChildCount(state, row);
      if (row.kind === "directory") {
        states.set(row.path, createDirectoryCountState(pending.path));
        directoryPaths.push(row.path);
        pendingFolders.push({ path: row.path, handle: row.handle });
      }
    });
  }
  settleDirectoryCounts(states, directoryPaths);
  return addDirectoryCounts(rows, states).filter(isDirectChildRow).sort(compareDirectoryRows);
};

const getDroppedDirectoryHandle = async (
  items: DirectoryDropItemList
): Promise<BrowserDirectoryHandle | null> => {
  const handles = await getDroppedFileSystemHandles(items);
  return handles.find(isDirectoryHandle) ?? null;
};

const getDroppedFileSystemHandles = async (
  items: DirectoryDropItemList
): Promise<BrowserFileSystemHandle[]> => {
  const handles: BrowserFileSystemHandle[] = [];
  for (let index = 0; index < items.length; index += 1) {
    const item = "item" in items ? items.item(index) : items[index] ?? null;
    if (item?.kind !== "file" || typeof item.getAsFileSystemHandle !== "function") continue;
    let handle: BrowserFileSystemHandle | null;
    try {
      handle = await item.getAsFileSystemHandle();
    } catch {
      continue;
    }
    if (handle && (isDirectoryHandle(handle) || isFileHandle(handle))) handles.push(handle);
  }
  return handles;
};

export { collectDirectoryRows, formatAccessError, getDroppedDirectoryHandle, getDroppedFileSystemHandles };
export type {
  BrowserDirectoryHandle,
  BrowserFileHandle,
  BrowserFileSystemHandle,
  DirectoryDropItem,
  DirectoryDropItemList,
  DirectoryFileRow,
  DirectoryFolderRow,
  DirectoryWarningRow,
  DirectoryRow
};
