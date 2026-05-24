"use strict";

import type {
  BrowserDirectoryHandle,
  BrowserFileHandle,
  BrowserFileSystemHandle
} from "./directory-handles.js";

const isDirectoryHandle = (handle: BrowserFileSystemHandle): handle is BrowserDirectoryHandle => {
  const maybe = handle as BrowserFileSystemHandle & { entries?: unknown };
  return handle.kind === "directory" && typeof maybe.entries === "function";
};

const createFileHandle = (file: File): BrowserFileHandle => ({
  kind: "file",
  name: file.name || "unnamed.bin",
  getFile: async () => file
});

const createUniqueEntryName = (name: string, counts: Map<string, number>): string => {
  const count = (counts.get(name) ?? 0) + 1;
  counts.set(name, count);
  return count === 1 ? name : `${name} (${count})`;
};

const createVirtualDirectoryHandle = (
  name: string,
  handles: readonly BrowserFileSystemHandle[]
): BrowserDirectoryHandle => ({
  kind: "directory",
  name,
  async *entries() {
    const counts = new Map<string, number>();
    for (const handle of handles) {
      yield [createUniqueEntryName(handle.name || "(unnamed)", counts), handle];
    }
  }
});

const createDirectoryRootForHandles = (
  name: string,
  handles: readonly BrowserFileSystemHandle[]
): BrowserDirectoryHandle | null => {
  const [onlyHandle] = handles;
  if (!onlyHandle) return null;
  if (handles.length === 1 && isDirectoryHandle(onlyHandle)) return onlyHandle;
  return createVirtualDirectoryHandle(name, handles);
};

const createDirectoryRootForFiles = (
  name: string,
  files: readonly File[]
): BrowserDirectoryHandle | null =>
  createDirectoryRootForHandles(name, files.map(createFileHandle));

export { createDirectoryRootForFiles, createDirectoryRootForHandles };
