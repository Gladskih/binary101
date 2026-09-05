"use strict";

import { open, type FileHandle } from "node:fs/promises";
import {
  DEFAULT_FILE_READ_WINDOW_BYTES,
  type DirectFileRangeReader
} from "../analyzers/file-range-reader.js";

const EMPTY_VIEW = new DataView(new ArrayBuffer(0));

type CachedWindow = { offset: number; view: DataView };

export type DiskFileRangeReader = {
  close: () => Promise<void>;
  reader: DirectFileRangeReader;
};

const clampRangeSize = (fileSize: number, offset: number, byteLength: number): number => {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(byteLength) || offset < 0 || byteLength < 1) {
    return 0;
  }
  return Math.max(0, Math.min(byteLength, fileSize - offset));
};

const isCachedWindowHit = (window: CachedWindow, offset: number, byteLength: number): boolean =>
  offset >= window.offset && offset <= window.offset + window.view.byteLength - byteLength;

const readView = async (handle: FileHandle, offset: number, byteLength: number): Promise<DataView> => {
  const bytes = new Uint8Array(byteLength);
  const result = await handle.read(bytes, 0, bytes.byteLength, offset);
  return new DataView(bytes.buffer, 0, result.bytesRead);
};

export const openDiskFileRangeReader = async (path: string, fileSize: number): Promise<DiskFileRangeReader> => {
  const handle = await open(path, "r");
  const size = Number.isSafeInteger(fileSize) && fileSize > 0 ? fileSize : 0;
  let cachedWindow: CachedWindow | null = null;
  const read = async (offset: number, byteLength: number): Promise<DataView> => {
    const available = clampRangeSize(size, offset, byteLength);
    if (!available) return EMPTY_VIEW;
    if (cachedWindow && isCachedWindowHit(cachedWindow, offset, available)) {
      return new DataView(cachedWindow.view.buffer, offset - cachedWindow.offset, available);
    }
    // Reuse the shared reader's measured cache window; see its profiling comment.
    const view = await readView(handle, offset,
      Math.min(size - offset, Math.max(available, DEFAULT_FILE_READ_WINDOW_BYTES)));
    cachedWindow = view.byteLength ? { offset, view } : null;
    return new DataView(view.buffer, view.byteOffset, Math.min(available, view.byteLength));
  };
  const readInto = async (
    offset: number,
    destination: Uint8Array<ArrayBuffer>
  ): Promise<Uint8Array<ArrayBuffer>> => {
    const available = clampRangeSize(size, offset, destination.byteLength);
    if (!available) return destination.subarray(0, 0);
    const result = await handle.read(destination, 0, available, offset);
    return destination.subarray(0, result.bytesRead);
  };
  return {
    close: async () => handle.close(),
    reader: {
      size,
      read,
      readBytes: async (offset, byteLength) => {
        const view = await read(offset, byteLength);
        return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      },
      readInto
    }
  };
};
