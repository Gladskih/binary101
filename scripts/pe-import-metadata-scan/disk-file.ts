"use strict";

import { open } from "node:fs/promises";
import { basename } from "node:path";

export type FileSlice = { arrayBuffer(): Promise<ArrayBuffer> };
export type FileLike = { name: string; size: number; slice(start?: number, end?: number): FileSlice };

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
};

const clampSlicePosition = (value: number | undefined, fallback: number, size: number): number => {
  if (value == null || !Number.isFinite(value)) return fallback;
  return Math.max(0, Math.min(Math.floor(value), size));
};

export const createDiskBackedFile = (path: string, size: number): FileLike => ({
  name: basename(path),
  size,
  slice(start?: number, end?: number): FileSlice {
    const from = clampSlicePosition(start, 0, size);
    const to = Math.max(from, clampSlicePosition(end, size, size));
    return {
      async arrayBuffer(): Promise<ArrayBuffer> {
        const handle = await open(path, "r");
        try {
          const buffer = new Uint8Array(to - from);
          const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, from);
          return toArrayBuffer(buffer.subarray(0, bytesRead));
        } finally {
          await handle.close();
        }
      }
    };
  }
});
