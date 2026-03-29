"use strict";

export type FileRangeReader = {
  read: (offset: number, size: number) => Promise<DataView>;
};

type CachedWindow = {
  offset: number;
  view: DataView;
};

const EMPTY_VIEW = new DataView(new ArrayBuffer(0));
// Browser measurements on the original PE hot path hit a clear plateau at
// 64 KiB:
// 32 B -> 6055 slice() calls / 5001.5 ms, 63 B -> 5640 / 4369.9 ms,
// 512 B -> 3382 / 2705.9 ms, 2 KiB -> 2906 / 2418.1 ms,
// 32 KiB -> 483 / 531.3 ms, 64 KiB -> 479 / 516.1 ms,
// 128 KiB -> 477 / 482.6 ms.
// 64 KiB is the smallest power-of-two window that reaches the flat part of
// the curve; larger windows only shave off a couple of reads while doubling
// the cached bytes and over-read span. Keep that production-tuned default
// when reusing the same reader strategy in other analyzers.

const clampRangeSize = (limit: number, offset: number, size: number): number => {
  if (offset < 0) return 0;
  return Math.max(0, Math.min(size, limit - offset));
};

const subView = (view: DataView, offset: number, length: number): DataView =>
  new DataView(view.buffer, view.byteOffset + offset, length);

const isCachedWindowHit = (cachedWindow: CachedWindow, offset: number, size: number): boolean =>
  offset >= cachedWindow.offset &&
  offset <= cachedWindow.offset + cachedWindow.view.byteLength - size;

export const createFileRangeReader = (
  file: File,
  baseOffset: number,
  limit: number,
  windowBytes = 64 * 1024
): FileRangeReader => {
  let cachedWindow: CachedWindow | null = null;
  const cacheWindowBytes = Number.isFinite(windowBytes) && windowBytes > 0
    ? Math.floor(windowBytes)
    : 0;

  const read = async (offset: number, size: number): Promise<DataView> => {
    const availableSize = clampRangeSize(limit, offset, size);
    if (availableSize === 0) return EMPTY_VIEW;
    if (cachedWindow && isCachedWindowHit(cachedWindow, offset, availableSize)) {
      return subView(cachedWindow.view, offset - cachedWindow.offset, availableSize);
    }
    const shouldCache = cacheWindowBytes > 0 && availableSize <= cacheWindowBytes;
    const readSize = shouldCache
      ? clampRangeSize(limit, offset, cacheWindowBytes)
      : availableSize;
    const view = new DataView(
      await file
        .slice(baseOffset + offset, baseOffset + offset + readSize)
        .arrayBuffer()
    );
    cachedWindow = shouldCache ? { offset, view } : null;
    return subView(view, 0, availableSize);
  };

  return { read };
};
