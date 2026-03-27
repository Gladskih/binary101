"use strict";

export type PeRangeReader = {
  read: (offset: number, size: number) => Promise<DataView>;
};

type CachedWindow = {
  offset: number;
  view: DataView;
};

const emptyView = new DataView(new ArrayBuffer(0));
// Browser measurements on the PE hot path hit a clear plateau at 64 KiB:
// 32 B -> 6055 slice() calls / 5001.5 ms, 63 B -> 5640 / 4369.9 ms,
// 512 B -> 3382 / 2705.9 ms, 2 KiB -> 2906 / 2418.1 ms,
// 32 KiB -> 483 / 531.3 ms, 64 KiB -> 479 / 516.1 ms, 128 KiB -> 477 / 482.6 ms.
// 64 KiB is the smallest power-of-two window that reaches the flat part of the
// curve; larger windows only shave off a couple of reads here while doubling
// the cached bytes and over-read span.
const peReaderWindowBytes = 64 * 1024;

const clampRangeSize = (limit: number, offset: number, size: number): number => {
  if (offset < 0) return 0;
  return Math.max(0, Math.min(size, limit - offset));
};

const subView = (view: DataView, offset: number, length: number): DataView =>
  new DataView(view.buffer, view.byteOffset + offset, length);

const isCachedWindowHit = (
  cachedWindow: CachedWindow,
  offset: number,
  size: number
): boolean =>
  offset >= cachedWindow.offset &&
  offset <= cachedWindow.offset + cachedWindow.view.byteLength - size;

export const createPeRangeReader = (
  file: File,
  baseOffset: number,
  limit: number
): PeRangeReader => {
  let cachedWindow: CachedWindow | null = null;

  const read = async (offset: number, size: number): Promise<DataView> => {
    const availableSize = clampRangeSize(limit, offset, size);
    if (availableSize === 0) return emptyView;
    if (cachedWindow && isCachedWindowHit(cachedWindow, offset, availableSize)) {
      return subView(cachedWindow.view, offset - cachedWindow.offset, availableSize);
    }
    // Chromium profiling showed PE hot paths spending about 80 s in parsing
    // while more than 100k tiny File.slice().arrayBuffer() calls dominated the
    // cost. Keep parsing on-demand and segment-based, but reuse a 64 KiB
    // window when the caller walks nearby file offsets.
    const shouldCache = availableSize <= peReaderWindowBytes;
    const readSize = shouldCache
      ? clampRangeSize(limit, offset, peReaderWindowBytes)
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

