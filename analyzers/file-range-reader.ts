"use strict";

// Browser BYOB reads detach the supplied view. The returned view restores
// ownership of the same backing buffer and covers only the bytes read.
type FileRangeReadInto = (
  offset: number,
  destination: Uint8Array<ArrayBuffer>
) => Promise<Uint8Array<ArrayBuffer>>;

export type FileRangeReader = {
  size: number;
  read: (offset: number, size: number) => Promise<DataView>;
  readBytes: (offset: number, size: number) => Promise<Uint8Array>;
  readInto?: FileRangeReadInto;
};

export type DirectFileRangeReader = FileRangeReader & { readInto: FileRangeReadInto };

type CachedWindow = {
  offset: number;
  view: DataView;
};

const EMPTY_VIEW = new DataView(new ArrayBuffer(0));
const EMPTY_BYTES = new Uint8Array(0);
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
export const DEFAULT_FILE_READ_WINDOW_BYTES = 64 * 1024;

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
  windowBytes = DEFAULT_FILE_READ_WINDOW_BYTES
): DirectFileRangeReader => {
  const size = Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 0;
  let cachedWindow: CachedWindow | null = null;
  const cacheWindowBytes = Number.isFinite(windowBytes) && windowBytes > 0
    ? Math.floor(windowBytes)
    : 0;

  const read = async (offset: number, byteLength: number): Promise<DataView> => {
    const availableSize = clampRangeSize(size, offset, byteLength);
    if (availableSize === 0) return EMPTY_VIEW;
    if (cachedWindow && isCachedWindowHit(cachedWindow, offset, availableSize)) {
      return subView(cachedWindow.view, offset - cachedWindow.offset, availableSize);
    }
    const shouldCache = cacheWindowBytes > 0 && availableSize <= cacheWindowBytes;
    const readSize = shouldCache
      ? clampRangeSize(size, offset, cacheWindowBytes)
      : availableSize;
    const view = new DataView(
      await file
        .slice(baseOffset + offset, baseOffset + offset + readSize)
        .arrayBuffer()
    );
    cachedWindow = shouldCache && view.byteLength ? { offset, view } : null;
    return subView(view, 0, Math.min(availableSize, view.byteLength));
  };

  const readBytes = async (offset: number, byteLength: number): Promise<Uint8Array> => {
    const view = await read(offset, byteLength);
    return view.byteLength
      ? new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
      : EMPTY_BYTES;
  };

  const readInto = async (
    offset: number,
    destination: Uint8Array<ArrayBuffer>
  ): Promise<Uint8Array<ArrayBuffer>> => {
    const availableSize = clampRangeSize(size, offset, destination.byteLength);
    if (availableSize === 0) return destination.subarray(0, 0);
    const streamReader = file
      .slice(baseOffset + offset, baseOffset + offset + availableSize)
      .stream()
      .getReader({ mode: "byob" });
    try {
      // A BYOB read detaches the supplied view and returns a new view over the
      // same backing memory. Requiring the full range avoids consumer-side chunks.
      const range = destination.subarray(0, availableSize);
      const next = await streamReader.read(range, { min: availableSize });
      if (!next.value) throw new Error("BYOB read did not return its destination buffer");
      return next.value;
    } finally {
      streamReader.releaseLock();
    }
  };

  return { size, read, readBytes, readInto };
};
