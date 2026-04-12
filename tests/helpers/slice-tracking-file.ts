"use strict";

import {
  createFileRangeReader,
  type FileRangeReader
} from "../../analyzers/file-range-reader.js";

const createSliceTrackingFile = (
  bytes: Uint8Array,
  size: number,
  name = "tracked.bin"
): { file: File & FileRangeReader; requests: number[] } => {
  const requests: number[] = [];
  const file = {
    lastModified: 0,
    name,
    size,
    type: "application/octet-stream",
    webkitRelativePath: "",
    slice(start?: number, end?: number, contentType?: string): Blob {
      const sliceStart = Math.max(0, Math.trunc(start ?? 0));
      const sliceEnd = Math.max(sliceStart, Math.trunc(end ?? size));
      requests.push(sliceEnd - sliceStart);
      const actualStart = Math.min(sliceStart, bytes.length);
      const actualEnd = Math.min(sliceEnd, bytes.length);
      return new Blob([bytes.slice(actualStart, actualEnd)], {
        type: contentType ?? "application/octet-stream"
      });
    }
  } as File;
  const reader = createFileRangeReader(file, 0, size, 0);
  const trackedFile = Object.assign(file, {
    read: reader.read,
    readBytes: reader.readBytes
  }) as File & FileRangeReader;
  return { file: trackedFile, requests };
};

export { createSliceTrackingFile };
