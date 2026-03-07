"use strict";

const createSliceTrackingFile = (
  bytes: Uint8Array,
  size: number,
  name = "tracked.bin"
): { file: File; requests: number[] } => {
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
  return { file, requests };
};

export { createSliceTrackingFile };
