"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { mappedRvaSpan } from "./rva-mapping.js";
import type { RvaToOffset } from "./types.js";

type RawChunk = readonly [offset: number, byteLength: number];

const collectMappedPrefixChunks = (
  startRva: number,
  byteLength: number,
  readerSize: number,
  rvaToOff: RvaToOffset
): RawChunk[] => {
  const chunks: RawChunk[] = [];
  for (let index = 0; index < byteLength;) {
    const span = mappedRvaSpan(rvaToOff, startRva + index, byteLength - index, readerSize);
    if (!span) break;
    chunks.push([span.offset, span.size]);
    index += span.size;
  }
  return chunks;
};

// Returns the readable prefix because callers need partial data to report malformed PE fields.
export const readMappedRvaPrefix = async (
  reader: Pick<FileRangeReader, "read" | "size"> & Partial<FileRangeReader>,
  startRva: number,
  byteLength: number,
  rvaToOff: RvaToOffset
): Promise<DataView> => {
  const chunks = collectMappedPrefixChunks(startRva, byteLength, reader.size, rvaToOff);
  const views: DataView[] = [];
  for (const chunk of chunks) {
    const view = await reader.read(chunk[0], chunk[1]);
    views.push(view);
    if (view.byteLength < chunk[1]) break;
  }
  // A contiguous RVA range is already represented by the reader's DataView, possibly
  // within its cached window. Reuse it to avoid allocating and copying the entire range
  // solely to join one fragment. Like FileRangeReader.read(), the result is read-only
  // and its byteOffset need not be zero. No measured speedup is assumed here.
  if (views.length === 1) return views[0]!;
  const bytes = new Uint8Array(views.reduce((sum, view) => sum + view.byteLength, 0));
  let destination = 0;
  for (const view of views) {
    bytes.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), destination);
    destination += view.byteLength;
  }
  return new DataView(bytes.buffer);
};

export const readMappedRvaBytes = async (
  reader: FileRangeReader, startRva: number, byteLength: number, rvaToOff: RvaToOffset
): Promise<Uint8Array> => {
  const view = await readMappedRvaPrefix(reader, startRva, byteLength, rvaToOff);
  return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
};
