"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "./layout/rva-limits.js";
import type { RvaToOffset } from "./types.js";

type RawChunk = readonly [offset: number, byteLength: number];

const collectMappedPrefixChunks = (
  startRva: number,
  byteLength: number,
  readerSize: number,
  rvaToOff: RvaToOffset
): RawChunk[] => {
  const chunks: RawChunk[] = [];
  for (let index = 0; index < byteLength; index += 1) {
    const rva = startRva + index;
    if (rva >= PE_RVA_EXCLUSIVE_LIMIT) break;
    const offset = rvaToOff(rva);
    if (offset == null || !Number.isSafeInteger(offset) || offset < 0 || offset >= readerSize) break;
    const last = chunks.at(-1);
    if (last && last[0] + last[1] === offset) {
      chunks[chunks.length - 1] = [last[0], last[1] + 1];
    } else {
      chunks.push([offset, 1]);
    }
  }
  return chunks;
};

// Returns the readable prefix because callers need partial data to report malformed PE fields.
export const readMappedRvaPrefix = async (
  reader: FileRangeReader,
  startRva: number,
  byteLength: number,
  rvaToOff: RvaToOffset
): Promise<DataView> => {
  if (!Number.isSafeInteger(startRva) || startRva < 0 ||
      !Number.isSafeInteger(byteLength)) return new DataView(new ArrayBuffer(0));
  const chunks = collectMappedPrefixChunks(startRva, byteLength, reader.size, rvaToOff);
  const views: DataView[] = [];
  for (const chunk of chunks) {
    const view = await reader.read(chunk[0], chunk[1]);
    views.push(view);
    if (view.byteLength < chunk[1]) break;
  }
  const bytes = new Uint8Array(views.reduce((sum, view) => sum + view.byteLength, 0));
  let destination = 0;
  for (const view of views) {
    bytes.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), destination);
    destination += view.byteLength;
  }
  return new DataView(bytes.buffer);
};
