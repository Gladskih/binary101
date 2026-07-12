"use strict";

import { finishCrc32, updateCrc32, crc32 } from "../crc32.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { parseRar } from "../rar/index.js";
import { readVint, toSafeNumber } from "../rar/utils.js";
import {
  SEVENZIP_NEXT_HEADER_CRC_OFFSET,
  SEVENZIP_NEXT_HEADER_OFFSET_OFFSET,
  SEVENZIP_NEXT_HEADER_SIZE_OFFSET,
  SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER
} from "../sevenz/layout.js";
import type { FileRange } from "./layout/file-ranges.js";
import { readEmbeddedSevenZipFileSize } from "./overlay-embedded.js";

const CRC_CHUNK_BYTES = 64 * 1024;

const createRangeFile = (file: File, range: FileRange): File => {
  const blob = file.slice(range.start, range.end, "application/octet-stream");
  if (typeof File === "function") return new File([blob], file.name);
  return Object.assign(blob, {
    name: file.name,
    lastModified: file.lastModified,
    webkitRelativePath: ""
  }) as File;
};

const readRangeCrc32 = async (
  reader: FileRangeReader,
  start: number,
  size: number
): Promise<number | null> => {
  let state = 0xffffffff;
  for (let cursor = start; cursor < start + size;) {
    const chunkSize = Math.min(CRC_CHUNK_BYTES, start + size - cursor);
    const chunk = await reader.read(cursor, chunkSize);
    if (chunk.byteLength !== chunkSize) return null;
    state = updateCrc32(state, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    cursor += chunkSize;
  }
  return finishCrc32(state);
};

export const readEmbeddedSevenZipEnd = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number
): Promise<number | null> => {
  const view = await reader.read(
    start,
    Math.min(SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER, range.end - start)
  );
  const archiveSize = readEmbeddedSevenZipFileSize(view, range.end - start);
  if (archiveSize == null) return null;
  const nextHeaderOffset = Number(view.getBigUint64(SEVENZIP_NEXT_HEADER_OFFSET_OFFSET, true));
  const nextHeaderSize = Number(view.getBigUint64(SEVENZIP_NEXT_HEADER_SIZE_OFFSET, true));
  if (!Number.isSafeInteger(nextHeaderOffset) || !Number.isSafeInteger(nextHeaderSize)) return null;
  const nextHeaderStart = start + SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER + nextHeaderOffset;
  const actualCrc = await readRangeCrc32(reader, nextHeaderStart, nextHeaderSize);
  return actualCrc === view.getUint32(SEVENZIP_NEXT_HEADER_CRC_OFFSET, true)
    ? start + archiveSize
    : null;
};

const readRar5End = async (
  reader: FileRangeReader,
  range: FileRange,
  start: number
): Promise<number | null> => {
  // RAR5 header envelopes begin with CRC32 plus small vints; the parser uses the same bounded probe.
  const probe = await reader.read(start, Math.min(32, range.end - start));
  const sizeInfo = readVint(probe, Uint32Array.BYTES_PER_ELEMENT);
  const headerSize = toSafeNumber(sizeInfo.value);
  if (headerSize == null) return null;
  const totalSize = Uint32Array.BYTES_PER_ELEMENT + sizeInfo.length + headerSize;
  if (totalSize > range.end - start) return null;
  const header = await reader.read(start, totalSize);
  const bytes = new Uint8Array(header.buffer, header.byteOffset + 4, totalSize - 4);
  return crc32(bytes) === header.getUint32(0, true) ? start + totalSize : null;
};

export const readEmbeddedRarEnd = async (
  file: File,
  reader: FileRangeReader,
  range: FileRange,
  start: number
): Promise<number | null> => {
  const rar = await parseRar(createRangeFile(file, { start, end: range.end }));
  if (!rar.isRar || !rar.mainHeader || !rar.endHeader) return null;
  const endHeaderStart = start + rar.endHeader.offset;
  if (rar.version === 5) return readRar5End(reader, range, endHeaderStart);
  const header = await reader.read(endHeaderStart, Math.min(7, range.end - endHeaderStart));
  if (header.byteLength < 7) return null;
  const headerSize = header.getUint16(5, true);
  return headerSize >= 7 && headerSize <= range.end - endHeaderStart
    ? endHeaderStart + headerSize
    : null;
};
