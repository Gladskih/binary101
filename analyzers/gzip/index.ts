"use strict";
import type { GzipParseResult, GzipStreamLayout, GzipTrailer } from "./types.js";
import {
  type GzipHeaderScanState,
  createGzipHeader,
  parseGzipOptionalHeader,
  pushGzipIssue,
  readGzipUint32le
} from "./header-scan.js";
import {
  GZIP_BASE_HEADER_BYTES,
  GZIP_DEFLATE_COMPRESSION_METHOD,
  GZIP_ID1,
  GZIP_ID2
} from "./signature.js";

const TRAILER_SIZE = 8;

const readGzipTrailer = async (
  file: Blob,
  trailer: GzipTrailer,
  stream: GzipStreamLayout,
  issues: string[]
): Promise<void> => {
  if (file.size < TRAILER_SIZE) {
    trailer.truncated = true;
    stream.truncatedFile = true;
    pushGzipIssue(issues, `Gzip trailer is truncated (${file.size}/${TRAILER_SIZE} bytes).`);
    return;
  }
  const trailerOffset = file.size - TRAILER_SIZE;
  stream.trailerOffset = trailerOffset;
  const trailerBytes = new Uint8Array(await file.slice(trailerOffset).arrayBuffer());
  const crc32 = readGzipUint32le(trailerBytes, 0);
  const isize = readGzipUint32le(trailerBytes, 4);
  if (crc32 == null || isize == null) {
    trailer.truncated = true;
    stream.truncatedFile = true;
    pushGzipIssue(issues, "Gzip trailer is truncated.");
  } else {
    trailer.crc32 = crc32;
    trailer.isize = isize;
  }
};

const finalizeGzipLayout = (
  file: Blob,
  headerBytesTotal: number | null,
  trailer: GzipTrailer,
  stream: GzipStreamLayout,
  issues: string[]
): void => {
  if (
    headerBytesTotal != null &&
    stream.trailerOffset != null &&
    stream.trailerOffset >= headerBytesTotal
  ) {
    stream.compressedOffset = headerBytesTotal;
    stream.compressedSize = stream.trailerOffset - headerBytesTotal;
  } else if (headerBytesTotal != null && file.size >= headerBytesTotal + TRAILER_SIZE) {
    stream.compressedOffset = headerBytesTotal;
    stream.compressedSize = file.size - headerBytesTotal - TRAILER_SIZE;
  } else if (headerBytesTotal != null) {
    stream.truncatedFile = true;
    trailer.truncated = true;
    pushGzipIssue(issues, "File is too small to contain both a gzip header and trailer.");
  }
  if (stream.compressedSize != null && stream.compressedSize < 0) {
    stream.truncatedFile = true;
    pushGzipIssue(issues, "Computed compressed stream size is negative (corrupt layout).");
    stream.compressedSize = null;
  }
};

export const parseGzip = async (file: Blob): Promise<GzipParseResult | null> => {
  const issues: string[] = [];
  const firstBytes = new Uint8Array(
    await file.slice(0, Math.min(file.size, GZIP_BASE_HEADER_BYTES)).arrayBuffer()
  );
  if (firstBytes.length < 2) return null;
  if (firstBytes[0] !== GZIP_ID1 || firstBytes[1] !== GZIP_ID2) return null;
  const state: GzipHeaderScanState = { file, headerBytes: firstBytes, issues };
  const header = createGzipHeader(firstBytes);
  const trailer: GzipTrailer = { crc32: null, isize: null, truncated: false };
  const stream: GzipStreamLayout = {
    compressedOffset: null,
    compressedSize: null,
    trailerOffset: null,
    truncatedFile: false
  };
  if (header.compressionMethod != null && header.compressionMethod !== GZIP_DEFLATE_COMPRESSION_METHOD) {
    pushGzipIssue(
      issues,
      `Unsupported gzip compression method ${header.compressionMethod} ` +
        `(expected ${GZIP_DEFLATE_COMPRESSION_METHOD}/Deflate).`
    );
  }
  if (header.flags.reservedBits !== 0) {
    pushGzipIssue(issues, `Gzip header has reserved flag bits set: 0x${header.flags.reservedBits.toString(16)}.`);
  }
  if (firstBytes.length < GZIP_BASE_HEADER_BYTES) {
    header.truncated = true;
    trailer.truncated = true;
    stream.truncatedFile = true;
    pushGzipIssue(
      issues,
      `Gzip base header is truncated (${firstBytes.length}/${GZIP_BASE_HEADER_BYTES} bytes).`
    );
    return { isGzip: true, fileSize: file.size, header, trailer, stream, issues };
  }
  await parseGzipOptionalHeader(state, header);
  if (header.truncated) stream.truncatedFile = true;
  await readGzipTrailer(file, trailer, stream, issues);
  finalizeGzipLayout(file, header.headerBytesTotal, trailer, stream, issues);
  return { isGzip: true, fileSize: file.size, header, trailer, stream, issues };
};
