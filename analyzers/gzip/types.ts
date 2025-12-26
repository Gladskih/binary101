"use strict";

export type GzipHeaderFlags = {
  ftext: boolean;
  fhcrc: boolean;
  fextra: boolean;
  fname: boolean;
  fcomment: boolean;
  reservedBits: number;
};

export type GzipExtraFieldSummary = {
  xlen: number;
  dataLength: number;
  truncated: boolean;
};

export type GzipHeader = {
  compressionMethod: number | null;
  compressionMethodName: string | null;
  flags: GzipHeaderFlags;
  mtime: number | null;
  extraFlags: number | null;
  os: number | null;
  osName: string | null;
  extra: GzipExtraFieldSummary | null;
  fileName: string | null;
  comment: string | null;
  headerCrc16: number | null;
  headerBytesTotal: number | null;
  truncated: boolean;
};

export type GzipTrailer = {
  crc32: number | null;
  isize: number | null;
  truncated: boolean;
};

export type GzipStreamLayout = {
  compressedOffset: number | null;
  compressedSize: number | null;
  trailerOffset: number | null;
  truncatedFile: boolean;
};

export type GzipParseResult = {
  isGzip: true;
  fileSize: number;
  header: GzipHeader;
  trailer: GzipTrailer;
  stream: GzipStreamLayout;
  issues: string[];
};

