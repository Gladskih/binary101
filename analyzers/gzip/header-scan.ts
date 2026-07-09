"use strict";
import type { GzipHeader, GzipHeaderFlags } from "./types.js";
import {
  GZIP_BASE_HEADER_BYTES,
  GZIP_DEFLATE_COMPRESSION_METHOD,
  GZIP_FLAG_FCOMMENT,
  GZIP_FLAG_FEXTRA,
  GZIP_FLAG_FHCRC,
  GZIP_FLAG_FNAME,
  GZIP_FLAG_FTEXT,
  GZIP_RESERVED_FLAGS_MASK
} from "./signature.js";

const MAX_ISSUES = 200;
const MAX_HEADER_SCAN_BYTES = 1024 * 1024;
const OS_NAMES: Record<number, string> = {
  0: "FAT filesystem (MS-DOS, OS/2, NT/Win32)",
  1: "Amiga",
  2: "VMS",
  3: "Unix",
  4: "VM/CMS",
  5: "Atari TOS",
  6: "HPFS filesystem (OS/2, NT)",
  7: "Macintosh",
  8: "Z-System",
  9: "CP/M",
  10: "TOPS-20",
  11: "NTFS filesystem (NT)",
  12: "QDOS",
  13: "Acorn RISCOS",
  255: "Unknown"
};

export type GzipHeaderScanState = { file: Blob; headerBytes: Uint8Array; issues: string[] };

const describeCompressionMethod = (method: number): string | null =>
  method === GZIP_DEFLATE_COMPRESSION_METHOD ? "Deflate" : null;
const describeOs = (os: number): string | null => OS_NAMES[os] || null;

export const pushGzipIssue = (issues: string[], message: string): void => {
  if (issues.length >= MAX_ISSUES) return;
  issues.push(message);
};

const readUint16le = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 2 > bytes.length) return null;
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
};

const readUint32le = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 4 > bytes.length) return null;
  return (
    (bytes[offset] ?? 0) |
    ((bytes[offset + 1] ?? 0) << 8) |
    ((bytes[offset + 2] ?? 0) << 16) |
    ((bytes[offset + 3] ?? 0) << 24)
  ) >>> 0;
};

const decodeLatin1 = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
};

const ensureHeaderBytes = async (
  state: GzipHeaderScanState,
  required: number
): Promise<boolean> => {
  if (required > MAX_HEADER_SCAN_BYTES) return false;
  if (required <= state.headerBytes.length) return true;
  state.headerBytes = new Uint8Array(
    await state.file.slice(0, Math.min(state.file.size, required)).arrayBuffer()
  );
  return state.headerBytes.length >= required;
};

const readNullTerminatedField = async (
  state: GzipHeaderScanState,
  fieldLabel: string,
  startOffset: number
): Promise<{ value: string; endOffset: number; truncated: boolean } | null> => {
  let scanOffset = startOffset;
  while (true) {
    const zeroIndex = state.headerBytes.indexOf(0, scanOffset);
    if (zeroIndex !== -1) {
      return {
        value: decodeLatin1(state.headerBytes.subarray(startOffset, zeroIndex)),
        endOffset: zeroIndex + 1,
        truncated: false
      };
    }
    if (state.headerBytes.length >= state.file.size) {
      return {
        value: decodeLatin1(state.headerBytes.subarray(startOffset)),
        endOffset: state.headerBytes.length,
        truncated: true
      };
    }
    if (state.headerBytes.length >= MAX_HEADER_SCAN_BYTES) {
      pushGzipIssue(state.issues, `${fieldLabel} is not NUL-terminated within ${MAX_HEADER_SCAN_BYTES} bytes; stopping header parsing.`);
      return null;
    }
    const prevLength = state.headerBytes.length;
    const nextEnd = Math.min(
      state.file.size,
      Math.min(MAX_HEADER_SCAN_BYTES, Math.max(state.headerBytes.length * 2, scanOffset + 1))
    );
    if (!(await ensureHeaderBytes(state, nextEnd))) {
      pushGzipIssue(state.issues, `${fieldLabel} is too large to scan safely; stopping header parsing.`);
      return null;
    }
    scanOffset = prevLength;
  }
};

export const readGzipUint32le = readUint32le;

export const createGzipHeader = (firstBytes: Uint8Array): GzipHeader => {
  const compressionMethod = firstBytes.length >= 3 ? firstBytes[2] ?? null : null;
  const flagsByte = firstBytes.length >= 4 ? firstBytes[3] ?? null : null;
  const flags: GzipHeaderFlags = {
    ftext: flagsByte != null ? (flagsByte & GZIP_FLAG_FTEXT) !== 0 : false,
    fhcrc: flagsByte != null ? (flagsByte & GZIP_FLAG_FHCRC) !== 0 : false,
    fextra: flagsByte != null ? (flagsByte & GZIP_FLAG_FEXTRA) !== 0 : false,
    fname: flagsByte != null ? (flagsByte & GZIP_FLAG_FNAME) !== 0 : false,
    fcomment: flagsByte != null ? (flagsByte & GZIP_FLAG_FCOMMENT) !== 0 : false,
    reservedBits: flagsByte != null ? flagsByte & GZIP_RESERVED_FLAGS_MASK : 0
  };
  const os = firstBytes.length >= 10 ? (firstBytes[9] ?? null) : null;
  return {
    compressionMethod,
    compressionMethodName: compressionMethod != null ? describeCompressionMethod(compressionMethod) : null,
    flags,
    mtime: firstBytes.length >= 8 ? readUint32le(firstBytes, 4) : null,
    extraFlags: firstBytes.length >= 9 ? (firstBytes[8] ?? null) : null,
    os,
    osName: os != null ? describeOs(os) || `OS ${os}` : null,
    extra: null,
    fileName: null,
    comment: null,
    headerCrc16: null,
    headerBytesTotal: null,
    truncated: false
  };
};

export const parseGzipOptionalHeader = async (
  state: GzipHeaderScanState,
  header: GzipHeader
): Promise<void> => {
  let cursor = GZIP_BASE_HEADER_BYTES;
  let headerParseFailed = false;
  if (header.flags.fextra) {
    headerParseFailed = await parseExtraField(state, header, cursor);
    cursor = header.extra ? cursor + 2 + header.extra.dataLength : cursor;
  }
  if (!headerParseFailed && header.flags.fname) {
    const res = await readNullTerminatedField(state, "Original filename", cursor);
    headerParseFailed = !res;
    if (res) {
      header.fileName = res.value;
      cursor = res.endOffset;
      if (res.truncated) {
        headerParseFailed = true;
        pushGzipIssue(state.issues, "Original filename is not NUL-terminated (truncated).");
      }
    }
  }
  if (!headerParseFailed && header.flags.fcomment) {
    const res = await readNullTerminatedField(state, "Comment", cursor);
    headerParseFailed = !res;
    if (res) {
      header.comment = res.value;
      cursor = res.endOffset;
      if (res.truncated) {
        headerParseFailed = true;
        pushGzipIssue(state.issues, "Comment is not NUL-terminated (truncated).");
      }
    }
  }
  if (!headerParseFailed && header.flags.fhcrc) headerParseFailed = await parseHeaderCrc(state, header, cursor);
  header.truncated = headerParseFailed;
  if (!headerParseFailed) header.headerBytesTotal = header.flags.fhcrc ? cursor + 2 : cursor;
};

const parseExtraField = async (
  state: GzipHeaderScanState,
  header: GzipHeader,
  cursor: number
): Promise<boolean> => {
  if (!(await ensureHeaderBytes(state, cursor + 2))) {
    pushGzipIssue(state.issues, "Extra field length (XLEN) is missing.");
    return true;
  }
  const xlen = readUint16le(state.headerBytes, cursor);
  if (xlen == null) {
    pushGzipIssue(state.issues, "Extra field length (XLEN) is missing.");
    return true;
  }
  const extraStart = cursor + 2;
  const extraEnd = extraStart + xlen;
  const hasExtraData = await ensureHeaderBytes(state, extraEnd);
  const available = Math.max(0, Math.min(state.headerBytes.length, extraEnd) - extraStart);
  header.extra = { xlen, dataLength: available, truncated: !hasExtraData || available < xlen };
  if (!header.extra.truncated) return false;
  pushGzipIssue(state.issues, `Extra field is truncated (${available}/${xlen} bytes).`);
  return true;
};

const parseHeaderCrc = async (
  state: GzipHeaderScanState,
  header: GzipHeader,
  cursor: number
): Promise<boolean> => {
  if (!(await ensureHeaderBytes(state, cursor + 2))) {
    pushGzipIssue(state.issues, "Header CRC16 (FHCRC) flag is set but bytes are missing.");
    return true;
  }
  const crc16 = readUint16le(state.headerBytes, cursor);
  if (crc16 == null) {
    pushGzipIssue(state.issues, "Header CRC16 (FHCRC) flag is set but bytes are missing.");
    return true;
  }
  header.headerCrc16 = crc16;
  return false;
};
