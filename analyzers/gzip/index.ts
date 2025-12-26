"use strict";

import type {
  GzipExtraFieldSummary,
  GzipHeader,
  GzipHeaderFlags,
  GzipParseResult,
  GzipStreamLayout,
  GzipTrailer
} from "./types.js";

const BASE_HEADER_SIZE = 10;
const TRAILER_SIZE = 8;
const MAX_ISSUES = 200;
const MAX_HEADER_SCAN_BYTES = 1024 * 1024;

const describeCompressionMethod = (method: number): string | null => {
  if (method === 8) return "Deflate";
  return null;
};

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

const describeOs = (os: number): string | null => OS_NAMES[os] || null;

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

export const parseGzip = async (file: File): Promise<GzipParseResult | null> => {
  const issues: string[] = [];
  const pushIssue = (message: string): void => {
    if (issues.length >= MAX_ISSUES) return;
    issues.push(message);
  };

  const firstBytes = new Uint8Array(await file.slice(0, Math.min(file.size, BASE_HEADER_SIZE)).arrayBuffer());
  if (firstBytes.length < 2) return null;
  if (firstBytes[0] !== 0x1f || firstBytes[1] !== 0x8b) return null;

  let headerBytes = firstBytes;
  const ensureHeaderBytes = async (required: number): Promise<boolean> => {
    if (required > MAX_HEADER_SCAN_BYTES) return false;
    if (required <= headerBytes.length) return true;
    const end = Math.min(file.size, required);
    headerBytes = new Uint8Array(await file.slice(0, end).arrayBuffer());
    return headerBytes.length >= required;
  };

  const compressionMethod = firstBytes.length >= 3 ? firstBytes[2] ?? null : null;
  const flagsByte = firstBytes.length >= 4 ? firstBytes[3] ?? null : null;
  const flags: GzipHeaderFlags = {
    ftext: flagsByte != null ? (flagsByte & 0x01) !== 0 : false,
    fhcrc: flagsByte != null ? (flagsByte & 0x02) !== 0 : false,
    fextra: flagsByte != null ? (flagsByte & 0x04) !== 0 : false,
    fname: flagsByte != null ? (flagsByte & 0x08) !== 0 : false,
    fcomment: flagsByte != null ? (flagsByte & 0x10) !== 0 : false,
    reservedBits: flagsByte != null ? flagsByte & 0xe0 : 0
  };

  const mtime = firstBytes.length >= 8 ? readUint32le(firstBytes, 4) : null;
  const extraFlags = firstBytes.length >= 9 ? (firstBytes[8] ?? null) : null;
  const os = firstBytes.length >= 10 ? (firstBytes[9] ?? null) : null;

  const header: GzipHeader = {
    compressionMethod,
    compressionMethodName: compressionMethod != null ? describeCompressionMethod(compressionMethod) : null,
    flags,
    mtime,
    extraFlags,
    os,
    osName: os != null ? describeOs(os) || `OS ${os}` : null,
    extra: null,
    fileName: null,
    comment: null,
    headerCrc16: null,
    headerBytesTotal: null,
    truncated: false
  };

  const trailer: GzipTrailer = {
    crc32: null,
    isize: null,
    truncated: false
  };

  const stream: GzipStreamLayout = {
    compressedOffset: null,
    compressedSize: null,
    trailerOffset: null,
    truncatedFile: false
  };

  if (compressionMethod != null && compressionMethod !== 8) {
    pushIssue(`Unsupported gzip compression method ${compressionMethod} (expected 8/Deflate).`);
  }
  if (flags.reservedBits !== 0) {
    pushIssue(`Gzip header has reserved flag bits set: 0x${flags.reservedBits.toString(16)}.`);
  }

  if (firstBytes.length < BASE_HEADER_SIZE) {
    header.truncated = true;
    trailer.truncated = true;
    stream.truncatedFile = true;
    pushIssue(`Gzip base header is truncated (${firstBytes.length}/${BASE_HEADER_SIZE} bytes).`);
    return { isGzip: true, fileSize: file.size, header, trailer, stream, issues };
  }

  let cursor = BASE_HEADER_SIZE;
  let headerParseFailed = false;

  const readNullTerminatedField = async (
    fieldLabel: string,
    startOffset: number
  ): Promise<{ value: string; endOffset: number; truncated: boolean } | null> => {
    let scanOffset = startOffset;
    while (true) {
      const zeroIndex = headerBytes.indexOf(0, scanOffset);
      if (zeroIndex !== -1) {
        const valueBytes = headerBytes.subarray(startOffset, zeroIndex);
        return { value: decodeLatin1(valueBytes), endOffset: zeroIndex + 1, truncated: false };
      }

      if (headerBytes.length >= file.size) {
        return {
          value: decodeLatin1(headerBytes.subarray(startOffset)),
          endOffset: headerBytes.length,
          truncated: true
        };
      }

      if (headerBytes.length >= MAX_HEADER_SCAN_BYTES) {
        pushIssue(`${fieldLabel} is not NUL-terminated within ${MAX_HEADER_SCAN_BYTES} bytes; stopping header parsing.`);
        return null;
      }

      const prevLength = headerBytes.length;
      const nextEnd = Math.min(
        file.size,
        Math.min(MAX_HEADER_SCAN_BYTES, Math.max(headerBytes.length * 2, scanOffset + 1))
      );
      const grew = await ensureHeaderBytes(nextEnd);
      if (!grew) {
        pushIssue(`${fieldLabel} is too large to scan safely; stopping header parsing.`);
        return null;
      }
      scanOffset = prevLength;
    }
  };

  if (flags.fextra) {
    const hasExtraLength = await ensureHeaderBytes(cursor + 2);
    if (!hasExtraLength) {
      headerParseFailed = true;
      pushIssue("Extra field length (XLEN) is missing.");
    } else {
      const xlen = readUint16le(headerBytes, cursor);
      if (xlen == null) {
        headerParseFailed = true;
        pushIssue("Extra field length (XLEN) is missing.");
      } else {
        cursor += 2;
        const extraEnd = cursor + xlen;
        const hasExtraData = await ensureHeaderBytes(extraEnd);
        const available = Math.max(0, Math.min(headerBytes.length, extraEnd) - cursor);
        const truncated = !hasExtraData || available < xlen;
        const summary: GzipExtraFieldSummary = { xlen, dataLength: available, truncated };
        header.extra = summary;
        cursor += available;
        if (truncated) {
          headerParseFailed = true;
          pushIssue(`Extra field is truncated (${available}/${xlen} bytes).`);
        }
      }
    }
  }

  if (!headerParseFailed && flags.fname) {
    const res = await readNullTerminatedField("Original filename", cursor);
    if (!res) {
      headerParseFailed = true;
    } else {
      header.fileName = res.value;
      cursor = res.endOffset;
      if (res.truncated) {
        headerParseFailed = true;
        pushIssue("Original filename is not NUL-terminated (truncated).");
      }
    }
  }

  if (!headerParseFailed && flags.fcomment) {
    const res = await readNullTerminatedField("Comment", cursor);
    if (!res) {
      headerParseFailed = true;
    } else {
      header.comment = res.value;
      cursor = res.endOffset;
      if (res.truncated) {
        headerParseFailed = true;
        pushIssue("Comment is not NUL-terminated (truncated).");
      }
    }
  }

  if (!headerParseFailed && flags.fhcrc) {
    const hasCrc = await ensureHeaderBytes(cursor + 2);
    if (!hasCrc) {
      headerParseFailed = true;
      pushIssue("Header CRC16 (FHCRC) flag is set but bytes are missing.");
    } else {
      const crc16 = readUint16le(headerBytes, cursor);
      cursor += 2;
      if (crc16 == null) {
        headerParseFailed = true;
        pushIssue("Header CRC16 (FHCRC) flag is set but bytes are missing.");
      } else {
        header.headerCrc16 = crc16;
      }
    }
  }

  if (headerParseFailed) {
    header.truncated = true;
    stream.truncatedFile = true;
  } else {
    header.headerBytesTotal = cursor;
  }

  if (file.size < TRAILER_SIZE) {
    trailer.truncated = true;
    stream.truncatedFile = true;
    pushIssue(`Gzip trailer is truncated (${file.size}/${TRAILER_SIZE} bytes).`);
  } else {
    const trailerOffset = file.size - TRAILER_SIZE;
    stream.trailerOffset = trailerOffset;
    const trailerBytes = new Uint8Array(await file.slice(trailerOffset).arrayBuffer());
    const crc32 = readUint32le(trailerBytes, 0);
    const isize = readUint32le(trailerBytes, 4);
    if (crc32 == null || isize == null) {
      trailer.truncated = true;
      stream.truncatedFile = true;
      pushIssue("Gzip trailer is truncated.");
    } else {
      trailer.crc32 = crc32;
      trailer.isize = isize;
    }
  }

  if (header.headerBytesTotal != null && stream.trailerOffset != null && stream.trailerOffset >= header.headerBytesTotal) {
    stream.compressedOffset = header.headerBytesTotal;
    stream.compressedSize = stream.trailerOffset - header.headerBytesTotal;
  } else if (header.headerBytesTotal != null && file.size >= header.headerBytesTotal + TRAILER_SIZE) {
    stream.compressedOffset = header.headerBytesTotal;
    stream.compressedSize = file.size - header.headerBytesTotal - TRAILER_SIZE;
  } else if (header.headerBytesTotal != null) {
    stream.truncatedFile = true;
    trailer.truncated = true;
    pushIssue("File is too small to contain both a gzip header and trailer.");
  }

  if (stream.compressedSize != null && stream.compressedSize < 0) {
    stream.truncatedFile = true;
    pushIssue("Computed compressed stream size is negative (corrupt layout).");
    stream.compressedSize = null;
  }

  return { isGzip: true, fileSize: file.size, header, trailer, stream, issues };
};
