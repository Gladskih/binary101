"use strict";

import type { PeClrMeta, PeClrStreamInfo } from "./clr-types.js";

export const CLR_METADATA_ROOT_MIN_BYTES = 0x20;

const CLR_STREAM_NAME_LIMIT_BYTES = 64;
const CLR_METADATA_SIGNATURE_BSJB = 0x424a5342;
const ASCII_PRINTABLE_MIN = 0x20;
const ASCII_PRINTABLE_MAX = 0x7e;
const MAX_METADATA_STREAMS = 2048;

interface Cursor {
  offset: number;
}

interface MetadataReader {
  readAt: (relativeOffset: number, byteLength: number) => Promise<DataView | null>;
}

const alignTo4 = (value: number): number => (value + 3) & ~3;

const toHex = (value: number, width: number): string =>
  "0x" + value.toString(16).padStart(width, "0");

const decodePrintableAscii = (bytes: Uint8Array): string => {
  let result = "";
  for (const byteValue of bytes) {
    if (byteValue === 0) break;
    if (byteValue >= ASCII_PRINTABLE_MIN && byteValue <= ASCII_PRINTABLE_MAX) {
      result += String.fromCharCode(byteValue);
    }
  }
  return result.trim();
};


const readU16At = async (
  reader: MetadataReader,
  cursor: Cursor
): Promise<number | null> => {
  const view = await reader.readAt(cursor.offset, 2);
  if (!view) return null;
  cursor.offset += 2;
  return view.getUint16(0, true);
};

const readU32At = async (
  reader: MetadataReader,
  cursor: Cursor
): Promise<number | null> => {
  const view = await reader.readAt(cursor.offset, 4);
  if (!view) return null;
  cursor.offset += 4;
  return view.getUint32(0, true);
};

const readBytesAt = async (
  reader: MetadataReader,
  cursor: Cursor,
  byteLength: number
): Promise<Uint8Array | null> => {
  const view = await reader.readAt(cursor.offset, byteLength);
  if (!view) return null;
  cursor.offset += byteLength;
  return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
};

const readStreamNameAt = async (
  reader: MetadataReader,
  cursor: Cursor,
  declaredMetaSize: number
): Promise<string | null> => {
  if (cursor.offset >= declaredMetaSize) return null;
  let name = "";
  const remainingBytes = declaredMetaSize - cursor.offset;
  const limit = Math.min(remainingBytes, CLR_STREAM_NAME_LIMIT_BYTES);
  for (let index = 0; index < limit; index += 1) {
    const byteView = await reader.readAt(cursor.offset, 1);
    if (!byteView) return null;
    cursor.offset += 1;
    const byteValue = byteView.getUint8(0);
    if (byteValue === 0) break;
    name += String.fromCharCode(byteValue);
  }
  cursor.offset = alignTo4(cursor.offset);
  return name;
};

const parseMetadataRootWithReader = async (
  reader: MetadataReader,
  declaredMetaSize: number,
  issues: string[]
): Promise<PeClrMeta | null> => {
  const cursor: Cursor = { offset: 0 };
  const signature = await readU32At(reader, cursor);
  if (signature == null) {
    issues.push("Metadata root is truncated; missing signature.");
    return null;
  }
  if (signature !== CLR_METADATA_SIGNATURE_BSJB) {
    issues.push(
      `Metadata root signature ${toHex(signature, 8)} is unexpected; expected ` +
        `${toHex(CLR_METADATA_SIGNATURE_BSJB, 8)} ("BSJB").`
    );
    return null;
  }
  const verMajor = await readU16At(reader, cursor);
  const verMinor = await readU16At(reader, cursor);
  const reserved = await readU32At(reader, cursor);
  const versionLength = await readU32At(reader, cursor);
  if (
    verMajor == null ||
    verMinor == null ||
    reserved == null ||
    versionLength == null
  ) {
    issues.push("Metadata root is truncated; missing required header fields.");
    return null;
  }
  if (versionLength > declaredMetaSize - cursor.offset) {
    issues.push("Metadata root version string is truncated or out of bounds.");
    return null;
  }
  let version = "";
  if (versionLength > 0) {
    const versionBytes = await readBytesAt(reader, cursor, versionLength);
    if (!versionBytes) {
      issues.push("Metadata root version string is truncated or out of bounds.");
      return null;
    }
    version = decodePrintableAscii(versionBytes);
    cursor.offset = alignTo4(cursor.offset);
  }
  const flags = await readU16At(reader, cursor);
  const streamCountRaw = await readU16At(reader, cursor);
  if (flags == null || streamCountRaw == null) {
    issues.push("Metadata root is truncated; missing stream header fields.");
    return null;
  }
  if (streamCountRaw > MAX_METADATA_STREAMS) {
    issues.push(
      `Metadata stream count (${streamCountRaw}) is very large; parsing capped at ` +
        `${MAX_METADATA_STREAMS} streams.`
    );
  }
  const streams: PeClrStreamInfo[] = [];
  for (
    let streamIndex = 0;
    streamIndex < Math.min(streamCountRaw, MAX_METADATA_STREAMS);
    streamIndex += 1
  ) {
    const offset = await readU32At(reader, cursor);
    const size = await readU32At(reader, cursor);
    if (offset == null || size == null) {
      issues.push("Metadata stream headers are truncated; some stream entries are missing.");
      break;
    }
    const name = await readStreamNameAt(reader, cursor, declaredMetaSize);
    if (name == null) {
      issues.push("Metadata stream headers are truncated; some stream names are missing.");
      break;
    }
    if (declaredMetaSize > 0 && offset + size > declaredMetaSize) {
      issues.push(
        `Metadata stream "${name}" extends past declared metadata size ` +
          `(${toHex(offset + size, 8)} > ${toHex(declaredMetaSize, 8)}).`
      );
    }
    streams.push({ name, offset, size });
  }
  if (streams.length < streamCountRaw) {
    issues.push("Metadata stream list is incomplete; fewer streams were parsed than declared.");
  }
  return {
    version,
    verMajor,
    verMinor,
    reserved,
    flags,
    streamCount: streamCountRaw,
    signature,
    streams
  };
};

export const parseClrMetadataRoot = async (
  file: File,
  metaOffset: number,
  metaSize: number,
  issues: string[]
): Promise<PeClrMeta | null> => {
  if (metaOffset < 0 || metaOffset >= file.size) {
    issues.push("Metadata root location is outside the file.");
    return null;
  }
  const availableSize = Math.min(metaSize, Math.max(0, file.size - metaOffset));
  if (availableSize < metaSize) {
    issues.push("Metadata directory is truncated; some bytes are missing from the end of the region.");
  }
  if (availableSize < CLR_METADATA_ROOT_MIN_BYTES) {
    issues.push("Metadata root is smaller than the minimum size (0x20 bytes); header is truncated.");
    return null;
  }

  const reader: MetadataReader = {
    readAt: async (relativeOffset, byteLength) => {
      if (relativeOffset < 0 || byteLength < 0) return null;
      if (relativeOffset + byteLength > availableSize) return null;
      const slice = await file
        .slice(metaOffset + relativeOffset, metaOffset + relativeOffset + byteLength)
        .arrayBuffer();
      return new DataView(slice);
    }
  };

  try {
    return await parseMetadataRootWithReader(reader, metaSize, issues);
  } catch {
    issues.push("Metadata root could not be read.");
    return null;
  }
};
