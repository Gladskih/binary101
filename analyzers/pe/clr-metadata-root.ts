"use strict";

import type { PeClrMeta, PeClrStreamInfo } from "./clr-types.js";

export const CLR_METADATA_ROOT_MIN_BYTES = 0x20;

const CLR_METADATA_MAX_READ_BYTES = 0x4000;
const CLR_STREAM_NAME_LIMIT_BYTES = 64;
const CLR_METADATA_SIGNATURE_BSJB = 0x424a5342;
const ASCII_PRINTABLE_MIN = 0x20;
const ASCII_PRINTABLE_MAX = 0x7e;
const MAX_METADATA_STREAMS = 2048;

interface Cursor {
  offset: number;
}

const hasBytes = (view: DataView, offset: number, byteLength: number): boolean =>
  view.byteLength >= offset + byteLength;

const readU16LE = (view: DataView, cursor: Cursor): number | null => {
  if (!hasBytes(view, cursor.offset, 2)) return null;
  const value = view.getUint16(cursor.offset, true);
  cursor.offset += 2;
  return value;
};

const readU32LE = (view: DataView, cursor: Cursor): number | null => {
  if (!hasBytes(view, cursor.offset, 4)) return null;
  const value = view.getUint32(cursor.offset, true);
  cursor.offset += 4;
  return value;
};

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

const readStreamName = (view: DataView, cursor: Cursor): string | null => {
  if (cursor.offset >= view.byteLength) return null;
  let name = "";
  const limit = Math.min(view.byteLength - cursor.offset, CLR_STREAM_NAME_LIMIT_BYTES);
  for (let index = 0; index < limit; index += 1) {
    const byteValue = view.getUint8(cursor.offset);
    cursor.offset += 1;
    if (byteValue === 0) break;
    name += String.fromCharCode(byteValue);
  }
  cursor.offset = alignTo4(cursor.offset);
  return name;
};

const parseMetadataRootFromView = (
  view: DataView,
  declaredMetaSize: number,
  issues: string[]
): PeClrMeta | null => {
  const cursor: Cursor = { offset: 0 };
  const signature = readU32LE(view, cursor);
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
  const verMajor = readU16LE(view, cursor);
  const verMinor = readU16LE(view, cursor);
  const reserved = readU32LE(view, cursor);
  const versionLength = readU32LE(view, cursor);
  if (
    verMajor == null ||
    verMinor == null ||
    reserved == null ||
    versionLength == null
  ) {
    issues.push("Metadata root is truncated; missing required header fields.");
    return null;
  }
  if (versionLength > view.byteLength - cursor.offset) {
    issues.push("Metadata root version string is truncated or out of bounds.");
    return null;
  }
  let version = "";
  if (versionLength > 0) {
    version = decodePrintableAscii(
      new Uint8Array(view.buffer, view.byteOffset + cursor.offset, versionLength)
    );
    cursor.offset = alignTo4(cursor.offset + versionLength);
  }
  const flags = readU16LE(view, cursor);
  const streamCountRaw = readU16LE(view, cursor);
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
  for (let streamIndex = 0; streamIndex < Math.min(streamCountRaw, MAX_METADATA_STREAMS); streamIndex += 1) {
    const offset = readU32LE(view, cursor);
    const size = readU32LE(view, cursor);
    if (offset == null || size == null) {
      issues.push("Metadata stream headers are truncated; some stream entries are missing.");
      break;
    }
    const name = readStreamName(view, cursor);
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
  try {
    return parseMetadataRootFromView(
      new DataView(
        await file
          .slice(
            metaOffset,
            metaOffset + Math.min(availableSize, CLR_METADATA_MAX_READ_BYTES)
          )
          .arrayBuffer()
      ),
      metaSize,
      issues
    );
  } catch {
    issues.push("Metadata root could not be read.");
    return null;
  }
};

