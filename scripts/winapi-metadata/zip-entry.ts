"use strict";

import { inflateRawSync } from "node:zlib";

const ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const ZIP_STORED_METHOD = 0;
const ZIP_DEFLATE_METHOD = 8;
const ZIP_EOCD_MIN_BYTES = 22;
const ZIP_EOCD_MAX_COMMENT_BYTES = 0xffff;

interface ZipCentralDirectory {
  offset: number;
  size: number;
  entryCount: number;
}

interface ZipEntry {
  name: string;
  flags: number;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

const assertRange = (bytes: Uint8Array, offset: number, size: number, context: string): void => {
  if (offset < 0 || size < 0 || offset + size > bytes.byteLength) {
    throw new Error(`ZIP ${context} extends outside the package.`);
  }
};

const readU16 = (bytes: Uint8Array, offset: number, context: string): number => {
  assertRange(bytes, offset, Uint16Array.BYTES_PER_ELEMENT, context);
  return new DataView(bytes.buffer, bytes.byteOffset + offset, Uint16Array.BYTES_PER_ELEMENT)
    .getUint16(0, true);
};

const readU32 = (bytes: Uint8Array, offset: number, context: string): number => {
  assertRange(bytes, offset, Uint32Array.BYTES_PER_ELEMENT, context);
  return new DataView(bytes.buffer, bytes.byteOffset + offset, Uint32Array.BYTES_PER_ELEMENT)
    .getUint32(0, true);
};

const decodeEntryName = (bytes: Uint8Array, flags: number): string => {
  const encoding = (flags & 0x0800) !== 0 ? "utf-8" : "latin1";
  return new TextDecoder(encoding).decode(bytes);
};

const findEndOfCentralDirectory = (bytes: Uint8Array): ZipCentralDirectory => {
  const searchStart = Math.max(0, bytes.byteLength - ZIP_EOCD_MIN_BYTES - ZIP_EOCD_MAX_COMMENT_BYTES);
  for (let offset = bytes.byteLength - ZIP_EOCD_MIN_BYTES; offset >= searchStart; offset -= 1) {
    if (readU32(bytes, offset, "end-of-central-directory signature") !== ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
      continue;
    }
    const entryCount = readU16(bytes, offset + 10, "central-directory entry count");
    const size = readU32(bytes, offset + 12, "central-directory size");
    const directoryOffset = readU32(bytes, offset + 16, "central-directory offset");
    assertRange(bytes, directoryOffset, size, "central directory");
    return { offset: directoryOffset, size, entryCount };
  }
  throw new Error("ZIP end-of-central-directory record was not found.");
};

const readCentralDirectoryEntry = (bytes: Uint8Array, offset: number): { entry: ZipEntry; nextOffset: number } => {
  if (readU32(bytes, offset, "central-directory signature") !== ZIP_CENTRAL_DIRECTORY_SIGNATURE) {
    throw new Error("ZIP central-directory entry signature is unexpected.");
  }
  const flags = readU16(bytes, offset + 8, "central-directory flags");
  const method = readU16(bytes, offset + 10, "central-directory method");
  const compressedSize = readU32(bytes, offset + 20, "central-directory compressed size");
  const uncompressedSize = readU32(bytes, offset + 24, "central-directory uncompressed size");
  const nameLength = readU16(bytes, offset + 28, "central-directory name length");
  const extraLength = readU16(bytes, offset + 30, "central-directory extra length");
  const commentLength = readU16(bytes, offset + 32, "central-directory comment length");
  const localHeaderOffset = readU32(bytes, offset + 42, "local-header offset");
  const nameOffset = offset + 46;
  assertRange(bytes, nameOffset, nameLength, "central-directory name");
  return {
    entry: {
      name: decodeEntryName(bytes.subarray(nameOffset, nameOffset + nameLength), flags),
      flags,
      method,
      compressedSize,
      uncompressedSize,
      localHeaderOffset
    },
    nextOffset: nameOffset + nameLength + extraLength + commentLength
  };
};

const findCentralDirectoryEntry = (bytes: Uint8Array, entryName: string): ZipEntry => {
  const directory = findEndOfCentralDirectory(bytes);
  let offset = directory.offset;
  for (let index = 0; index < directory.entryCount; index += 1) {
    const parsed = readCentralDirectoryEntry(bytes, offset);
    if (parsed.entry.name === entryName) return parsed.entry;
    offset = parsed.nextOffset;
    if (offset > directory.offset + directory.size) break;
  }
  throw new Error(`ZIP entry "${entryName}" was not found.`);
};

export const listZipEntries = (bytes: Uint8Array): string[] => {
  const directory = findEndOfCentralDirectory(bytes);
  const names: string[] = [];
  let offset = directory.offset;
  for (let index = 0; index < directory.entryCount; index += 1) {
    const parsed = readCentralDirectoryEntry(bytes, offset);
    names.push(parsed.entry.name);
    offset = parsed.nextOffset;
    if (offset > directory.offset + directory.size) break;
  }
  return names;
};

const readCompressedEntryData = (bytes: Uint8Array, entry: ZipEntry): Uint8Array => {
  const offset = entry.localHeaderOffset;
  if (readU32(bytes, offset, "local-file-header signature") !== ZIP_LOCAL_FILE_HEADER_SIGNATURE) {
    throw new Error(`ZIP local header for "${entry.name}" has an unexpected signature.`);
  }
  const nameLength = readU16(bytes, offset + 26, "local-file-header name length");
  const extraLength = readU16(bytes, offset + 28, "local-file-header extra length");
  const dataOffset = offset + 30 + nameLength + extraLength;
  assertRange(bytes, dataOffset, entry.compressedSize, `compressed entry "${entry.name}"`);
  return bytes.subarray(dataOffset, dataOffset + entry.compressedSize);
};

const inflateEntry = (entry: ZipEntry, compressed: Uint8Array): Uint8Array => {
  if (entry.method === ZIP_STORED_METHOD) return compressed;
  if (entry.method === ZIP_DEFLATE_METHOD) return inflateRawSync(Buffer.from(compressed));
  throw new Error(`ZIP entry "${entry.name}" uses unsupported compression method ${entry.method}.`);
};

export const extractZipEntry = (bytes: Uint8Array, entryName: string): Uint8Array => {
  const entry = findCentralDirectoryEntry(bytes, entryName);
  const inflated = inflateEntry(entry, readCompressedEntryData(bytes, entry));
  if (inflated.byteLength !== entry.uncompressedSize) {
    throw new Error(`ZIP entry "${entry.name}" decompressed to an unexpected size.`);
  }
  return inflated;
};
