"use strict";

export interface UpxPackHeader {
  version: number;
  format: number;
  method: number;
  level: number;
  unpackedAdler32: number;
  packedAdler32: number;
  unpackedSize: number;
  packedSize: number;
  originalFileSize: number;
  filter: number;
  filterParameter: number;
  filterMru: number;
  headerSize: number;
  headerChecksum: number | null;
}

export type UpxPackHeaderParseResult = { header: UpxPackHeader } | { error: string } | null;

// PackHeader layout and checksum algorithm are defined by upstream UPX.
// https://github.com/upx/upx/blob/devel/src/packhead.cpp
const UPX_MAGIC = Uint8Array.of(0x55, 0x50, 0x58, 0x21);
const MODERN_HEADER_BYTES = 32;
const OLD_HEADER_BYTES = 28;
const CHECKSUM_VERSION = 10;
const PE32_FORMATS = new Set([9, 21]);
const PE32_PLUS_FORMATS = new Set([36, 43, 44]);

const hasMagic = (view: DataView, offset: number): boolean => {
  if (offset < 0 || offset > view.byteLength - UPX_MAGIC.byteLength) return false;
  return UPX_MAGIC.every((byte, index) => view.getUint8(offset + index) === byte);
};

const matchesPeWidth = (format: number, imagePointerBytes: 4 | 8): boolean =>
  (imagePointerBytes === 4 ? PE32_FORMATS : PE32_PLUS_FORMATS).has(format);

const isKnownMethod = (method: number): boolean =>
  (method >= 2 && method <= 10) || method === 14;

export const upxPackHeaderChecksum = (headerWithoutChecksum: Uint8Array): number => {
  let sum = 0;
  for (let index = UPX_MAGIC.byteLength; index < headerWithoutChecksum.byteLength; index += 1) {
    sum += headerWithoutChecksum[index] ?? 0;
  }
  return sum % 251;
};

const readChecksum = (
  view: DataView,
  offset: number,
  headerSize: number,
  version: number
): { stored: number | null; calculated: number | null } => {
  if (version < CHECKSUM_VERSION) return { stored: null, calculated: null };
  const bytes = new Uint8Array(view.buffer, view.byteOffset + offset, headerSize - 1);
  return { stored: view.getUint8(offset + headerSize - 1), calculated: upxPackHeaderChecksum(bytes) };
};

const validateHeader = (header: UpxPackHeader, imagePointerBytes: 4 | 8): string | null => {
  if (!matchesPeWidth(header.format, imagePointerBytes)) {
    return "UPX PackHeader format does not match this PE image.";
  }
  if (header.version === 0 || header.version === 0xff) return "UPX PackHeader version is invalid.";
  if (!isKnownMethod(header.method)) return "UPX PackHeader compression method is unsupported.";
  if (header.level < 1 || header.level > 10) return "UPX PackHeader compression level is invalid.";
  if (header.packedSize < 2 || header.unpackedSize < 2) return "UPX PackHeader sizes are too small.";
  if (header.packedSize >= header.unpackedSize) {
    return "UPX PackHeader packed size is not smaller than its unpacked size.";
  }
  if (header.originalFileSize < 2) return "UPX PackHeader original file size is invalid.";
  return null;
};

export const parseUpxPackHeader = (
  view: DataView,
  offset: number,
  imagePointerBytes: 4 | 8
): UpxPackHeaderParseResult => {
  if (!hasMagic(view, offset)) return null;
  if (offset > view.byteLength - 8) return { error: "UPX PackHeader is truncated." };
  const version = view.getUint8(offset + 4);
  const headerSize = version >= CHECKSUM_VERSION ? MODERN_HEADER_BYTES : OLD_HEADER_BYTES;
  if (offset > view.byteLength - headerSize) return { error: "UPX PackHeader is truncated." };
  const checksum = readChecksum(view, offset, headerSize, version);
  const rawLevel = view.getUint8(offset + 7);
  const header: UpxPackHeader = {
    version,
    format: view.getUint8(offset + 5),
    method: view.getUint8(offset + 6),
    level: rawLevel & 0x0f,
    unpackedAdler32: view.getUint32(offset + 8, true),
    packedAdler32: view.getUint32(offset + 12, true),
    unpackedSize: view.getUint32(offset + 16, true),
    packedSize: view.getUint32(offset + 20, true),
    originalFileSize: view.getUint32(offset + 24, true),
    filter: version >= CHECKSUM_VERSION ? view.getUint8(offset + 28) : (rawLevel & 0x80 ? 0x26 : 0),
    filterParameter: version >= CHECKSUM_VERSION ? view.getUint8(offset + 29) : 0,
    filterMru: version >= CHECKSUM_VERSION && view.getUint8(offset + 30)
      ? view.getUint8(offset + 30) + 1
      : 0,
    headerSize,
    headerChecksum: checksum.stored
  };
  if (checksum.stored !== checksum.calculated) return { error: "UPX PackHeader checksum does not match." };
  const error = validateHeader(header, imagePointerBytes);
  return error ? { error } : { header };
};
