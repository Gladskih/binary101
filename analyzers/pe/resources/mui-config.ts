"use strict";

export interface MuiResourceConfiguration {
  declaredSize: number;
  version: number;
  pathType: number;
  fileType: number;
  systemAttributes: number;
  fallbackLocation: number;
  serviceChecksum: string;
  checksum: string;
  unknown1: [number, number];
  unknown2: [number, number];
  muiPaths: string[];
  mainTypeNames: string[];
  mainTypeIds: number[];
  muiTypeNames: string[];
  muiTypeIds: number[];
  languageName: string | null;
  fallbackLanguageName: string | null;
  trailingByteCount: number;
}

export interface MuiResourceConfigurationParseResult {
  configuration: MuiResourceConfiguration | null;
  issues: string[];
}

type ResourceRange = { offset: number; size: number };

type MuiResourceHeader = {
  declaredSize: number;
  version: number;
  pathType: number;
  fileType: number;
  systemAttributes: number;
  fallbackLocation: number;
  serviceChecksum: string;
  checksum: string;
  unknown1: [number, number];
  muiPath: ResourceRange;
  unknown2: [number, number];
  mainTypeNames: ResourceRange;
  mainTypeIds: ResourceRange;
  muiTypeNames: ResourceRange;
  muiTypeIds: ResourceRange;
  languageName: ResourceRange;
  fallbackLanguageName: ResourceRange;
};

const UINT32_SIZE = 4;
const RESOURCE_RANGE_SIZE = UINT32_SIZE * 2;
const CHECKSUM_BYTE_LENGTH = 16;
// Wine's GetFileMUIInfo source models the MUI resource structure with this 132-byte fixed header.
// https://learn.microsoft.com/en-us/windows/win32/intl/resource-utilities
// https://gitlab.winehq.org/wine/wine/-/commit/f477eca7894ba969d44cdad0f91f1be73133ed2c
const MUI_RESOURCE_HEADER_SIZE = 132;

const readUint32 = (view: DataView, offset: number): number => view.getUint32(offset, true);

const formatHexBytes = (bytes: Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

const readRange = (view: DataView, offset: number): ResourceRange => ({
  offset: readUint32(view, offset),
  size: readUint32(view, offset + UINT32_SIZE)
});

const rangeFits = (range: ResourceRange, limit: number): boolean =>
  !range.size ||
  (range.offset >= MUI_RESOURCE_HEADER_SIZE && range.offset <= limit && range.size <= limit - range.offset);

const readUint32Pair = (view: DataView, offset: number): [number, number] => [
  readUint32(view, offset),
  readUint32(view, offset + UINT32_SIZE)
];

const readMuiResourceHeader = (data: Uint8Array, issues: string[]): MuiResourceHeader | null => {
  if (data.length < UINT32_SIZE) {
    issues.push("MUI resource config is too small to read the MUIRCT signature.");
    return null;
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;
  const signature = readUint32(view, offset);
  offset += UINT32_SIZE;
  // Microsoft Resource Utilities print MUIRCT Signature fecdfecd for resource configuration data.
  if (signature !== 0xfecdfecd) {
    issues.push("MUI resource config signature is not fecdfecd.");
    return null;
  }
  if (data.length < MUI_RESOURCE_HEADER_SIZE) {
    issues.push("MUI resource config header is truncated.");
    return null;
  }
  const declaredSize = readUint32(view, offset);
  offset += UINT32_SIZE;
  const version = readUint32(view, offset);
  offset += UINT32_SIZE;
  const pathType = readUint32(view, offset);
  offset += UINT32_SIZE;
  const fileType = readUint32(view, offset);
  offset += UINT32_SIZE;
  const systemAttributes = readUint32(view, offset);
  offset += UINT32_SIZE;
  const fallbackLocation = readUint32(view, offset);
  offset += UINT32_SIZE;
  // MUIRCT dumps Service Checksum and Checksum as 16-byte values.
  const serviceChecksum = formatHexBytes(data.subarray(offset, offset + CHECKSUM_BYTE_LENGTH));
  offset += CHECKSUM_BYTE_LENGTH;
  const checksum = formatHexBytes(data.subarray(offset, offset + CHECKSUM_BYTE_LENGTH));
  offset += CHECKSUM_BYTE_LENGTH;
  const unknown1 = readUint32Pair(view, offset);
  offset += UINT32_SIZE * 2;
  const muiPath = readRange(view, offset);
  offset += RESOURCE_RANGE_SIZE;
  const unknown2 = readUint32Pair(view, offset);
  offset += UINT32_SIZE * 2;
  const mainTypeNames = readRange(view, offset);
  offset += RESOURCE_RANGE_SIZE;
  const mainTypeIds = readRange(view, offset);
  offset += RESOURCE_RANGE_SIZE;
  const muiTypeNames = readRange(view, offset);
  offset += RESOURCE_RANGE_SIZE;
  const muiTypeIds = readRange(view, offset);
  offset += RESOURCE_RANGE_SIZE;
  const languageName = readRange(view, offset);
  offset += RESOURCE_RANGE_SIZE;
  const fallbackLanguageName = readRange(view, offset);
  return offset + RESOURCE_RANGE_SIZE === MUI_RESOURCE_HEADER_SIZE
    ? {
        declaredSize,
        version,
        pathType,
        fileType,
        systemAttributes,
        fallbackLocation,
        serviceChecksum,
        checksum,
        unknown1,
        muiPath,
        unknown2,
        mainTypeNames,
        mainTypeIds,
        muiTypeNames,
        muiTypeIds,
        languageName,
        fallbackLanguageName
      }
    : null;
};

const readRangeBytes = (
  data: Uint8Array,
  range: ResourceRange,
  limit: number,
  label: string,
  issues: string[]
): Uint8Array | null => {
  if (!range.size) return new Uint8Array();
  if (!rangeFits(range, limit)) {
    issues.push(`MUI resource config ${label} range points outside the declared config size.`);
    return null;
  }
  return data.subarray(range.offset, range.offset + range.size);
};

const readUint32Array = (
  data: Uint8Array,
  range: ResourceRange,
  limit: number,
  label: string,
  issues: string[]
): number[] | null => {
  const bytes = readRangeBytes(data, range, limit, label, issues);
  if (!bytes) return null;
  if (!bytes.length) return [];
  if (bytes.length % UINT32_SIZE !== 0) {
    issues.push(`MUI resource config ${label} array is not DWORD-aligned.`);
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Array.from({ length: bytes.length / UINT32_SIZE }, (_, index) =>
    readUint32(view, index * UINT32_SIZE)
  );
};

const readUtf16StringList = (
  data: Uint8Array,
  range: ResourceRange,
  limit: number,
  label: string,
  issues: string[]
): string[] | null => {
  const bytes = readRangeBytes(data, range, limit, label, issues);
  if (!bytes) return null;
  if (!bytes.length) return [];
  if (bytes.length % 2 !== 0) {
    issues.push(`MUI resource config ${label} string data is not UTF-16LE aligned.`);
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(bytes.length - 2, true) !== 0) {
    issues.push(`MUI resource config ${label} string list is not NUL-terminated.`);
  }
  return new TextDecoder("utf-16le")
    .decode(bytes)
    .split("\0")
    .map(value => value.trim())
    .filter(Boolean);
};

const readSingleUtf16String = (
  data: Uint8Array,
  range: ResourceRange,
  limit: number,
  label: string,
  issues: string[]
): string | null => {
  const values = readUtf16StringList(data, range, limit, label, issues);
  return values?.[0] || null;
};

export const getMuiResourceFileTypeLabel = (fileType: number): string => {
  const labels: string[] = [];
  // Wine maps on-disk file_type bits to FILEMUIINFO MUI_FILETYPE_* values by shifting
  // MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN / MUI down by one bit.
  if ((fileType & 0x01) !== 0) labels.push("Language-neutral main (LN)");
  if ((fileType & 0x02) !== 0) labels.push("Language-specific MUI resource");
  return labels.length ? labels.join(" + ") : "Unknown MUI file type";
};

export const parseMuiResourceConfigurationDetailed = (
  data: Uint8Array
): MuiResourceConfigurationParseResult => {
  const issues: string[] = [];
  const header = readMuiResourceHeader(data, issues);
  if (!header) return { configuration: null, issues };
  if (header.declaredSize < MUI_RESOURCE_HEADER_SIZE) {
    issues.push("MUI resource config declared size is smaller than the fixed header.");
    return { configuration: null, issues };
  }
  if (header.declaredSize > data.length) {
    issues.push("MUI resource config declared size exceeds the resource payload size.");
  }
  const limit = Math.min(data.length, header.declaredSize);
  const muiPaths = readUtf16StringList(data, header.muiPath, limit, "MUI path", issues);
  const mainTypeNames = readUtf16StringList(data, header.mainTypeNames, limit, "LN type names", issues);
  const mainTypeIds = readUint32Array(data, header.mainTypeIds, limit, "LN type IDs", issues);
  const muiTypeNames = readUtf16StringList(data, header.muiTypeNames, limit, "MUI type names", issues);
  const muiTypeIds = readUint32Array(data, header.muiTypeIds, limit, "MUI type IDs", issues);
  if (!muiPaths || !mainTypeNames || !mainTypeIds || !muiTypeNames || !muiTypeIds) {
    return { configuration: null, issues };
  }
  return { configuration: {
    declaredSize: header.declaredSize,
    version: header.version,
    pathType: header.pathType,
    fileType: header.fileType,
    systemAttributes: header.systemAttributes,
    fallbackLocation: header.fallbackLocation,
    serviceChecksum: header.serviceChecksum,
    checksum: header.checksum,
    unknown1: header.unknown1,
    unknown2: header.unknown2,
    muiPaths,
    mainTypeNames,
    mainTypeIds,
    muiTypeNames,
    muiTypeIds,
    languageName: readSingleUtf16String(data, header.languageName, limit, "language name", issues),
    fallbackLanguageName: readSingleUtf16String(data, header.fallbackLanguageName, limit, "fallback language", issues),
    trailingByteCount: Math.max(0, data.length - header.declaredSize)
  }, issues };
};

export const parseMuiResourceConfiguration = (data: Uint8Array): MuiResourceConfiguration | null =>
  parseMuiResourceConfigurationDetailed(data).configuration;
