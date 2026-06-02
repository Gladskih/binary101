"use strict";

export interface MuiResourceConfiguration {
  version: number;
  fileType: number;
  mainTypeNames: string[];
  mainTypeIds: number[];
  muiTypeNames: string[];
  muiTypeIds: number[];
  languageName: string | null;
  fallbackLanguageName: string | null;
}

type ResourceRange = { offset: number; size: number };

type MuiResourceHeader = {
  declaredSize: number;
  version: number;
  fileType: number;
  mainTypeNames: ResourceRange;
  mainTypeIds: ResourceRange;
  muiTypeNames: ResourceRange;
  muiTypeIds: ResourceRange;
  languageName: ResourceRange;
  fallbackLanguageName: ResourceRange;
};

const UINT32_SIZE = 4;
const RESOURCE_RANGE_SIZE = UINT32_SIZE * 2;
// Wine's GetFileMUIInfo source models the MUI resource structure with this 132-byte fixed header.
// https://learn.microsoft.com/en-us/windows/win32/intl/resource-utilities
// https://gitlab.winehq.org/wine/wine/-/commit/f477eca7894ba969d44cdad0f91f1be73133ed2c
const MUI_RESOURCE_HEADER_SIZE = 132;

const readUint32 = (view: DataView, offset: number): number => view.getUint32(offset, true);

const readRange = (view: DataView, offset: number): ResourceRange => ({
  offset: readUint32(view, offset),
  size: readUint32(view, offset + UINT32_SIZE)
});

const rangeFits = (range: ResourceRange, limit: number): boolean =>
  (range.offset === 0 && range.size === 0) ||
  (range.offset >= MUI_RESOURCE_HEADER_SIZE && range.offset <= limit && range.size <= limit - range.offset);

const readMuiResourceHeader = (data: Uint8Array): MuiResourceHeader | null => {
  if (data.length < MUI_RESOURCE_HEADER_SIZE) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;
  const signature = readUint32(view, offset);
  offset += UINT32_SIZE;
  // Microsoft Resource Utilities print MUIRCT Signature fecdfecd for resource configuration data.
  if (signature !== 0xfecdfecd) return null;
  const declaredSize = readUint32(view, offset);
  offset += UINT32_SIZE;
  const version = readUint32(view, offset);
  offset += UINT32_SIZE * 2;
  const fileType = readUint32(view, offset);
  offset += UINT32_SIZE * 3;
  // MUIRCT dumps Service Checksum and Checksum as 16-byte values.
  offset += 16 * 2;
  offset += UINT32_SIZE * 2;
  offset += RESOURCE_RANGE_SIZE;
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
        fileType,
        mainTypeNames,
        mainTypeIds,
        muiTypeNames,
        muiTypeIds,
        languageName,
        fallbackLanguageName
      }
    : null;
};

const readUint32Array = (view: DataView, range: ResourceRange, limit: number): number[] | null => {
  if (!range.size) return [];
  if (!rangeFits(range, limit) || range.size % UINT32_SIZE !== 0) return null;
  return Array.from({ length: range.size / UINT32_SIZE }, (_, index) =>
    readUint32(view, range.offset + index * UINT32_SIZE)
  );
};

const readUtf16StringList = (data: Uint8Array, range: ResourceRange, limit: number): string[] | null => {
  if (!range.size) return [];
  if (!rangeFits(range, limit) || range.size % 2 !== 0) return null;
  return new TextDecoder("utf-16le")
    .decode(data.subarray(range.offset, range.offset + range.size))
    .split("\0")
    .map(value => value.trim())
    .filter(Boolean);
};

const readSingleUtf16String = (data: Uint8Array, range: ResourceRange, limit: number): string | null => {
  const values = readUtf16StringList(data, range, limit);
  return values?.[0] || null;
};

export const parseMuiResourceConfiguration = (data: Uint8Array): MuiResourceConfiguration | null => {
  const header = readMuiResourceHeader(data);
  if (!header || header.declaredSize < MUI_RESOURCE_HEADER_SIZE) return null;
  const limit = Math.min(data.length, header.declaredSize);
  const view = new DataView(data.buffer, data.byteOffset, limit);
  const mainTypeNames = readUtf16StringList(data, header.mainTypeNames, limit);
  const mainTypeIds = readUint32Array(view, header.mainTypeIds, limit);
  const muiTypeNames = readUtf16StringList(data, header.muiTypeNames, limit);
  const muiTypeIds = readUint32Array(view, header.muiTypeIds, limit);
  if (!mainTypeNames || !mainTypeIds || !muiTypeNames || !muiTypeIds) return null;
  return {
    version: header.version,
    fileType: header.fileType,
    mainTypeNames,
    mainTypeIds,
    muiTypeNames,
    muiTypeIds,
    languageName: readSingleUtf16String(data, header.languageName, limit),
    fallbackLanguageName: readSingleUtf16String(data, header.fallbackLanguageName, limit)
  };
};
