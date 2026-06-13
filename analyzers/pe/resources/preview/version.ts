"use strict";

import type {
  ResourcePreviewResult,
  ResourceVersionPreview
} from "./types.js";

// JavaScript typed-array element sizes are byte counts; PE WORD/DWORD bit
// splits require the conventional 8-bit byte used by the PE/COFF spec.
const BITS_PER_BYTE = 8;
const WORD_BITS = Uint16Array.BYTES_PER_ELEMENT * BITS_PER_BYTE;
const WORD_VALUE_COUNT = 2 ** WORD_BITS;
const WORD_MASK = WORD_VALUE_COUNT - 1;
const DWORD_SIZE = Uint32Array.BYTES_PER_ELEMENT;
const DWORD_ALIGNMENT_MASK = DWORD_SIZE - 1;

// VS_VERSIONINFO begins with three WORD fields: wLength, wValueLength, wType.
// Source: Microsoft Learn, VS_VERSIONINFO /
// https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
const VERSION_HEADER_WORD_COUNT = 3;
const VERSION_HEADER_SIZE = VERSION_HEADER_WORD_COUNT * Uint16Array.BYTES_PER_ELEMENT;

// sizeof(VS_FIXEDFILEINFO) is 13 DWORDs. Source:
// Microsoft Learn, VS_FIXEDFILEINFO /
// https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
const VS_FIXEDFILEINFO_DWORD_COUNT = 13;
const VS_FIXEDFILEINFO_SIZE = VS_FIXEDFILEINFO_DWORD_COUNT * DWORD_SIZE;
// VS_FIXEDFILEINFO field order is documented as dwSignature, dwStrucVersion,
// dwFileVersionMS, dwFileVersionLS, dwProductVersionMS, dwProductVersionLS, ...
// Source: Microsoft Learn, VS_FIXEDFILEINFO.
const VS_FIXEDFILEINFO_STRUCT_VERSION_DWORD_INDEX = 1;
const VS_FIXEDFILEINFO_FILE_VERSION_MS_DWORD_INDEX = 2;
const VS_FIXEDFILEINFO_FILE_VERSION_LS_DWORD_INDEX = 3;
const VS_FIXEDFILEINFO_PRODUCT_VERSION_MS_DWORD_INDEX = 4;
const VS_FIXEDFILEINFO_PRODUCT_VERSION_LS_DWORD_INDEX = 5;
// VS_FIXEDFILEINFO.dwSignature is fixed at 0xFEEF04BD. Source:
// Microsoft Learn, VS_FIXEDFILEINFO.
const VS_FIXEDFILEINFO_SIGNATURE = 0xfeef04bd;

type VersionNode = {
  length: number;
  valueLength: number;
  valueType: number;
  key: string;
  start: number;
  end: number;
  valueOffset: number;
  valueByteLength: number;
  childrenOffset: number;
};

type FixedFileInfoResult =
  | {
      versionInfo: Pick<ResourceVersionPreview, "fixedFileInfo" | "fileVersionString" | "productVersionString">;
      issues?: string[];
    }
  | { issues: string[] };

const alignDword = (offset: number): number => (offset + DWORD_ALIGNMENT_MASK) & ~DWORD_ALIGNMENT_MASK;

const highWord = (value: number): number => (value >>> WORD_BITS) & WORD_MASK;

const lowWord = (value: number): number => value & WORD_MASK;

const readUtf16Z = (view: DataView, offset: number, end: number): { text: string; nextOffset: number } => {
  let pos = offset;
  let text = "";
  while (pos + 1 < end) {
    const codeUnit = view.getUint16(pos, true);
    pos += 2;
    if (codeUnit === 0) break;
    text += String.fromCharCode(codeUnit);
  }
  return { text, nextOffset: pos };
};

const parseVersionNode = (view: DataView, offset: number, limit: number): VersionNode | null => {
  if (offset + VERSION_HEADER_SIZE > limit) return null;
  const length = view.getUint16(offset, true);
  if (length < VERSION_HEADER_SIZE) return null;
  const end = Math.min(limit, offset + length);
  if (end <= offset + VERSION_HEADER_SIZE) return null;
  const valueLength = view.getUint16(offset + 2, true);
  const valueType = view.getUint16(offset + 4, true);
  const key = readUtf16Z(view, offset + VERSION_HEADER_SIZE, end);
  const valueOffset = alignDword(key.nextOffset);
  const valueByteLength = valueType === 1 ? valueLength * 2 : valueLength;
  const childrenOffset = alignDword(Math.min(end, valueOffset + valueByteLength));
  return {
    length,
    valueLength,
    valueType,
    key: key.text,
    start: offset,
    end,
    valueOffset,
    valueByteLength,
    childrenOffset
  };
};

const formatVersionPair = (high: number, low: number): string =>
  `${highWord(high)}.${lowWord(high)}.${highWord(low)}.${lowWord(low)}`;

const parseFixedFileInfo = (
  view: DataView,
  root: VersionNode
): FixedFileInfoResult => {
  if (root.key !== "VS_VERSION_INFO") {
    return { issues: ["VERSION resource key is missing or invalid."] };
  }
  if (root.valueByteLength < VS_FIXEDFILEINFO_SIZE || root.valueOffset + VS_FIXEDFILEINFO_SIZE > root.end) {
    return { issues: ["Version block is too small to read VS_FIXEDFILEINFO."] };
  }
  const signature = view.getUint32(root.valueOffset, true);
  if (signature !== VS_FIXEDFILEINFO_SIGNATURE) {
    return { issues: ["VS_FIXEDFILEINFO signature is missing or invalid."] };
  }
  const structVersion = view.getUint32(
    root.valueOffset + DWORD_SIZE * VS_FIXEDFILEINFO_STRUCT_VERSION_DWORD_INDEX,
    true
  );
  return {
    versionInfo: {
      fixedFileInfo: {
        structVersionRaw: structVersion,
        structVersionMajor: highWord(structVersion),
        structVersionMinor: lowWord(structVersion)
      },
      fileVersionString: formatVersionPair(
        view.getUint32(root.valueOffset + DWORD_SIZE * VS_FIXEDFILEINFO_FILE_VERSION_MS_DWORD_INDEX, true),
        view.getUint32(root.valueOffset + DWORD_SIZE * VS_FIXEDFILEINFO_FILE_VERSION_LS_DWORD_INDEX, true)
      ),
      productVersionString: formatVersionPair(
        view.getUint32(root.valueOffset + DWORD_SIZE * VS_FIXEDFILEINFO_PRODUCT_VERSION_MS_DWORD_INDEX, true),
        view.getUint32(root.valueOffset + DWORD_SIZE * VS_FIXEDFILEINFO_PRODUCT_VERSION_LS_DWORD_INDEX, true)
      )
    }
  };
};

const collectStringValues = (
  view: DataView,
  block: VersionNode
): Array<{ table: string; key: string; value: string }> => {
  const values: Array<{ table: string; key: string; value: string }> = [];
  for (let pos = block.childrenOffset; pos + VERSION_HEADER_SIZE <= block.end;) {
    const table = parseVersionNode(view, pos, block.end);
    if (!table || table.end <= pos) break;
    for (let childPos = table.childrenOffset; childPos + VERSION_HEADER_SIZE <= table.end;) {
      const value = parseVersionNode(view, childPos, table.end);
      if (!value || value.end <= childPos) break;
      if (value.valueType === 1 && value.valueOffset < value.end) {
        const text = readUtf16Z(
          view,
          value.valueOffset,
          Math.min(value.end, value.valueOffset + value.valueByteLength)
        ).text;
        values.push({
          table: table.key,
          key: value.key,
          value: text
        });
      }
      childPos = alignDword(value.end);
    }
    pos = alignDword(table.end);
  }
  return values;
};

const collectTranslations = (
  view: DataView,
  block: VersionNode
): Array<{ languageId: number; codePage: number }> => {
  const translations: Array<{ languageId: number; codePage: number }> = [];
  for (let pos = block.childrenOffset; pos + VERSION_HEADER_SIZE <= block.end;) {
    const child = parseVersionNode(view, pos, block.end);
    if (!child || child.end <= pos) break;
    if (child.key === "Translation") {
      const valueEnd = Math.min(child.end, child.valueOffset + child.valueByteLength);
      for (let itemPos = child.valueOffset; itemPos + 3 < valueEnd; itemPos += 4) {
        translations.push({
          languageId: view.getUint16(itemPos, true),
          codePage: view.getUint16(itemPos + 2, true)
        });
      }
    }
    pos = alignDword(child.end);
  }
  return translations;
};

export const addVersionPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "VERSION" || data.byteLength < VERSION_HEADER_SIZE) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const root = parseVersionNode(view, 0, data.byteLength);
  if (!root) {
    return { issues: ["VERSION resource header is truncated or malformed."] };
  }
  const fixed = parseFixedFileInfo(view, root);
  if (!("versionInfo" in fixed)) return fixed;
  const versionInfo: ResourceVersionPreview = { ...fixed.versionInfo };
  for (let pos = root.childrenOffset; pos + VERSION_HEADER_SIZE <= root.end;) {
    const child = parseVersionNode(view, pos, root.end);
    if (!child || child.end <= pos) break;
    if (child.key === "StringFileInfo") {
      const stringValues = collectStringValues(view, child);
      if (stringValues.length) versionInfo.stringValues = stringValues;
    } else if (child.key === "VarFileInfo") {
      const translations = collectTranslations(view, child);
      if (translations.length) versionInfo.translations = translations;
    }
    pos = alignDword(child.end);
  }
  return {
    preview: {
      previewKind: "version",
      versionInfo
    },
    ...(fixed.issues?.length ? { issues: fixed.issues } : {})
  };
};
