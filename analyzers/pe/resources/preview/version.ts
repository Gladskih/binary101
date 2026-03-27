"use strict";

import type {
  ResourcePreviewResult,
  ResourceVersionPreview
} from "./types.js";

const VERSION_HEADER_SIZE = 6; // VS_VERSIONINFO header: wLength + wValueLength + wType

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
      fixedFileInfo: Pick<ResourceVersionPreview, "fileVersionString" | "productVersionString">;
      issues?: string[];
    }
  | { issues: string[] };

const DWORD_SIZE = Uint32Array.BYTES_PER_ELEMENT;

const alignDword = (offset: number): number => (offset + 3) & ~3;

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
  `${(high >>> 16) & 0xffff}.${high & 0xffff}.${(low >>> 16) & 0xffff}.${low & 0xffff}`;

const parseFixedFileInfo = (
  view: DataView,
  root: VersionNode
): FixedFileInfoResult => {
  if (root.key !== "VS_VERSION_INFO") {
    return { issues: ["VERSION resource key is missing or invalid."] };
  }
  // sizeof(VS_FIXEDFILEINFO) is 13 DWORDs = 52 bytes. Source:
  // Microsoft Learn, VS_FIXEDFILEINFO / https://learn.microsoft.com/en-us/windows/win32/menurc/vs-fixedfileinfo
  if (root.valueByteLength < 13 * DWORD_SIZE || root.valueOffset + 13 * DWORD_SIZE > root.end) {
    return { issues: ["Version block is too small to read VS_FIXEDFILEINFO."] };
  }
  const signature = view.getUint32(root.valueOffset, true);
  const structVersion = view.getUint32(root.valueOffset + DWORD_SIZE, true);
  // VS_FIXEDFILEINFO.dwSignature is always 0xFEEF04BD. Source:
  // Microsoft Learn, VS_FIXEDFILEINFO / https://learn.microsoft.com/en-us/windows/win32/menurc/vs-fixedfileinfo
  if (signature !== 0xfeef04bd) {
    return { issues: ["VS_FIXEDFILEINFO signature is missing or invalid."] };
  }
  // VS_FIXEDFILEINFO.dwStrucVersion is 0x00010000 for the current structure version. Source:
  // Microsoft Learn, VS_FIXEDFILEINFO / https://learn.microsoft.com/en-us/windows/win32/menurc/vs-fixedfileinfo
  return {
    fixedFileInfo: {
      fileVersionString: formatVersionPair(
        view.getUint32(root.valueOffset + DWORD_SIZE * 2, true),
        view.getUint32(root.valueOffset + DWORD_SIZE * 3, true)
      ),
      productVersionString: formatVersionPair(
        view.getUint32(root.valueOffset + DWORD_SIZE * 4, true),
        view.getUint32(root.valueOffset + DWORD_SIZE * 5, true)
      )
    },
    ...(structVersion !== 0x00010000
      ? {
          issues: [
            `VS_FIXEDFILEINFO struct version is unexpected (expected 0x00010000, found 0x${structVersion.toString(16).padStart(8, "0")}).`
          ]
        }
      : {})
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
  if (!("fixedFileInfo" in fixed)) return fixed;
  const versionInfo: ResourceVersionPreview = { ...fixed.fixedFileInfo };
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
