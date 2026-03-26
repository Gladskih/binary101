"use strict";

import type { ResourceTree } from "../../analyzers/pe/resources-core.js";
import type { ResourceLangWithPreview } from "../../analyzers/pe/resources-preview-types.js";

// IMAGE_RESOURCE_DIRECTORY is 16 bytes. Source:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-table
const RESOURCE_DIRECTORY_HEADER_SIZE = 16;
// Group icon/cursor directory layouts follow GRPICONDIR / GRPICONDIRENTRY / GRPCURSORDIR /
// GRPCURSORDIRENTRY in winuser.h. Source:
// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/winuser.h
const GROUP_RESOURCE_HEADER_SIZE = 6;
const GROUP_RESOURCE_ENTRY_SIZE = 14;
const PREFERRED_GROUP_IMAGE_SIZE = 32;
const CURSOR_LOCAL_HEADER_SIZE = 4;

type ResourceDetail = ResourceTree["detail"][number];

// 0x0409 (en-US) is a stable default LANGID for preview tests.
export const createPreviewLangEntry = (
  dataRva = 0,
  size = 0,
  codePage = 0,
  lang: number | null = 1033
): ResourceLangWithPreview => ({
  lang,
  size,
  codePage,
  dataRVA: dataRva,
  reserved: 0
});

export const createPreviewDetailGroup = (
  typeName: string,
  id: number,
  langEntry: ResourceLangWithPreview
): ResourceDetail => ({
  typeName,
  entries: [{ id, name: null, langs: [langEntry] }]
});

export const createPreviewTree = (
  detail: ResourceTree["detail"],
  rvaToOff: ResourceTree["rvaToOff"] = value => value
): ResourceTree => ({
  base: 0,
  limitEnd: RESOURCE_DIRECTORY_HEADER_SIZE,
  top: [],
  detail,
  view: async (off, len) =>
    new DataView(new ArrayBuffer(Math.max(RESOURCE_DIRECTORY_HEADER_SIZE, off + len)), off, len),
  rvaToOff
});

export const createPreviewFixture = (fileSize: number): {
  fileBytes: Uint8Array;
  appendData: (data: Uint8Array) => { offset: number; size: number };
  writeData: (offset: number, data: Uint8Array) => { offset: number; size: number };
} => {
  const fileBytes = new Uint8Array(fileSize).fill(0);
  let nextOffset = 64; // Start away from offset 0 so tests never depend on zero-offset special cases.
  return {
    fileBytes,
    appendData: data => {
      const offset = nextOffset;
      fileBytes.set(data, offset);
      nextOffset += (data.length + 15) & ~15;
      return { offset, size: data.length };
    },
    writeData: (offset, data) => {
      fileBytes.set(data, offset);
      return { offset, size: data.length };
    }
  };
};

export const writeUtf16Z = (bytes: Uint8Array, offset: number, text: string): number => {
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < text.length; index += 1) {
    view.setUint16(offset + index * 2, text.charCodeAt(index), true);
  }
  view.setUint16(offset + text.length * 2, 0, true);
  return offset + text.length * 2 + 2;
};

export const alignDword = (offset: number): number => (offset + 3) & ~3;

export const buildCursorResource = (
  hotspotX: number,
  hotspotY: number,
  payload: Uint8Array
): Uint8Array => {
  const bytes = new Uint8Array(CURSOR_LOCAL_HEADER_SIZE + payload.length);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, hotspotX, true);
  view.setUint16(2, hotspotY, true);
  bytes.set(payload, CURSOR_LOCAL_HEADER_SIZE);
  return bytes;
};

export const buildSingleEntryGroupIconResource = (
  iconSize: number,
  iconId: number
): Uint8Array => {
  const bytes = new Uint8Array(GROUP_RESOURCE_HEADER_SIZE + GROUP_RESOURCE_ENTRY_SIZE).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(2, 1, true); // GRPICONDIR.idType = 1 for icons in winuser.h.
  view.setUint16(4, 1, true);
  view.setUint8(6, PREFERRED_GROUP_IMAGE_SIZE);
  view.setUint8(7, PREFERRED_GROUP_IMAGE_SIZE);
  view.setUint16(10, 1, true);
  view.setUint16(12, 32, true);
  view.setUint32(14, iconSize, true);
  view.setUint16(18, iconId, true);
  return bytes;
};

export const buildLargeGroupIconResource = (
  entryCount: number,
  iconSize: number,
  iconId: number
): Uint8Array => {
  const bytes = new Uint8Array(GROUP_RESOURCE_HEADER_SIZE + entryCount * GROUP_RESOURCE_ENTRY_SIZE).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(2, 1, true); // GRPICONDIR.idType = 1 for icons in winuser.h.
  view.setUint16(4, entryCount, true);
  for (let index = 0; index < entryCount; index += 1) {
    const entryOffset = GROUP_RESOURCE_HEADER_SIZE + index * GROUP_RESOURCE_ENTRY_SIZE;
    const isSelectedEntry = index === entryCount - 1;
    view.setUint8(entryOffset, isSelectedEntry ? PREFERRED_GROUP_IMAGE_SIZE : 1);
    view.setUint8(entryOffset + 1, isSelectedEntry ? PREFERRED_GROUP_IMAGE_SIZE : 1);
    view.setUint16(entryOffset + 4, 1, true);
    view.setUint16(entryOffset + 6, 32, true);
    view.setUint32(entryOffset + 8, isSelectedEntry ? iconSize : 0, true);
    view.setUint16(entryOffset + 12, isSelectedEntry ? iconId : 0, true);
  }
  return bytes;
};

export const buildSingleEntryGroupCursorResource = (
  cursorSize: number,
  cursorId: number,
  hotspotX: number,
  hotspotY: number
): Uint8Array => {
  const bytes = new Uint8Array(GROUP_RESOURCE_HEADER_SIZE + GROUP_RESOURCE_ENTRY_SIZE).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(2, 2, true); // GRPCURSORDIR.idType = 2 for cursors in winuser.h.
  view.setUint16(4, 1, true);
  view.setUint8(6, PREFERRED_GROUP_IMAGE_SIZE);
  view.setUint8(7, PREFERRED_GROUP_IMAGE_SIZE);
  view.setUint16(10, hotspotX, true);
  view.setUint16(12, hotspotY, true);
  view.setUint32(14, cursorSize, true);
  view.setUint16(18, cursorId, true);
  return bytes;
};
