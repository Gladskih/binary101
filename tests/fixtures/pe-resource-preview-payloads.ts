"use strict";

import { createBmpFile, createPngFile } from "./image-sample-files.js";
import { createAniFile } from "./riff-sample-files.js";

const DS_SETFONT = 0x00000040;
const RESOURCE_TYPE_CURSOR = 1;
const RESOURCE_TYPE_BITMAP = 2;
const RESOURCE_TYPE_ICON = 3;
const RESOURCE_TYPE_MENU = 4;
const RESOURCE_TYPE_DIALOG = 5;
const RESOURCE_TYPE_STRING = 6;
const RESOURCE_TYPE_ACCELERATOR = 9;
const RESOURCE_TYPE_RCDATA = 10;
const RESOURCE_TYPE_MESSAGETABLE = 11;
const RESOURCE_TYPE_GROUP_CURSOR = 12;
const RESOURCE_TYPE_GROUP_ICON = 14;
const RESOURCE_TYPE_VERSION = 16;
const RESOURCE_TYPE_ANICURSOR = 21;
const RESOURCE_TYPE_HTML = 23;
const RESOURCE_TYPE_MANIFEST = 24;

export type ResourceSpec = {
  typeId: number;
  entryId: number;
  langId: number;
  codePage: number;
  data: Uint8Array;
};

const align = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

const writeUtf16Z = (bytes: Uint8Array, offset: number, text: string): number => {
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < text.length; index += 1) {
    view.setUint16(offset + index * 2, text.charCodeAt(index), true);
  }
  view.setUint16(offset + text.length * 2, 0, true);
  return offset + text.length * 2 + 2;
};

const encodeUtf16Z = (text: string): Uint8Array => {
  const bytes = new Uint8Array((text.length + 1) * 2);
  writeUtf16Z(bytes, 0, text);
  return bytes;
};

const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
};

const buildVersionNode = (
  key: string,
  valueBytes: Uint8Array,
  valueType: 0 | 1,
  children: Uint8Array[]
): Uint8Array => {
  const keyBytes = encodeUtf16Z(key);
  const valueOffset = align(6 + keyBytes.length, 4);
  const valueLength = valueType === 1 ? valueBytes.length / 2 : valueBytes.length;
  const paddedChildren = children.map(child => {
    const padding = align(child.length, 4) - child.length;
    return padding > 0 ? concatBytes([child, new Uint8Array(padding)]) : child;
  });
  const totalLength = valueOffset + valueBytes.length + paddedChildren.reduce((sum, child) => sum + child.length, 0);
  const bytes = new Uint8Array(totalLength).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, totalLength, true);
  view.setUint16(2, valueLength, true);
  view.setUint16(4, valueType, true);
  bytes.set(keyBytes, 6);
  bytes.set(valueBytes, valueOffset);
  let offset = valueOffset + valueBytes.length;
  for (const child of paddedChildren) {
    bytes.set(child, offset);
    offset += child.length;
  }
  return bytes;
};

const buildVersionResource = (): Uint8Array => {
  const fixed = new Uint8Array(52).fill(0);
  const view = new DataView(fixed.buffer);
  view.setUint32(0, 0xfeef04bd, true);
  view.setUint32(4, 0x00010000, true);
  view.setUint32(8, 0x00010002, true);
  view.setUint32(12, 0x00030004, true);
  view.setUint32(16, 0x00010002, true);
  view.setUint32(20, 0x00030004, true);
  const stringTable = buildVersionNode("040904B0", new Uint8Array(), 1, [
    buildVersionNode("CompanyName", encodeUtf16Z("Binary101"), 1, []),
    buildVersionNode("FileDescription", encodeUtf16Z("PE resource showcase"), 1, [])
  ]);
  const translation = (() => {
    const bytes = new Uint8Array(4);
    const translationView = new DataView(bytes.buffer);
    translationView.setUint16(0, 0x0409, true);
    translationView.setUint16(2, 1200, true);
    return buildVersionNode("Translation", bytes, 0, []);
  })();
  return buildVersionNode("VS_VERSION_INFO", fixed, 0, [
    buildVersionNode("StringFileInfo", new Uint8Array(), 1, [stringTable]),
    buildVersionNode("VarFileInfo", new Uint8Array(), 1, [translation])
  ]);
};

const buildStringTableResource = (): Uint8Array => {
  const bytes = new Uint8Array(48).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 5, true);
  writeUtf16Z(bytes, 2, "Hello");
  view.setUint16(14, 5, true);
  writeUtf16Z(bytes, 16, "World");
  return bytes;
};

const buildMessageTableResource = (): Uint8Array => {
  const bytes = new Uint8Array(80).fill(0);
  const view = new DataView(bytes.buffer);
  const firstEntryOffset = 32;
  const secondEntryOffset = firstEntryOffset + 6;
  view.setUint32(0, 1, true);
  view.setUint32(4, 10, true);
  view.setUint32(8, 11, true);
  view.setUint32(12, firstEntryOffset, true);
  view.setUint16(firstEntryOffset, 6, true);
  view.setUint16(firstEntryOffset + 2, 0, true);
  bytes[firstEntryOffset + 4] = "O".charCodeAt(0);
  bytes[firstEntryOffset + 5] = "K".charCodeAt(0);
  view.setUint16(secondEntryOffset, 8, true);
  view.setUint16(secondEntryOffset + 2, 1, true);
  writeUtf16Z(bytes, secondEntryOffset + 4, "Hi");
  return bytes;
};

const buildCursorResource = (hotspotX: number, hotspotY: number, payload: Uint8Array): Uint8Array => {
  const bytes = new Uint8Array(4 + payload.length);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, hotspotX, true);
  view.setUint16(2, hotspotY, true);
  bytes.set(payload, 4);
  return bytes;
};

const buildGroupIconResource = (iconSize: number, iconId: number): Uint8Array => {
  const bytes = new Uint8Array(20).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(4, 1, true);
  view.setUint8(6, 32);
  view.setUint8(7, 32);
  view.setUint16(10, 1, true);
  view.setUint16(12, 32, true);
  view.setUint32(14, iconSize, true);
  view.setUint16(18, iconId, true);
  return bytes;
};

const buildGroupCursorResource = (cursorSize: number, cursorId: number): Uint8Array => {
  const bytes = new Uint8Array(20).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(4, 1, true);
  view.setUint8(6, 32);
  view.setUint8(7, 32);
  view.setUint16(10, 7, true);
  view.setUint16(12, 9, true);
  view.setUint32(14, cursorSize, true);
  view.setUint16(18, cursorId, true);
  return bytes;
};

const buildAcceleratorTable = (): Uint8Array => {
  const bytes = new Uint8Array(8).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint8(0, 0x89);
  view.setUint16(2, 0x4f, true);
  view.setUint16(4, 100, true);
  return bytes;
};

const buildStandardMenuTemplate = (): Uint8Array => {
  const bytes = new Uint8Array(64).fill(0);
  const view = new DataView(bytes.buffer);
  let offset = 4;
  view.setUint16(offset, 0x0090, true);
  offset = writeUtf16Z(bytes, offset + 2, "File");
  view.setUint16(offset, 0x0080, true);
  view.setUint16(offset + 2, 100, true);
  offset = writeUtf16Z(bytes, offset + 4, "Open");
  return bytes.subarray(0, offset);
};

const buildStandardDialogTemplate = (): Uint8Array => {
  const bytes = new Uint8Array(160).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, DS_SETFONT, true);
  view.setUint16(8, 1, true);
  view.setInt16(14, 120, true);
  view.setInt16(16, 80, true);
  let offset = 18;
  offset += 4;
  offset = writeUtf16Z(bytes, offset, "Preview Dialog");
  view.setUint16(offset, 9, true);
  offset = writeUtf16Z(bytes, offset + 2, "MS Shell Dlg");
  offset = align(offset, 4);
  view.setUint32(offset, 0x50010000, true);
  view.setInt16(offset + 8, 14, true);
  view.setInt16(offset + 10, 50, true);
  view.setInt16(offset + 12, 50, true);
  view.setInt16(offset + 14, 14, true);
  view.setUint16(offset + 16, 100, true);
  view.setUint16(offset + 18, 0xffff, true);
  view.setUint16(offset + 20, 0x0080, true);
  const next = writeUtf16Z(bytes, offset + 22, "OK");
  view.setUint16(next, 0, true);
  return bytes.subarray(0, next + 2);
};

export const createPeResourceSpecs = (): ResourceSpec[] => {
  const png = createPngFile().data;
  const cursorLeaf = buildCursorResource(7, 9, png);
  return [
    { typeId: RESOURCE_TYPE_CURSOR, entryId: 4, langId: 1033, codePage: 0, data: cursorLeaf },
    {
      typeId: RESOURCE_TYPE_BITMAP,
      entryId: 1,
      langId: 1033,
      codePage: 0,
      data: createBmpFile().data.subarray(14)
    },
    { typeId: RESOURCE_TYPE_ICON, entryId: 1, langId: 1033, codePage: 0, data: png },
    { typeId: RESOURCE_TYPE_MENU, entryId: 1, langId: 1033, codePage: 0, data: buildStandardMenuTemplate() },
    { typeId: RESOURCE_TYPE_DIALOG, entryId: 1, langId: 1033, codePage: 0, data: buildStandardDialogTemplate() },
    { typeId: RESOURCE_TYPE_STRING, entryId: 1, langId: 1033, codePage: 1200, data: buildStringTableResource() },
    { typeId: RESOURCE_TYPE_ACCELERATOR, entryId: 1, langId: 1033, codePage: 0, data: buildAcceleratorTable() },
    {
      typeId: RESOURCE_TYPE_RCDATA,
      entryId: 1,
      langId: 1033,
      codePage: 65001,
      data: new TextEncoder().encode("{\"kind\":\"rcdata\"}\n")
    },
    {
      typeId: RESOURCE_TYPE_MESSAGETABLE,
      entryId: 1,
      langId: 2057,
      codePage: 1252,
      data: buildMessageTableResource()
    },
    {
      typeId: RESOURCE_TYPE_GROUP_CURSOR,
      entryId: 1,
      langId: 1033,
      codePage: 0,
      data: buildGroupCursorResource(cursorLeaf.length, 4)
    },
    {
      typeId: RESOURCE_TYPE_GROUP_ICON,
      entryId: 1,
      langId: 1033,
      codePage: 0,
      data: buildGroupIconResource(png.length, 1)
    },
    { typeId: RESOURCE_TYPE_VERSION, entryId: 1, langId: 1033, codePage: 1200, data: buildVersionResource() },
    { typeId: RESOURCE_TYPE_ANICURSOR, entryId: 1, langId: 1033, codePage: 0, data: createAniFile().data },
    {
      typeId: RESOURCE_TYPE_HTML,
      entryId: 1,
      langId: 1033,
      codePage: 65001,
      data: new TextEncoder().encode("<html><body>resource</body></html>")
    },
    {
      typeId: RESOURCE_TYPE_MANIFEST,
      entryId: 1,
      langId: 1033,
      codePage: 65001,
      data: new TextEncoder().encode("<?xml version=\"1.0\"?><assembly/>")
    }
  ].sort((left, right) => left.typeId - right.typeId);
};
