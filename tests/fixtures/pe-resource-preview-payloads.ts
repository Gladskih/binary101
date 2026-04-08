"use strict";

import { createBmpFile, createPngFile } from "./image-sample-files.js";
import {
  buildMessageTableResource,
  buildStringTableResource,
  buildVersionResource
} from "./pe-resource-metadata-payloads.js";
import {
  createManifestIncidentalValues,
  createManifestXmlFixture
} from "./pe-manifest-preview-fixture.js";
import { createAniFile } from "./riff-sample-files.js";

const DS_SETFONT = 0x00000040;
const RESOURCE_TYPE_CURSOR = 1;
const RESOURCE_TYPE_BITMAP = 2;
const RESOURCE_TYPE_ICON = 3;
const RESOURCE_TYPE_MENU = 4;
const RESOURCE_TYPE_DIALOG = 5;
const RESOURCE_TYPE_STRING = 6;
const RESOURCE_TYPE_FONTDIR = 7;
const RESOURCE_TYPE_FONT = 8;
const RESOURCE_TYPE_ACCELERATOR = 9;
const RESOURCE_TYPE_RCDATA = 10;
const RESOURCE_TYPE_MESSAGETABLE = 11;
const RESOURCE_TYPE_GROUP_CURSOR = 12;
const RESOURCE_TYPE_GROUP_ICON = 14;
const RESOURCE_TYPE_VERSION = 16;
const RESOURCE_TYPE_DLGINCLUDE = 17;
const RESOURCE_TYPE_PLUGPLAY = 19;
const RESOURCE_TYPE_VXD = 20;
const RESOURCE_TYPE_ANICURSOR = 21;
const RESOURCE_TYPE_ANIICON = 22;
const RESOURCE_TYPE_HTML = 23;
const RESOURCE_TYPE_MANIFEST = 24;
// These supportedOS GUIDs are the exact subject of the renderer annotation test.
// Source: Microsoft Learn, "Application manifests".
const WELL_KNOWN_SUPPORTED_OS_IDS = [
  "{e2011457-1546-43c5-a5fe-008deee3d3f0}",
  "{35138b9a-5d96-4fbd-8e2d-a2440225f93a}",
  "{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}",
  "{1f676c76-80e1-4239-95bb-83d0f6d0da78}",
  "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"
];

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

const buildFontDirectoryResource = (): Uint8Array => {
  const bytes = new Uint8Array(8).fill(0);
  new DataView(bytes.buffer).setUint16(0, 1, true);
  return bytes;
};

const buildTrueTypeSignatureResource = (): Uint8Array =>
  new Uint8Array([0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80]);

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
  const manifest = createManifestXmlFixture(
    {
      processorArchitecture: "amd64",
      requestedExecutionLevel: "asInvoker",
      supportedOsIds: WELL_KNOWN_SUPPORTED_OS_IDS
    },
    createManifestIncidentalValues()
  );
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
    { typeId: RESOURCE_TYPE_FONTDIR, entryId: 1, langId: 1033, codePage: 0, data: buildFontDirectoryResource() },
    { typeId: RESOURCE_TYPE_FONT, entryId: 1, langId: 1033, codePage: 0, data: buildTrueTypeSignatureResource() },
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
    {
      typeId: RESOURCE_TYPE_DLGINCLUDE,
      entryId: 1,
      langId: 1033,
      codePage: 65001,
      data: new TextEncoder().encode("#include \"preview-dialog.h\"\n")
    },
    {
      typeId: RESOURCE_TYPE_PLUGPLAY,
      entryId: 1,
      langId: 1033,
      codePage: 0,
      data: new Uint8Array([0x50, 0x4e, 0x50, 0x00])
    },
    {
      typeId: RESOURCE_TYPE_VXD,
      entryId: 1,
      langId: 1033,
      codePage: 0,
      data: new Uint8Array([0x56, 0x58, 0x44, 0x00])
    },
    { typeId: RESOURCE_TYPE_ANICURSOR, entryId: 1, langId: 1033, codePage: 0, data: createAniFile().data },
    { typeId: RESOURCE_TYPE_ANIICON, entryId: 1, langId: 1033, codePage: 0, data: createAniFile().data },
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
      data: new TextEncoder().encode(manifest.xml)
    }
  ].sort((left, right) => left.typeId - right.typeId);
};
