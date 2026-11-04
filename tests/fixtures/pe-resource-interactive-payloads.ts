import { encodeUtf16Z } from "./pe-resource-metadata-payloads.js";
import { joinResourceBytes, resourceDword } from "./pe-resource-advanced-payloads.js";
import type { ResourceSpec } from "./pe-resource-preview-payloads.js";

const word = (value: number): Uint8Array => Uint8Array.of(value & 255, value >>> 8);

const dialogControl = (
  style: number, id: number, bounds: [number, number, number, number],
  classOrdinal: number, title: Uint8Array
): Uint8Array => {
  const bytes = joinResourceBytes(resourceDword(style), resourceDword(0),
    ...bounds.map(word), word(id), word(0xffff), word(classOrdinal), title, word(0));
  return joinResourceBytes(bytes, new Uint8Array((4 - bytes.length % 4) % 4));
};

export const createInteractiveDialogResource = (): Uint8Array => {
  const header = joinResourceBytes(resourceDword(0x90c80040), resourceDword(0), word(4),
    word(0), word(0), word(180), word(100), word(0xffff), word(1), word(0),
    encodeUtf16Z("Resource dialog"), word(9), encodeUtf16Z("Arial"));
  return joinResourceBytes(header, new Uint8Array((4 - header.length % 4) % 4),
    dialogControl(0x50000003, 100, [8, 8, 20, 20], 0x82, joinResourceBytes(word(0xffff), word(1))),
    dialogControl(0x50010003, 101, [36, 10, 120, 12], 0x80, encodeUtf16Z("&Remember")),
    dialogControl(0x50010003, 102, [36, 32, 120, 48], 0x85, encodeUtf16Z("")),
    dialogControl(0x50010001, 103, [122, 78, 50, 14], 0x80, encodeUtf16Z("OK")));
};

const dialogInit = (): Uint8Array => joinResourceBytes(
  word(102), word(0x403), resourceDword(4), new TextEncoder().encode("One\0"),
  word(102), word(0x403), resourceDword(4), new TextEncoder().encode("Two\0"), word(0)
);

const dialogLayout = (): Uint8Array => {
  const bytes = new Uint8Array(2 + 4 * 8);
  const view = new DataView(bytes.buffer);
  // AFX_DIALOG_LAYOUT: the last child moves with both edges of the dialog.
  view.setUint16(2 + 3 * 8, 100, true); view.setUint16(2 + 3 * 8 + 2, 100, true);
  return bytes;
};

export const interactiveRibbonXml = "<?xml version=\"1.0\"?><AFX_RIBBON><HEADER><VERSION>1</VERSION></HEADER>" +
  "<RIBBON_BAR><IMAGE><ID><NAME>IDB_MAIN</NAME><VALUE>1</VALUE></ID></IMAGE>" +
  "<BUTTON_MAIN><TEXT>File</TEXT></BUTTON_MAIN><CATEGORY_MAIN><ELEMENTS><ELEMENT>" +
  "<ELEMENT_NAME>Button</ELEMENT_NAME><TEXT>Exit</TEXT><ID><VALUE>101</VALUE></ID></ELEMENT>" +
  "</ELEMENTS></CATEGORY_MAIN><QAT_ELEMENTS><ITEMS><ITEM><ID><VALUE>100</VALUE></ID>" +
  "<VISIBLE>TRUE</VISIBLE></ITEM></ITEMS></QAT_ELEMENTS><CATEGORIES>" +
  "<CATEGORY><NAME>Home</NAME><PANELS><PANEL><NAME>Actions</NAME><ELEMENTS><ELEMENT>" +
  "<ELEMENT_NAME>Button</ELEMENT_NAME><TEXT>Open</TEXT><ID><VALUE>100</VALUE></ID>" +
  "<IMAGE><ID><VALUE>1</VALUE></ID></IMAGE><ELEMENTS><ELEMENT><ELEMENT_NAME>Button_Check</ELEMENT_NAME>" +
  "<TEXT>Nested choice</TEXT></ELEMENT></ELEMENTS></ELEMENT></ELEMENTS></PANEL></PANELS></CATEGORY>" +
  "<CATEGORY><NAME>View</NAME><PANELS><PANEL><NAME>Display</NAME><ELEMENTS><ELEMENT>" +
  "<ELEMENT_NAME>ComboBox</ELEMENT_NAME><TEXT>Scale</TEXT></ELEMENT></ELEMENTS></PANEL></PANELS></CATEGORY>" +
  "</CATEGORIES></RIBBON_BAR></AFX_RIBBON>";

export const createInteractiveResourcePayloads = (): ResourceSpec[] => [
  { typeId: 5, entryId: 401, langId: 1033, codePage: 0, data: createInteractiveDialogResource() },
  { typeId: 240, entryId: 401, langId: 1033, codePage: 0, data: dialogInit() },
  { typeId: "AFX_DIALOG_LAYOUT", entryId: 401, langId: 1033, codePage: 0, data: dialogLayout() },
  { typeId: 28, entryId: 402, langId: 1033, codePage: 65001, data: new TextEncoder().encode(interactiveRibbonXml) }
];
