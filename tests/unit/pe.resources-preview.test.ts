"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../analyzers/pe/resources-preview.js";
import type { ResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const IMAGE_RESOURCE_DIRECTORY_SIZE = 16; // IMAGE_RESOURCE_DIRECTORY
const IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8; // IMAGE_RESOURCE_DIRECTORY_ENTRY
const RESOURCE_DIRECTORY_SUBDIRECTORY_FLAG = 0x80000000;
const RESOURCE_DIRECTORY_ID_COUNT_OFFSET = 14;
const MESSAGE_RESOURCE_ENTRY_FLAG = { ansi: 0, unicode: 1 } as const;
const UTF16LE_CODE_PAGE = 1200;
const VERSION_INFO_FIXED_FILE_INFO_SIGNATURE = 0xfeef04bd;
const VERSION_INFO_FIXED_FILE_INFO_SIZE = 52;

type ResourceDetail = ResourceTree["detail"][number];
type ResourceLang = ResourceDetail["entries"][number]["langs"][number];
type ResourcePreviewResult = Awaited<ReturnType<typeof enrichResourcePreviews>>;
type PreviewResourceLang = ResourceLang & {
  previewKind?: string;
  previewMime?: string;
  textPreview?: string;
  textEncoding?: string | null;
  stringTable?: Array<{ id: number | null; text: string }>;
  messageTable?: { messages: Array<{ id: number; strings: string[] }>; truncated: boolean };
  previewIssues?: string[];
  versionInfo?: { fileVersionString?: string; productVersionString?: string };
};

const writeUtf16 = (bytes: Uint8Array, offset: number, text: string): void => {
  for (let index = 0; index < text.length; index += 1) {
    const codeUnit = text.charCodeAt(index);
    bytes[offset + index * 2] = codeUnit & 0xff;
    bytes[offset + index * 2 + 1] = codeUnit >>> 8;
  }
};

const writeDirectoryEntry = (
  view: DataView,
  offset: number,
  nameField: number,
  targetField: number
): void => {
  view.setUint32(offset, nameField, true);
  view.setUint32(offset + Uint32Array.BYTES_PER_ELEMENT, targetField, true);
};

const createResourcePreviewFixture = (fileSize: number): {
  fileBytes: Uint8Array;
  writeData: (offset: number, data: Uint8Array) => { offset: number; size: number };
} => {
  const fileBytes = new Uint8Array(fileSize).fill(0);
  return {
    fileBytes,
    writeData: (offset, data) => {
      fileBytes.set(data, offset);
      return { offset, size: data.length };
    }
  };
};

const createLang = (
  dataRva: number,
  size: number,
  codePage: number,
  lang: number | null
): ResourceLang => ({ lang, size, codePage, dataRVA: dataRva, reserved: 0 });

const createDetail = (typeName: string, id: number, lang: ResourceLang): ResourceDetail => ({
  typeName,
  entries: [{ id, name: null, langs: [lang] }]
});

const createResourceTree = (
  detail: ResourceDetail[],
  directoryBuffer = new ArrayBuffer(IMAGE_RESOURCE_DIRECTORY_SIZE)
): ResourceTree => ({
  base: 0,
  limitEnd: directoryBuffer.byteLength,
  top: [],
  detail,
  view: async (off, len) => new DataView(directoryBuffer, off, len),
  rvaToOff: value => value
});

const buildStringTableResource = (): Uint8Array => {
  const bytes = new Uint8Array(24).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 5, true);
  writeUtf16(bytes, 2, "Hello");
  view.setUint16(12, 6, true); // Deliberately too large for the remaining payload.
  writeUtf16(bytes, 14, "Hi");
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
  view.setUint16(firstEntryOffset + 2, MESSAGE_RESOURCE_ENTRY_FLAG.ansi, true);
  bytes[firstEntryOffset + 4] = "O".charCodeAt(0);
  bytes[firstEntryOffset + 5] = "K".charCodeAt(0);
  view.setUint16(secondEntryOffset, 8, true);
  view.setUint16(secondEntryOffset + 2, MESSAGE_RESOURCE_ENTRY_FLAG.unicode, true);
  writeUtf16(bytes, secondEntryOffset + 4, "Hi");
  return bytes;
};

const buildVersionResource = (): Uint8Array => {
  const bytes = new Uint8Array(96).fill(0);
  const view = new DataView(bytes.buffer);
  const key = "VS_VERSION_INFO";
  view.setUint16(0, bytes.length, true);
  view.setUint16(2, VERSION_INFO_FIXED_FILE_INFO_SIZE, true);
  writeUtf16(bytes, 6, key);
  const valueStart = (6 + key.length * 2 + 2 + 3) & ~3;
  view.setUint32(valueStart, VERSION_INFO_FIXED_FILE_INFO_SIGNATURE, true);
  view.setUint32(valueStart + 4, 0x00010000, true);
  view.setUint32(valueStart + 8, 0x00090000, true);
  view.setUint32(valueStart + 12, 0x521e0008, true);
  view.setUint32(valueStart + 16, 0x00090000, true);
  view.setUint32(valueStart + 20, 0x521e0008, true);
  return bytes;
};

const getPreviewLang = (result: ResourcePreviewResult, typeName: string): PreviewResourceLang => {
  const group = expectDefined(result.detail.find(entry => entry.typeName === typeName));
  const resourceEntry = expectDefined(group.entries[0]);
  return expectDefined(resourceEntry.langs[0]) as PreviewResourceLang;
};

void test("enrichResourcePreviews builds text previews for MANIFEST and HTML", async () => {
  const fixture = createResourcePreviewFixture(256);
  const manifest = fixture.writeData(64, encoder.encode('<?xml version="1.0"?><assembly/>'));
  const html = fixture.writeData(128, encoder.encode("<html><body>hi</body></html>"));
  const tree = createResourceTree([
    createDetail("MANIFEST", 3, createLang(manifest.offset, manifest.size, 65001, null)),
    createDetail("HTML", 4, createLang(html.offset, html.size, 65001, 1031))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  assert.strictEqual(getPreviewLang(result, "MANIFEST").previewKind, "text");
  assert.match(expectDefined(getPreviewLang(result, "MANIFEST").textPreview), /assembly/);
  assert.strictEqual(getPreviewLang(result, "HTML").previewKind, "html");
  assert.match(expectDefined(getPreviewLang(result, "HTML").textPreview), /<body>hi/);
});

void test("enrichResourcePreviews builds STRING, MESSAGETABLE, and VERSION previews", async () => {
  const fixture = createResourcePreviewFixture(1024);
  const stringTable = fixture.writeData(128, buildStringTableResource());
  const messageTable = fixture.writeData(256, buildMessageTableResource());
  const version = fixture.writeData(512, buildVersionResource());
  const tree = createResourceTree([
    createDetail("STRING", 1, createLang(stringTable.offset, stringTable.size, UTF16LE_CODE_PAGE, 1031)),
    createDetail("MESSAGETABLE", 5, createLang(messageTable.offset, messageTable.size, 0, 2057)),
    createDetail("VERSION", 6, createLang(version.offset, version.size, UTF16LE_CODE_PAGE, 3082))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const stringLang = getPreviewLang(result, "STRING");
  const messageLang = getPreviewLang(result, "MESSAGETABLE");
  const versionLang = getPreviewLang(result, "VERSION");

  assert.strictEqual(stringLang.previewKind, "stringTable");
  assert.ok(expectDefined(stringLang.stringTable).length >= 1);
  assert.ok((stringLang.previewIssues || []).length > 0);
  assert.strictEqual(messageLang.previewKind, "messageTable");
  assert.deepEqual(expectDefined(messageLang.messageTable), {
    messages: [
      { id: 10, strings: ["OK"] },
      { id: 11, strings: ["Hi"] }
    ],
    truncated: false
  });
  assert.match((messageLang.previewIssues || []).join(" "), /supported code page/i);
  assert.strictEqual(versionLang.previewKind, "version");
  assert.strictEqual(versionLang.versionInfo?.fileVersionString, "9.0.21022.8");
  assert.strictEqual(versionLang.versionInfo?.productVersionString, "9.0.21022.8");
});

void test("enrichResourcePreviews reports resource-directory mapping gaps", async () => {
  const directoryBuffer = new ArrayBuffer(
    IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
  );
  const directoryView = new DataView(directoryBuffer);
  directoryView.setUint16(RESOURCE_DIRECTORY_ID_COUNT_OFFSET, 1, true);
  writeDirectoryEntry(
    directoryView,
    IMAGE_RESOURCE_DIRECTORY_SIZE,
    3,
    RESOURCE_DIRECTORY_SUBDIRECTORY_FLAG | 0x20
  );
  const tree: ResourceTree = {
    base: 0,
    limitEnd: directoryBuffer.byteLength,
    dirRva: 0x1000,
    dirSize: 0x40,
    top: [],
    detail: [],
    view: async (off, len) => new DataView(directoryBuffer, off, len),
    rvaToOff: rva => (rva >= 0x1000 && rva < 0x1000 + directoryBuffer.byteLength ? rva - 0x1000 : null)
  };

  const result = await enrichResourcePreviews(new MockFile(new Uint8Array(directoryBuffer)), tree);
  assert.match((result.issues || []).join(" "), /RT_ICON name directory/i);
});

void test("enrichResourcePreviews uses the resource code page to decode UTF-16LE HTML without a BOM", async () => {
  const fixture = createResourcePreviewFixture(256);
  const htmlBytes = new Uint8Array("<html>".length * 2);
  writeUtf16(htmlBytes, 0, "<html>");
  const html = fixture.writeData(64, htmlBytes);
  const tree = createResourceTree([
    createDetail("HTML", 7, createLang(html.offset, html.size, UTF16LE_CODE_PAGE, 1033))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const htmlLang = getPreviewLang(result, "HTML");

  assert.strictEqual(htmlLang.previewKind, "html");
  assert.strictEqual(htmlLang.textPreview, "<html>");
  assert.strictEqual(htmlLang.textEncoding, "UTF-16LE");
});

void test("enrichResourcePreviews warns when resource preview reads fewer bytes than the declared data size", async () => {
  const fixture = createResourcePreviewFixture(96);
  const manifest = fixture.writeData(64, encoder.encode("<assembly/>"));
  const tree = createResourceTree([
    createDetail("MANIFEST", 8, createLang(manifest.offset, manifest.size + 16, 65001, 1033))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const manifestLang = getPreviewLang(result, "MANIFEST");

  assert.strictEqual(manifestLang.previewKind, "text");
  assert.ok((manifestLang.previewIssues || []).some(issue => /truncated|short|declared/i.test(issue)));
});

void test("enrichResourcePreviews does not read VS_FIXEDFILEINFO past the declared VS_VERSIONINFO length", async () => {
  const fixture = createResourcePreviewFixture(256);
  const versionBytes = new Uint8Array(96).fill(0);
  const view = new DataView(versionBytes.buffer);
  const key = "VS_VERSION_INFO";
  // wLength intentionally ends before a full VS_FIXEDFILEINFO, while wValueLength still advertises sizeof(VS_FIXEDFILEINFO).
  view.setUint16(0, 40, true);
  view.setUint16(2, VERSION_INFO_FIXED_FILE_INFO_SIZE, true);
  writeUtf16(versionBytes, 6, key);
  const valueStart = (6 + key.length * 2 + 2 + 3) & ~3;
  view.setUint32(valueStart, VERSION_INFO_FIXED_FILE_INFO_SIGNATURE, true);
  view.setUint32(valueStart + 4, 0x00010000, true);
  view.setUint32(valueStart + 8, 0x00090000, true);
  view.setUint32(valueStart + 12, 0x521e0008, true);
  view.setUint32(valueStart + 16, 0x00090000, true);
  view.setUint32(valueStart + 20, 0x521e0008, true);
  const version = fixture.writeData(128, versionBytes);
  const tree = createResourceTree([
    createDetail("VERSION", 9, createLang(version.offset, version.size, UTF16LE_CODE_PAGE, 1033))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const versionLang = getPreviewLang(result, "VERSION");

  assert.notStrictEqual(versionLang.previewKind, "version");
  assert.ok((versionLang.previewIssues || []).some(issue => /too small|truncated|length/i.test(issue)));
});
